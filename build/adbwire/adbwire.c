/*
 * adbwire — a minimal ADB client for Android Wireless Debugging, built for
 * exactly one job: connect to an already-paired device over TLS and run a
 * single shell command (optionally streaming a local file into its stdin).
 *
 * It deliberately implements only the subset termux-adb-bridge needs for
 * bootstrap and recovery. There is NO pairing (use stock `adb pair` once;
 * the device remembers your ~/.android/adbkey afterwards), NO adb server,
 * NO sync/push service (a file is streamed with `cat > path` over stdin),
 * and NO device list. That is the whole point: the recurring dependency is
 * connect + run-one-command, and that is all this does.
 *
 * Wireless-debugging connect sequence (confirmed against AOSP adb, see
 * transport.cpp DoTlsHandshake + adb.cpp handle_packet A_STLS):
 *   1. TCP connect to the wireless-debugging connect port.
 *   2. PLAINTEXT ADB CNXN; the device replies PLAINTEXT STLS and we reply
 *      STLS. This "start TLS" step is mandatory - connecting with TLS
 *      immediately is rejected with EOF. The plaintext CNXN is the real
 *      connection request, not a throwaway.
 *   3. TLS 1.3 over the same socket, presenting a self-signed cert made
 *      from ~/.android/adbkey (the device trusts that key from pairing).
 *      The server cert is not verified (self-signed).
 *   4. The device sends its CNXN (deferred from step 2) after TLS; we just
 *      read it. Do NOT send another CNXN here - adbd answers STLS again.
 *      AUTH is ignored by adbd in TLS mode: the client cert is the auth.
 *   5. OPEN "shell,v2,raw:<cmd>", WRTE/READ flow control, CLSE.
 *   shell_v2 packets: 1-byte id + 4-byte little-endian length + payload.
 *   ids: 0 stdin, 1 stdout, 2 stderr, 3 exit, 4 close-stdin, 5 window-size.
 *
 * Build:  clang -O2 -o adbwire adbwire.c -lssl -lcrypto
 * Usage:
 *   adbwire 'id'                    # discover the port via mDNS, loopback connect
 *   adbwire --discover              # print the current wireless-debugging port
 *   adbwire -s <host:port> 'id'     # explicit address (no discovery)
 *   adbwire -p local.bin 'cat > /data/local/tmp/x && chmod 700 /data/local/tmp/x'
 *   adbwire -k ~/.android/adbkey 'getprop ro.build.version.sdk'
 *
 * Exit status is the remote command's exit status (like `adb shell`).
 * SPDX-License-Identifier: GPL-3.0-only
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "spake2.h"

#define ADB_CNXN 0x4e584e43u
#define ADB_AUTH 0x48545541u
#define ADB_OPEN 0x4e45504fu
#define ADB_OKAY 0x59414b4fu
#define ADB_CLSE 0x45534c43u
#define ADB_WRTE 0x45545257u
#define ADB_STLS 0x534c5453u

#define A_VERSION 0x01000001u
#define A_STLS_VERSION 0x01000000u
#define A_AUTH_TOKEN 1
#define A_AUTH_SIGNATURE 2

#define MAXDATA (256 * 1024)

#define SHELL_STDIN 0
#define SHELL_STDOUT 1
#define SHELL_STDERR 2
#define SHELL_EXIT 3
#define SHELL_CLOSE_STDIN 4
/* shell_v2 packet header: 1-byte id + 4-byte little-endian length. */
#define SHELL_HEADER 5

static void put_u32le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v);
    p[1] = (unsigned char)(v >> 8);
    p[2] = (unsigned char)(v >> 16);
    p[3] = (unsigned char)(v >> 24);
}

static uint32_t get_u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

struct adb_msg {
    uint32_t command, arg0, arg1, data_length, data_check, magic;
};

/* A connection is a raw fd during the plaintext CNXN/STLS phase, then the
 * same fd wrapped in an SSL object once TLS is up. */
struct adb_io {
    int fd;
    SSL *ssl;
};

/* ---- TLS-over-socket byte helpers (SSL_read/write may be partial) ---- */
static int ssl_write_all(SSL *ssl, const void *buf, size_t len) {
    const unsigned char *p = buf;
    while (len > 0) {
        int n = SSL_write(ssl, p, len > INT_MAX ? INT_MAX : (int)len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int ssl_read_all(SSL *ssl, void *buf, size_t len) {
    unsigned char *p = buf;
    while (len > 0) {
        int n = SSL_read(ssl, p, len > INT_MAX ? INT_MAX : (int)len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int io_write_all(struct adb_io *io, const void *buf, size_t len) {
    if (io->ssl) return ssl_write_all(io->ssl, buf, len);
    const unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = write(io->fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int io_read_all(struct adb_io *io, void *buf, size_t len) {
    if (io->ssl) return ssl_read_all(io->ssl, buf, len);
    unsigned char *p = buf;
    while (len > 0) {
        ssize_t n = read(io->fd, p, len);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

/* ---- ADB wire messages ---- */
static int adb_send(struct adb_io *io, uint32_t cmd, uint32_t arg0, uint32_t arg1,
                    const void *data, uint32_t len) {
    unsigned char hdr[24];
    const unsigned char *d = data;
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < len; i++) checksum += d[i];
    put_u32le(hdr + 0, cmd);
    put_u32le(hdr + 4, arg0);
    put_u32le(hdr + 8, arg1);
    put_u32le(hdr + 12, len);
    put_u32le(hdr + 16, checksum);
    put_u32le(hdr + 20, cmd ^ 0xffffffffu);
    if (io_write_all(io, hdr, sizeof(hdr)) < 0) return -1;
    if (len > 0 && io_write_all(io, data, len) < 0) return -1;
    return 0;
}

static int adb_recv(struct adb_io *io, struct adb_msg *m, unsigned char **data) {
    unsigned char hdr[24];
    *data = NULL;
    if (io_read_all(io, hdr, sizeof(hdr)) < 0) return -1;
    m->command = get_u32le(hdr + 0);
    m->arg0 = get_u32le(hdr + 4);
    m->arg1 = get_u32le(hdr + 8);
    m->data_length = get_u32le(hdr + 12);
    m->data_check = get_u32le(hdr + 16);
    m->magic = get_u32le(hdr + 20);
    if (m->magic != (m->command ^ 0xffffffffu)) return -1;
    if (m->data_length > MAXDATA) return -1;
    if (m->data_length > 0) {
        *data = malloc(m->data_length);
        if (!*data) return -1;
        if (io_read_all(io, *data, m->data_length) < 0) {
            free(*data);
            *data = NULL;
            return -1;
        }
    }
    if (getenv("ADBWIRE_DEBUG")) {
        fprintf(stderr, "[debug] recv cmd=0x%08x arg0=%u arg1=%u len=%u\n",
                m->command, m->arg0, m->arg1, m->data_length);
        if (*data && m->data_length) {
            fprintf(stderr, "[debug]   data[%u]:", m->data_length);
            for (uint32_t i = 0; i < m->data_length && i < 24; i++)
                fprintf(stderr, " %02x", (*data)[i]);
            fprintf(stderr, "\n");
        }
    }
    return 0;
}

/* ---- plaintext CNXN -> STLS -> STLS, then TLS may begin ---- */
static int adb_start_tls(struct adb_io *io) {
    const char *banner = "host::features=shell_v2,cmd,stat_v2";
    if (adb_send(io, ADB_CNXN, A_VERSION, MAXDATA, banner,
                 (uint32_t)strlen(banner) + 1) < 0)
        return -1;
    struct adb_msg m;
    unsigned char *data = NULL;
    if (adb_recv(io, &m, &data) < 0) return -1;
    int got_stls = (m.command == ADB_STLS);
    free(data);
    if (!got_stls) return -1;
    return adb_send(io, ADB_STLS, A_STLS_VERSION, 0, NULL, 0);
}

/* ---- RSA token signing: adb uses SHA1 + PKCS#1 v1.5 (see AOSP
 * adb_auth_host.cpp). Do not "modernize" the hash - adbd verifies SHA1. ---- */
static int rsa_sign_sha1(EVP_PKEY *pkey, const unsigned char *token,
                         size_t tlen, unsigned char *sig, size_t *siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    int ok = EVP_DigestSignInit(ctx, NULL, EVP_sha1(), NULL, pkey) == 1 &&
             EVP_DigestSign(ctx, sig, siglen, token, tlen) == 1;
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}

static EVP_PKEY *load_key(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    return pkey;
}

/* Self-signed cert from the adbkey. adbd only checks the cert's PUBLIC KEY
 * (EVP_PKEY_cmp against the keys it learned at pairing), so any cert
 * carrying this key is accepted; the exact bytes/subject don't matter. */
static X509 *self_signed_from(EVP_PKEY *pkey) {
    X509 *x = X509_new();
    if (!x) return NULL;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_get_notBefore(x), -3600);
    X509_gmtime_adj(X509_get_notAfter(x), 60L * 60 * 24 * 3650);
    X509_set_pubkey(x, pkey);
    X509_NAME *name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               (const unsigned char *)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               (const unsigned char *)"Android", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"Adb", -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (!X509_sign(x, pkey, EVP_sha256())) {
        X509_free(x);
        return NULL;
    }
    return x;
}

/* OpenSSL's client will not auto-send a cert that fails to match the
 * server's CertificateRequest CA-name list, and adbd's list names are
 * "O=AdbKey-0,CN=<sha256 of the RSA pubkey>" - which our cert does not
 * carry. adb itself sidesteps this with a cert_cb that force-sets the cert;
 * do the same. */
struct cert_ctx {
    X509 *cert;
    EVP_PKEY *pkey;
};

static int tls_cert_cb(SSL *ssl, void *arg) {
    struct cert_ctx *cc = arg;
    if (getenv("ADBWIRE_DEBUG")) fprintf(stderr, "[debug] cert_cb invoked\n");
    if (SSL_use_certificate(ssl, cc->cert) != 1) return 0;
    if (SSL_use_PrivateKey(ssl, cc->pkey) != 1) return 0;
    return 1;
}

static void tls_info_cb(const SSL *ssl, int where, int ret) {
    if (!getenv("ADBWIRE_DEBUG")) return;
    const char *state = SSL_state_string_long(ssl);
    if (where & SSL_CB_HANDSHAKE_START) fprintf(stderr, "[debug] hs start: %s\n", state);
    if (where & SSL_CB_HANDSHAKE_DONE) fprintf(stderr, "[debug] hs done: %s\n", state);
    if (where & SSL_CB_ALERT) fprintf(stderr, "[debug] alert %s: %s\n",
                                       (ret & SSL_CB_READ) ? "read" : "write",
                                       SSL_alert_desc_string_long(ret));
}

static int tcp_connect(const char *host, const char *port) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

/* ---- post-TLS: read the device's CNXN. Do NOT send another CNXN here ----
 * The plaintext CNXN in adb_start_tls is the real connection request; adbd
 * answers it with STLS, then defers its own CNXN until after TLS. Sending a
 * second CNXN here makes adbd reply with STLS again (confirmed on-device).
 * AUTH is ignored by adbd in TLS mode - the client certificate is the
 * authentication - but handle a token anyway for older behavior. */
static int adb_handshake(struct adb_io *io, EVP_PKEY *authkey) {
    int auth_attempts = 0;
    for (;;) {
        struct adb_msg m;
        unsigned char *data = NULL;
        if (adb_recv(io, &m, &data) < 0) return -1;

        if (m.command == ADB_CNXN) {
            free(data);
            return 0;
        }
        if (m.command == ADB_AUTH && m.arg0 == A_AUTH_TOKEN) {
            if (++auth_attempts > 3) {
                free(data);
                return -1;
            }
            unsigned char sig[512];
            size_t siglen = sizeof(sig);
            int rc = rsa_sign_sha1(authkey, data, m.data_length, sig, &siglen);
            free(data);
            if (rc < 0) return -1;
            if (adb_send(io, ADB_AUTH, A_AUTH_SIGNATURE, 0, sig,
                         (uint32_t)siglen) < 0)
                return -1;
            continue;
        }
        /* anything else (stray OKAY/CLSE): ignore */
        free(data);
    }
}

/* ---- OPEN shell,v2 + drive stdin, collect stdout/stderr/exit ---- */
static int run_shell(struct adb_io *io, const char *command, int in_fd) {
    uint32_t local = 1, remote = 0;
    int opened = 0, stdin_done = 0, exit_code = -1;
    char service[8192];

    snprintf(service, sizeof(service), "shell,v2,raw:%s", command);
    if (adb_send(io, ADB_OPEN, local, 0, service,
                 (uint32_t)strlen(service) + 1) < 0)
        return -1;

    unsigned char *inbuf = malloc(MAXDATA);
    if (!inbuf) return -1;

    for (;;) {
        struct adb_msg m;
        unsigned char *data = NULL;
        if (adb_recv(io, &m, &data) < 0) {
            free(inbuf);
            return -1;
        }

        if (m.command == ADB_OKAY) {
            if (!opened) {
                opened = 1;
                remote = m.arg0;
            }
            if (!stdin_done) {
                ssize_t n = in_fd >= 0 ? read(in_fd, inbuf, MAXDATA - SHELL_HEADER) : 0;
                if (n > 0) {
                    unsigned char *pkt = malloc(SHELL_HEADER + (size_t)n);
                    if (!pkt) {
                        free(data);
                        free(inbuf);
                        return -1;
                    }
                    pkt[0] = SHELL_STDIN;
                    put_u32le(pkt + 1, (uint32_t)n);
                    memcpy(pkt + SHELL_HEADER, inbuf, (size_t)n);
                    adb_send(io, ADB_WRTE, local, remote, pkt,
                             (uint32_t)n + SHELL_HEADER);
                    free(pkt);
                } else {
                    /* kIdCloseStdin tells the remote to close the process's
                     * stdin (EOF); a zero-length stdin packet does not. */
                    unsigned char eof[SHELL_HEADER];
                    eof[0] = SHELL_CLOSE_STDIN;
                    put_u32le(eof + 1, 0);
                    adb_send(io, ADB_WRTE, local, remote, eof, SHELL_HEADER);
                    stdin_done = 1;
                }
            }
        } else if (m.command == ADB_WRTE) {
            /* One WRTE can carry several shell_v2 packets back-to-back. */
            uint32_t off = 0;
            while (off + SHELL_HEADER <= m.data_length) {
                uint8_t id = data[off];
                uint32_t len = get_u32le(data + off + 1);
                const unsigned char *payload = data + off + SHELL_HEADER;
                if (len > m.data_length - (off + SHELL_HEADER))
                    len = m.data_length - (off + SHELL_HEADER);
                if (id == SHELL_STDOUT)
                    fwrite(payload, 1, len, stdout);
                else if (id == SHELL_STDERR)
                    fwrite(payload, 1, len, stderr);
                else if (id == SHELL_EXIT && len >= 1)
                    exit_code = payload[0];
                off += SHELL_HEADER + len;
            }
            adb_send(io, ADB_OKAY, local, remote, NULL, 0);
        } else if (m.command == ADB_CLSE) {
            adb_send(io, ADB_CLSE, local, remote, NULL, 0);
            free(data);
            break;
        }
        free(data);
    }

    fflush(stdout);
    fflush(stderr);
    free(inbuf);
    return exit_code;
}

/* ---- mDNS discovery of the wireless-debugging connect port --------------
 * Wireless debugging advertises "_adb-tls-connect._tcp.local" over mDNS and
 * picks a new ephemeral port every time it is (re)enabled, so there is no
 * stable address to configure. Since Termux runs on the target device itself,
 * the discovered port is reached over loopback (127.0.0.1), which is why we
 * only need the SRV record's port, not the A record's address. */
#define MDNS_GROUP "224.0.0.251"
#define MDNS_PORT 5353
#define ADB_MDNS_SERVICE "_adb-tls-connect._tcp.local"

static size_t build_mdns_query(unsigned char *buf, size_t bufsz,
                               const char *service) {
    if (bufsz < 12) return 0;
    memset(buf, 0, 12);
    buf[5] = 1; /* qdcount = 1 */
    size_t o = 12;
    const char *p = service;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (l == 0 || o + 1 + l + 5 > bufsz) return 0;
        buf[o++] = (unsigned char)l;
        memcpy(buf + o, p, l);
        o += l;
        if (!dot) break;
        p = dot + 1;
    }
    buf[o++] = 0;            /* root label */
    buf[o++] = 0; buf[o++] = 12; /* QTYPE = PTR */
    buf[o++] = 0; buf[o++] = 1;  /* QCLASS = IN */
    return o;
}

/* Read a (possibly compressed) DNS name at `off`; sets *next to where the
 * caller resumes (just past a pointer, not where it led). */
static int mdns_read_name(const unsigned char *b, size_t len, size_t off,
                          char *out, size_t outsz, size_t *next) {
    size_t o = off, n = 0, orig_next = off;
    int jumped = 0, guard = 0;
    out[0] = '\0';
    for (;;) {
        if (++guard > 128 || o >= len) return -1;
        unsigned char l = b[o];
        if (l == 0) {
            o++;
            if (!jumped) orig_next = o;
            break;
        }
        if ((l & 0xC0) == 0xC0) {
            if (o + 1 >= len) return -1;
            size_t ptr = (size_t)(((l & 0x3F) << 8) | b[o + 1]);
            if (!jumped) orig_next = o + 2;
            o = ptr;
            jumped = 1;
            continue;
        }
        o++;
        if (o + l > len) return -1;
        if (n && n < outsz - 1) out[n++] = '.';
        for (unsigned char i = 0; i < l && n < outsz - 1; i++) out[n++] = b[o + i];
        o += l;
    }
    out[n] = '\0';
    *next = orig_next;
    return 0;
}

struct mdns_result {
    int found;
    int preferred; /* owner name had no "(N)" duplicate suffix */
    uint16_t port;
};

/* A datagram may pack several DNS messages back to back. */
static void mdns_parse(const unsigned char *b, size_t len, const char *filter,
                       struct mdns_result *r) {
    size_t start = 0;
    char name[256];
    while (start + 12 <= len) {
        uint16_t qd = (uint16_t)((b[start + 4] << 8) | b[start + 5]);
        uint16_t an = (uint16_t)((b[start + 6] << 8) | b[start + 7]);
        uint16_t ns = (uint16_t)((b[start + 8] << 8) | b[start + 9]);
        uint16_t ar = (uint16_t)((b[start + 10] << 8) | b[start + 11]);
        size_t off = start + 12, next = 0;
        int bad = 0;
        for (int i = 0; i < qd && !bad; i++) {
            if (mdns_read_name(b, len, off, name, sizeof(name), &next) < 0) { bad = 1; break; }
            off = next + 4;
        }
        for (int i = 0; i < an + ns + ar && !bad; i++) {
            if (mdns_read_name(b, len, off, name, sizeof(name), &next) < 0) { bad = 1; break; }
            off = next;
            if (off + 10 > len) { bad = 1; break; }
            uint16_t rtype = (uint16_t)((b[off] << 8) | b[off + 1]);
            uint16_t rdlen = (uint16_t)((b[off + 8] << 8) | b[off + 9]);
            size_t rdata = off + 10;
            if (rdata + rdlen > len) { bad = 1; break; }
            if (rtype == 33 && strstr(name, filter) && rdlen >= 6) {
                uint16_t port = (uint16_t)((b[rdata + 4] << 8) | b[rdata + 5]);
                int pref = (strchr(name, '(') == NULL);
                if (!r->found || (pref && !r->preferred)) {
                    r->found = 1;
                    r->preferred = pref;
                    r->port = port;
                }
            }
            off = rdata + rdlen;
        }
        if (bad || off <= start) break; /* never spin on a malformed message */
        start = off;
    }
}

static int discover_port(const char *service, const char *filter,
                         int timeout_sec, uint16_t *out_port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
#ifdef SO_REUSEPORT
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &yes, sizeof(yes));
#endif
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(MDNS_PORT);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    struct ip_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = inet_addr(MDNS_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr(MDNS_GROUP);
    dst.sin_port = htons(MDNS_PORT);
    unsigned char query[512];
    size_t qlen = build_mdns_query(query, sizeof(query), service);
    if (qlen == 0) { close(fd); return -1; }

    /* mDNS responders rate-limit and drop duplicates, so a single query can
     * go unanswered. Resend once a second for the whole window. */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct mdns_result r;
    memset(&r, 0, sizeof(r));
    unsigned char buf[9000];
    for (int attempt = 0; attempt < timeout_sec && !r.preferred; attempt++) {
        sendto(fd, query, qlen, 0, (struct sockaddr *)&dst, sizeof(dst));
        for (;;) {
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break; /* 1s elapsed with no more data - resend */
            mdns_parse(buf, (size_t)n, filter, &r);
            if (r.preferred) break;
        }
    }
    close(fd);
    if (!r.found) return -1;
    *out_port = r.port;
    return 0;
}

static int discover_adb_port(int timeout_sec, uint16_t *out_port) {
    return discover_port(ADB_MDNS_SERVICE, "_adb-tls-connect", timeout_sec, out_port);
}

static int discover_pairing_port(int timeout_sec, uint16_t *out_port) {
    return discover_port("_adb-tls-pairing._tcp.local", "_adb-tls-pairing",
                         timeout_sec, out_port);
}

/* ---- pairing (SPAKE2) ---------------------------------------------------
 * While the "Pair device with pairing code" dialog is open, the device
 * advertises "_adb-tls-pairing._tcp.local". That port speaks a small
 * protocol over TLS (no ADB CNXN/STLS): export TLS keying material, mix it
 * with the 6-digit code, run SPAKE2, then exchange an AES-128-GCM-encrypted
 * PeerInfo carrying our adb public key. On success the device adds that key
 * to its authorized list, after which the normal connect path works.
 * See AOSP pairing_connection/pairing_auth. */
#define PAIR_HDR_VERSION 1
#define PAIR_TYPE_SPAKE2 0
#define PAIR_TYPE_PEERINFO 1
#define PAIR_PEERINFO_SIZE 8192
#define PAIR_TYPE_ADB_RSA_PUB_KEY 0
#define PAIR_TYPE_ADB_DEVICE_GUID 1

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static int hmac_sha256(const uint8_t *key, size_t keylen, const uint8_t *data,
                       size_t datalen, uint8_t out[32]) {
    unsigned int len = 32;
    return HMAC(EVP_sha256(), key, (int)keylen, data, datalen, out, &len) ? 0
                                                                         : -1;
}
#pragma GCC diagnostic pop

/* HKDF-SHA256, salt = empty (zero) as adb uses it. Only L <= 32 needed. */
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len, const uint8_t *info,
                       size_t info_len, uint8_t *out, size_t out_len) {
    uint8_t zero[32] = {0};
    uint8_t prk[32], t[32], buf[512];
    if (info_len + 1 > sizeof(buf) || out_len > sizeof(t)) return -1;
    if (hmac_sha256(zero, sizeof(zero), ikm, ikm_len, prk) < 0) return -1;
    memcpy(buf, info, info_len);
    buf[info_len] = 1;
    if (hmac_sha256(prk, sizeof(prk), buf, info_len + 1, t) < 0) return -1;
    memcpy(out, t, out_len);
    return 0;
}

static void put_u64le(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}

/* BoringSSL's EVP_AEAD AES-128-GCM: 12-byte nonce = little-endian sequence
 * number, output is ciphertext with a 16-byte tag appended. */
static int aes128gcm_seal(const uint8_t key[16], uint64_t seq,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len) {
    uint8_t nonce[12] = {0};
    put_u64le(nonce, seq);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, total = 0;
    int ok = EVP_EncryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_EncryptInit_ex(c, NULL, NULL, key, nonce) == 1 &&
             EVP_EncryptUpdate(c, out, &len, in, (int)in_len) == 1;
    total = len;
    if (ok) ok = EVP_EncryptFinal_ex(c, out + total, &len) == 1;
    total += len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, out + total) == 1;
    total += 16;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return -1;
    *out_len = (size_t)total;
    return 0;
}

static int aes128gcm_open(const uint8_t key[16], uint64_t seq,
                          const uint8_t *in, size_t in_len, uint8_t *out,
                          size_t *out_len) {
    if (in_len < 16) return -1;
    uint8_t nonce[12] = {0};
    put_u64le(nonce, seq);
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return -1;
    int len = 0, total = 0;
    int ok = EVP_DecryptInit_ex(c, EVP_aes_128_gcm(), NULL, NULL, NULL) == 1 &&
             EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) == 1 &&
             EVP_DecryptInit_ex(c, NULL, NULL, key, nonce) == 1 &&
             EVP_DecryptUpdate(c, out, &len, in, (int)(in_len - 16)) == 1;
    total = len;
    if (ok)
        ok = EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_TAG, 16,
                                 (void *)(in + in_len - 16)) == 1;
    if (ok) ok = EVP_DecryptFinal_ex(c, out + total, &len) == 1;
    total += len;
    EVP_CIPHER_CTX_free(c);
    if (!ok) return -1;
    *out_len = (size_t)total;
    return 0;
}

static int pair_write_hdr(SSL *ssl, uint8_t type, uint32_t payload) {
    uint8_t h[6];
    h[0] = PAIR_HDR_VERSION;
    h[1] = type;
    h[2] = (uint8_t)(payload >> 24);
    h[3] = (uint8_t)(payload >> 16);
    h[4] = (uint8_t)(payload >> 8);
    h[5] = (uint8_t)payload;
    return ssl_write_all(ssl, h, sizeof(h));
}

static int pair_read_hdr(SSL *ssl, uint8_t *type, uint32_t *payload) {
    uint8_t h[6];
    if (ssl_read_all(ssl, h, sizeof(h)) < 0) return -1;
    if (h[0] != PAIR_HDR_VERSION) return -1;
    *type = h[1];
    *payload = ((uint32_t)h[2] << 24) | ((uint32_t)h[3] << 16) |
               ((uint32_t)h[4] << 8) | h[5];
    return 0;
}

static int pair_over_tls(SSL *ssl, const char *code, const char *pubkey_path) {
    uint8_t exported[64];
    /* adb passes the label including its NUL: sizeof("adb-label") == 10 */
    if (SSL_export_keying_material(ssl, exported, sizeof(exported), "adb-label",
                                   10, NULL, 0, 0) != 1) {
        fprintf(stderr, "adbwire: pairing: TLS keying-material export failed\n");
        return -1;
    }

    uint8_t password[256];
    size_t plen = strlen(code);
    if (plen == 0 || plen + sizeof(exported) > sizeof(password)) return -1;
    memcpy(password, code, plen);
    memcpy(password + plen, exported, sizeof(exported));
    plen += sizeof(exported);

    spake2_ctx *sp = spake2_new(
        1, (const uint8_t *)"adb pair client", sizeof("adb pair client"),
        (const uint8_t *)"adb pair server", sizeof("adb pair server"));
    if (!sp) return -1;
    uint8_t mymsg[SPAKE2_MAX_MSG_SIZE];
    size_t mylen = 0;
    if (!spake2_generate_msg(sp, mymsg, &mylen, sizeof(mymsg), password, plen)) {
        spake2_free(sp);
        return -1;
    }
    if (pair_write_hdr(ssl, PAIR_TYPE_SPAKE2, (uint32_t)mylen) < 0 ||
        ssl_write_all(ssl, mymsg, mylen) < 0) {
        spake2_free(sp);
        return -1;
    }
    uint8_t type;
    uint32_t payload;
    if (pair_read_hdr(ssl, &type, &payload) < 0 || type != PAIR_TYPE_SPAKE2 ||
        payload != SPAKE2_MAX_MSG_SIZE) {
        spake2_free(sp);
        fprintf(stderr, "adbwire: pairing: bad SPAKE2 reply header\n");
        return -1;
    }
    uint8_t theirmsg[SPAKE2_MAX_MSG_SIZE];
    if (ssl_read_all(ssl, theirmsg, sizeof(theirmsg)) < 0) {
        spake2_free(sp);
        return -1;
    }
    uint8_t keymat[SPAKE2_MAX_KEY_SIZE];
    size_t keylen = 0;
    int ok = spake2_process_msg(sp, keymat, &keylen, sizeof(keymat), theirmsg,
                                sizeof(theirmsg));
    spake2_free(sp);
    if (!ok) {
        fprintf(stderr, "adbwire: pairing: SPAKE2 failed (wrong code?)\n");
        return -1;
    }

    static const uint8_t info[] = "adb pairing_auth aes-128-gcm key";
    uint8_t aeskey[16];
    if (hkdf_sha256(keymat, keylen, info, sizeof(info) - 1, aeskey,
                    sizeof(aeskey)) < 0)
        return -1;

    /* our PeerInfo: type ADB_RSA_PUB_KEY, data = contents of adbkey.pub */
    uint8_t *peerinfo = calloc(1, PAIR_PEERINFO_SIZE);
    if (!peerinfo) return -1;
    peerinfo[0] = PAIR_TYPE_ADB_RSA_PUB_KEY;
    FILE *f = fopen(pubkey_path, "r");
    if (!f) {
        fprintf(stderr, "adbwire: pairing: cannot read %s\n", pubkey_path);
        free(peerinfo);
        return -1;
    }
    size_t n = fread(peerinfo + 1, 1, PAIR_PEERINFO_SIZE - 2, f);
    fclose(f);
    while (n > 0 && (peerinfo[1 + n - 1] == '\n' || peerinfo[1 + n - 1] == '\r'))
        peerinfo[1 + --n] = '\0';

    uint8_t *enc = malloc(PAIR_PEERINFO_SIZE + 16);
    if (!enc) {
        free(peerinfo);
        return -1;
    }
    size_t enclen = 0;
    if (aes128gcm_seal(aeskey, 0, peerinfo, PAIR_PEERINFO_SIZE, enc, &enclen) <
            0 ||
        pair_write_hdr(ssl, PAIR_TYPE_PEERINFO, (uint32_t)enclen) < 0 ||
        ssl_write_all(ssl, enc, enclen) < 0) {
        free(peerinfo);
        free(enc);
        return -1;
    }
    free(peerinfo);

    if (pair_read_hdr(ssl, &type, &payload) < 0 || type != PAIR_TYPE_PEERINFO ||
        payload < 16 || payload > PAIR_PEERINFO_SIZE + 16) {
        free(enc);
        fprintf(stderr, "adbwire: pairing: bad peer-info reply header\n");
        return -1;
    }
    uint8_t *rbuf = malloc(payload);
    uint8_t *dec = malloc(payload);
    if (!rbuf || !dec) {
        free(rbuf);
        free(dec);
        free(enc);
        return -1;
    }
    if (ssl_read_all(ssl, rbuf, payload) < 0) {
        free(rbuf);
        free(dec);
        free(enc);
        return -1;
    }
    size_t declen = 0;
    if (aes128gcm_open(aeskey, 0, rbuf, payload, dec, &declen) < 0) {
        free(rbuf);
        free(dec);
        free(enc);
        fprintf(stderr, "adbwire: pairing: peer-info decrypt failed\n");
        return -1;
    }
    if (declen >= 1 && dec[0] == PAIR_TYPE_ADB_DEVICE_GUID)
        fprintf(stderr, "adbwire: paired with device '%s'\n",
                declen > 1 ? (char *)(dec + 1) : "?");
    free(rbuf);
    free(dec);
    free(enc);
    return 0;
}

static int pair_run(const char *host, const char *port, const char *code,
                    EVP_PKEY *pkey, const char *keypath) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) return -1;
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    X509 *cert = self_signed_from(pkey);
    if (!cert || SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        X509_free(cert);
        SSL_CTX_free(ctx);
        return -1;
    }
    struct cert_ctx cc = {cert, pkey};
    SSL_CTX_set_cert_cb(ctx, tls_cert_cb, &cc);

    int fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "adbwire: pairing: cannot connect to %s:%s\n", host, port);
        X509_free(cert);
        SSL_CTX_free(ctx);
        return -1;
    }
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "adbwire: pairing: TLS handshake with %s:%s failed\n",
                host, port);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        X509_free(cert);
        SSL_CTX_free(ctx);
        return -1;
    }
    char pubkey_path[PATH_MAX];
    snprintf(pubkey_path, sizeof(pubkey_path), "%s.pub", keypath);
    int rc = pair_over_tls(ssl, code, pubkey_path);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    X509_free(cert);
    SSL_CTX_free(ctx);
    return rc;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "usage: %s [-s <host:port>] [-k <adbkey>] [-p <stdin-file>] [-t <sec>] <command...>\n"
            "       %s --pair <code> [-s <host:port>] [-k <adbkey>] [-t <sec>]\n"
            "\n"
            "  -s host:port   wireless-debugging address. For a command, the connect\n"
            "                 port; for --pair, the pairing address. If omitted, the\n"
            "                 port is discovered over mDNS and reached at 127.0.0.1.\n"
            "  -k path        private key (default ~/.android/adbkey)\n"
            "  -p file        stream file into the remote command's stdin\n"
            "  -t seconds     mDNS discovery timeout (default 5)\n"
            "  -P, --pair code  pair using the 6-digit code shown in the Wireless\n"
            "                 debugging pairing dialog, then exit\n"
            "  -d, --discover print the discovered connect port and exit\n"
            "  -h, --help     this help\n"
            "\n"
            "Exit status is the remote command's exit status.\n",
            prog, prog);
}

int main(int argc, char **argv) {
    const char *serial = NULL, *keypath = NULL, *infile = NULL, *pair_code = NULL;
    int opt, discover_timeout = 5, discover_only = 0;
    static const struct option longopts[] = {
        {"discover", no_argument, 0, 'd'},
        {"pair", required_argument, 0, 'P'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0},
    };

    while ((opt = getopt_long(argc, argv, "s:k:p:t:P:dh", longopts, NULL)) != -1) {
        switch (opt) {
            case 's': serial = optarg; break;
            case 'k': keypath = optarg; break;
            case 'p': infile = optarg; break;
            case 't': discover_timeout = atoi(optarg); break;
            case 'P': pair_code = optarg; break;
            case 'd': discover_only = 1; break;
            case 'h': usage(argv[0]); return 0;
            default: usage(argv[0]); return 1;
        }
    }

    if (pair_code) {
        char phost[256], pport[32], pkeybuf[PATH_MAX];
        if (serial) {
            const char *colon = strrchr(serial, ':');
            if (!colon || colon == serial || colon[1] == '\0') {
                fprintf(stderr, "adbwire: -s must be host:port (got '%s')\n", serial);
                return 1;
            }
            size_t hlen = (size_t)(colon - serial);
            if (hlen >= sizeof(phost)) hlen = sizeof(phost) - 1;
            memcpy(phost, serial, hlen);
            phost[hlen] = '\0';
            snprintf(pport, sizeof(pport), "%s", colon + 1);
        } else {
            uint16_t p;
            if (discover_pairing_port(discover_timeout, &p) < 0) {
                fprintf(stderr, "adbwire: no pairing service found via mDNS - open "
                                "Wireless debugging -> 'Pair device with pairing code' "
                                "(or pass -s host:port)\n");
                return 1;
            }
            snprintf(phost, sizeof(phost), "127.0.0.1");
            snprintf(pport, sizeof(pport), "%u", p);
        }
        if (!keypath) {
            const char *home = getenv("HOME");
            snprintf(pkeybuf, sizeof(pkeybuf), "%s/.android/adbkey",
                     home ? home : ".");
            keypath = pkeybuf;
        }
        EVP_PKEY *pkey = load_key(keypath);
        if (!pkey) {
            fprintf(stderr, "adbwire: cannot read private key %s\n", keypath);
            ERR_print_errors_fp(stderr);
            return 1;
        }
        int rc = pair_run(phost, pport, pair_code, pkey, keypath);
        EVP_PKEY_free(pkey);
        if (rc == 0) {
            printf("paired\n");
            return 0;
        }
        return 1;
    }

    char host[256], port[32], target[300];
    if (!serial) {
        uint16_t p;
        if (discover_adb_port(discover_timeout, &p) < 0) {
            fprintf(stderr, "adbwire: no wireless-debugging service found via "
                            "mDNS (is Wireless Debugging on? pass -s host:port "
                            "to skip discovery)\n");
            return 1;
        }
        snprintf(host, sizeof(host), "127.0.0.1");
        snprintf(port, sizeof(port), "%u", p);
        if (discover_only) {
            printf("%u\n", p);
            return 0;
        }
    } else {
        if (discover_only) {
            fprintf(stderr, "adbwire: --discover and -s are mutually exclusive\n");
            return 1;
        }
        /* split host:port (last colon, so IPv6 literals without brackets
         * still resolve sensibly for the common IPv4 case) */
        const char *colon = strrchr(serial, ':');
        if (!colon || colon == serial || colon[1] == '\0') {
            fprintf(stderr, "adbwire: -s must be host:port (got '%s')\n", serial);
            return 1;
        }
        size_t hlen = (size_t)(colon - serial);
        if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
        memcpy(host, serial, hlen);
        host[hlen] = '\0';
        snprintf(port, sizeof(port), "%s", colon + 1);
    }
    snprintf(target, sizeof(target), "%s:%s", host, port);

    if (!discover_only && optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    char keybuf[PATH_MAX];
    if (!keypath) {
        const char *home = getenv("HOME");
        snprintf(keybuf, sizeof(keybuf), "%s/.android/adbkey",
                 home ? home : ".");
        keypath = keybuf;
    }

    EVP_PKEY *pkey = load_key(keypath);
    if (!pkey) {
        fprintf(stderr, "adbwire: cannot read private key %s\n", keypath);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        fprintf(stderr, "adbwire: SSL_CTX_new failed\n");
        return 1;
    }
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    X509 *cert = self_signed_from(pkey);
    if (!cert || SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, pkey) != 1) {
        fprintf(stderr, "adbwire: failed to install client key/cert\n");
        ERR_print_errors_fp(stderr);
        return 1;
    }
    struct cert_ctx cc = {cert, pkey};
    SSL_CTX_set_cert_cb(ctx, tls_cert_cb, &cc);
    SSL_CTX_set_info_callback(ctx, tls_info_cb);

    int fd = tcp_connect(host, port);
    if (fd < 0) {
        fprintf(stderr, "adbwire: cannot connect to %s\n", target);
        return 1;
    }

    struct adb_io io = {.fd = fd, .ssl = NULL};

    /* Plaintext "start TLS" exchange must happen before any TLS bytes. */
    if (adb_start_tls(&io) < 0) {
        fprintf(stderr, "adbwire: device did not offer STLS (not a wireless "
                        "debugging connect port?)\n");
        close(fd);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, fd);
    if (SSL_connect(ssl) != 1) {
        fprintf(stderr, "adbwire: TLS handshake with %s failed\n", target);
        ERR_print_errors_fp(stderr);
        close(fd);
        return 1;
    }
    io.ssl = ssl;

    if (adb_handshake(&io, pkey) < 0) {
        fprintf(stderr, "adbwire: ADB handshake failed (not paired, or key "
                        "not trusted?)\n");
        SSL_shutdown(ssl);
        SSL_free(ssl); /* owns the socket BIO: closes fd */
        return 1;
    }

    int in_fd = -1;
    if (infile) {
        in_fd = open(infile, O_RDONLY);
        if (in_fd < 0) {
            fprintf(stderr, "adbwire: cannot open %s: %s\n", infile,
                    strerror(errno));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return 1;
        }
    }

    /* join remaining args with spaces, like `adb shell` does */
    size_t cmdlen = 1;
    for (int i = optind; i < argc; i++) cmdlen += strlen(argv[i]) + 1;
    char *command = malloc(cmdlen);
    if (!command) {
        fprintf(stderr, "adbwire: out of memory\n");
        return 1;
    }
    command[0] = '\0';
    for (int i = optind; i < argc; i++) {
        if (i > optind) strcat(command, " ");
        strcat(command, argv[i]);
    }

    int rc = run_shell(&io, command, in_fd);
    if (in_fd >= 0) close(in_fd);

    SSL_shutdown(ssl);
    SSL_free(ssl); /* owns the socket BIO: closes fd */
    SSL_CTX_free(ctx);
    X509_free(cert);
    EVP_PKEY_free(pkey);
    free(command);

    return rc < 0 ? 1 : rc;
}
