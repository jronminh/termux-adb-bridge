// SPDX-License-Identifier: GPL-3.0-only
// relaysh-client (v3) — Termux-side client for relaysh-daemon.
//
// Speaks the v3 protocol (see protocol.h): a challenge/response handshake
// that authenticates the daemon, then two ChaCha20+HMAC AEAD streams. stdout
// and stderr arrive as separate authenticated streams. Exit code is the
// remote command's real exit code (128+signal on a signal death).
//
// Config: the pre-shared secret and port are baked in at build time -
// build/build.sh generates one secret and compiles it into both this client
// and the daemon together, so no secret is ever stored as a file. An explicit
// RELAYSH_PORT_FILE / RELAYSH_SECRET_FILE overrides them, for talking to a
// differently-configured daemon (e.g. in tests).
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol.h"
#include "relaysh-crypto.h"
#include "relaysh-policy.h"

#define HOST "127.0.0.1"
#define RESPONSE_TIMEOUT_SECONDS 40
#define PAYLOAD_MARKER "\n__RELAYSH_PAYLOAD__\n"
#define PAYLOAD_MARKER_LEN 21

// Substituted by build/build.sh. Same secret as the daemon built in the same
// run; there is no on-disk secret anywhere.
static const int BAKED_PORT = __TRUSTED_PORT_PLACEHOLDER__;
static const char BAKED_SECRET[] = "__SECRET_PLACEHOLDER__";

static int g_quiet = 0;
static int g_no_audit = 0;

#define POLICY_DENY_EXIT 77
#define AUDIT_MAX_BYTES  (1024 * 1024)

// Prints the baked allowlist (or a note that there is none). No daemon
// round-trip: build.sh compiles the same list into this client.
static void print_policy(void) {
#if RELAYSH_POLICY_PRESENT
    for (size_t i = 0; relaysh_policy_allow[i] != NULL; i++)
        printf("%s\n", relaysh_policy_allow[i]);
#else
    printf("(no policy - all commands allowed)\n");
#endif
}

// Appends one audit line to $HOME/.local/share/relaysh/audit.log (or
// $RELAYSH_AUDIT_LOG). Best-effort: never fails the command. This is a
// client-side trace, so it stays readable even when the daemon is down —
// it is evidence for debugging, not a tamper-proof log.
static void audit_log(const char* cmd, int code, long ms) {
    if (g_no_audit) return;
    char path[PATH_MAX];
    const char* env = getenv("RELAYSH_AUDIT_LOG");
    if (env && *env) {
        snprintf(path, sizeof(path), "%s", env);
    } else {
        const char* home = getenv("HOME");
        if (!home || !*home) return;
        char dir[PATH_MAX];
        snprintf(dir, sizeof(dir), "%s/.local/share/relaysh", home);
        mkdir(dir, 0700);
        snprintf(path, sizeof(path), "%s/audit.log", dir);
    }

    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > AUDIT_MAX_BYTES) {
        char old[PATH_MAX];
        snprintf(old, sizeof(old), "%s.1", path);
        rename(path, old);
    }

    FILE* f = fopen(path, "a");
    if (!f) return;
    chmod(path, 0600);

    char ts[32];
    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", &tm);

    char esc[512];
    size_t j = 0;
    for (size_t i = 0; cmd[i] && j < sizeof(esc) - 1; i++) {
        unsigned char c = (unsigned char)cmd[i];
        esc[j++] = (c == '\n' || c == '\r' || c == '\t') ? ' ' : (char)c;
    }
    esc[j] = 0;

    const char* decision = (code == POLICY_DENY_EXIT) ? "deny" : "allow";
    fprintf(f, "%s code=%d decision=%s ms=%ld cmd=%s\n", ts, code, decision, ms, esc);
    fclose(f);
}

static void usage(FILE* out) {
    fputs(
"Usage: relaysh-client [OPTIONS] COMMAND...\n"
"       relaysh-client -c 'COMMAND'\n"
"       echo 'COMMAND' | relaysh-client -f -\n"
"\n"
"Run COMMAND at the relaysh daemon's UID (normally `shell`) and print its\n"
"output (stdout and stderr stay separate). Exit code is the remote command's\n"
"real exit code (128+signal for a signal death).\n"
"\n"
"Options:\n"
"  -c CMD         Run CMD instead of the positional arguments.\n"
"  -f FILE        Read the command from FILE (\"-\" reads stdin).\n"
"  -p FILE        Stream FILE's bytes to the command's stdin (\"-\" reads\n"
"                 stdin). Works on any v3 daemon.\n"
"  -q, --quiet    Suppress this tool's own status/error messages.\n"
"  -v, --verbose  Print the exact command being sent, to stderr.\n"
"  --check        Health check: run `id` against the daemon.\n"
"  --policy       Print the baked exact-match allowlist (or note there is\n"
"                 none) and exit. No daemon contact.\n"
"  --no-audit     Do not append to the audit log for this call.\n"
"  -h, --help     Show this help.\n",
    out);
}

static void die_usage(const char* msg) {
    if (!g_quiet && msg) fprintf(stderr, "relaysh-client: %s\n", msg);
    usage(stderr);
    exit(2);
}
static void err_exit(int code, const char* fmt, ...) {
    if (!g_quiet) {
        va_list ap; va_start(ap, fmt);
        fprintf(stderr, "relaysh-client: ");
        vfprintf(stderr, fmt, ap);
        fprintf(stderr, "\n");
        va_end(ap);
    }
    exit(code);
}

static char* xstrdup_trimmed(const char* s, size_t n) {
    while (n > 0 && isspace((unsigned char)s[n - 1])) n--;
    size_t start = 0;
    while (start < n && isspace((unsigned char)s[start])) start++;
    char* out = malloc(n - start + 1);
    memcpy(out, s + start, n - start);
    out[n - start] = 0;
    return out;
}

static char* read_stream_strip_trailing_nl(FILE* f) {
    size_t cap = 4096, len = 0;
    char* buf = malloc(cap);
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, f)) > 0) {
        len += r;
        if (len == cap) { cap *= 2; buf = realloc(buf, cap); }
    }
    while (len > 0 && buf[len - 1] == '\n') len--;
    buf = realloc(buf, len + 1);
    buf[len] = 0;
    return buf;
}

static char* read_file_trimmed(const char* path) {
    FILE* f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 256, len = 0;
    char* buf = malloc(cap);
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, f)) > 0) {
        len += r;
        if (len == cap) { cap *= 2; buf = realloc(buf, cap); }
    }
    fclose(f);
    char* trimmed = xstrdup_trimmed(buf, len);
    free(buf);
    return trimmed;
}

static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}
static void put_be64(unsigned char out[8], uint64_t v) {
    for (int i = 0; i < 8; i++) out[i] = (unsigned char)((v >> (56 - 8*i)) & 0xFF);
}
static uint32_t get_be32(const unsigned char in[4]) {
    return ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
           ((uint32_t)in[2] << 8)  | (uint32_t)in[3];
}

static int connect_daemon(int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) err_exit(1, "socket() failed: %s", strerror(errno));
    struct timeval tv = { .tv_sec = RESPONSE_TIMEOUT_SECONDS, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, HOST, &addr.sin_addr);
    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) != 0)
        err_exit(1, "could not connect to daemon on 127.0.0.1:%d: %s (is it running? see the README)", port, strerror(errno));
    return fd;
}

// ---------------------------------------------------------------- v3 client
static int v3_handshake(int fd, const unsigned char secret[32], proto_keys* keys) {
    unsigned char cnonce[PROTO_NONCE_LEN];
    if (relaysh_random(cnonce, sizeof(cnonce)) != 0) return -1;
    unsigned char hello[PROTO_HELLO_LEN];
    memcpy(hello, PROTO_MAGIC, PROTO_MAGIC_LEN);
    hello[PROTO_MAGIC_LEN] = PROTO_VERSION;
    memcpy(hello + PROTO_MAGIC_LEN + 1, cnonce, PROTO_NONCE_LEN);
    put_be64(hello + PROTO_MAGIC_LEN + 1 + PROTO_NONCE_LEN, (uint64_t)now_ns());
    if (proto_write_full(fd, hello, PROTO_HELLO_LEN) != 0) return -1;

    unsigned char resp[PROTO_PROOF_LEN];
    if (proto_read_full(fd, resp, PROTO_PROOF_LEN) != 0) return -1;
    if (memcmp(resp, PROTO_MAGIC, PROTO_MAGIC_LEN) != 0) return -1;
    const unsigned char* dnonce = resp + PROTO_MAGIC_LEN;
    const unsigned char* proof  = dnonce + PROTO_NONCE_LEN;
    unsigned char expect[32];
    proto_derive(secret, cnonce, dnonce, keys, expect);
    if (relaysh_constant_time_eq(expect, proof, 32) != 0) return -1; // server auth failed
    return 0;
}

// Sends the request (command + optional payload), relays the response to
// stdout/stderr, returns 0 and sets *exit_code on success, -1 on failure.
static int v3_run(int fd, const proto_keys* keys, const char* command,
                  const char* payload_path, int* exit_code) {
    uint64_t ctr = 0, rctr = 0;
    size_t cmdlen = strlen(command);
    int has_payload = payload_path != NULL;
    size_t region_len = cmdlen + (has_payload ? PAYLOAD_MARKER_LEN : 0);

    unsigned char* region = malloc(region_len ? region_len : 1);
    memcpy(region, command, cmdlen);
    if (has_payload) memcpy(region + cmdlen, PAYLOAD_MARKER, PAYLOAD_MARKER_LEN);

    for (size_t off = 0; off < region_len; ) {
        size_t n = region_len - off;
        if (n > PROTO_MSG_MAX) n = PROTO_MSG_MAX;
        if (proto_send_msg(fd, keys, 0, &ctr, PROTO_T_DATA, region + off, n) != 0) {
            free(region); return -1;
        }
        off += n;
    }
    free(region);

    if (has_payload) {
        FILE* pf = strcmp(payload_path, "-") == 0 ? stdin : fopen(payload_path, "rb");
        if (!pf) err_exit(2, "could not open -p payload file: %s", payload_path);
        unsigned char pbuf[16384];
        size_t r;
        while ((r = fread(pbuf, 1, sizeof(pbuf), pf)) > 0) {
            if (proto_send_msg(fd, keys, 0, &ctr, PROTO_T_DATA, pbuf, r) != 0) {
                if (pf != stdin) fclose(pf);
                return -1;
            }
        }
        if (pf != stdin) fclose(pf);
    }

    if (proto_send_msg(fd, keys, 0, &ctr, PROTO_T_END, NULL, 0) != 0) return -1;

    unsigned char buf[PROTO_MSG_MAX];
    for (;;) {
        unsigned char type;
        size_t n = 0;
        if (proto_recv_msg(fd, keys, 1, &rctr, &type, buf, sizeof(buf), &n) != 0) return -1;
        if (type == PROTO_T_END) {
            if (n != 4) return -1;
            *exit_code = (int)get_be32(buf);
            return 0;
        }
        FILE* out = (type == PROTO_T_STDERR) ? stderr : stdout;
        if (n) fwrite(buf, 1, n, out);
    }
}

int main(int argc, char** argv) {
    int verbose = 0, check = 0;
    const char* opt_c = NULL;
    const char* opt_f = NULL;
    const char* opt_p = NULL;
    int i = 1;
    for (; i < argc; i++) {
        const char* a = argv[i];
        if (strcmp(a, "-c") == 0) { if (i + 1 >= argc) die_usage("-c requires an argument"); opt_c = argv[++i]; }
        else if (strcmp(a, "-f") == 0) { if (i + 1 >= argc) die_usage("-f requires an argument"); opt_f = argv[++i]; }
        else if (strcmp(a, "-p") == 0) { if (i + 1 >= argc) die_usage("-p requires an argument"); opt_p = argv[++i]; }
        else if (strcmp(a, "-q") == 0 || strcmp(a, "--quiet") == 0) g_quiet = 1;
        else if (strcmp(a, "-v") == 0 || strcmp(a, "--verbose") == 0) verbose = 1;
        else if (strcmp(a, "--check") == 0) check = 1;
        else if (strcmp(a, "--policy") == 0) { print_policy(); return 0; }
        else if (strcmp(a, "--no-audit") == 0) g_no_audit = 1;
        else if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) { usage(stdout); return 0; }
        else if (strcmp(a, "--") == 0) { i++; break; }
        else if (a[0] == '-' && a[1] != '\0') { char b[64]; snprintf(b, sizeof(b), "unknown option: %s", a); die_usage(b); }
        else break;
    }

    char* command = NULL;
    if (check) command = strdup("id");
    else if (opt_c) command = strdup(opt_c);
    else if (opt_f) {
        FILE* f = strcmp(opt_f, "-") == 0 ? stdin : fopen(opt_f, "r");
        if (!f) err_exit(2, "could not open -f file: %s", opt_f);
        command = read_stream_strip_trailing_nl(f);
        if (f != stdin) fclose(f);
    } else if (i < argc) {
        size_t len = 0;
        for (int j = i; j < argc; j++) len += strlen(argv[j]) + 1;
        command = malloc(len + 1);
        command[0] = 0;
        for (int j = i; j < argc; j++) { if (j > i) strcat(command, " "); strcat(command, argv[j]); }
    } else if (!isatty(0)) {
        command = read_stream_strip_trailing_nl(stdin);
    } else {
        die_usage(NULL);
    }
    if (!command || command[0] == 0) err_exit(2, "empty command, nothing to send");

    int port = BAKED_PORT;
    const char* port_env = getenv("RELAYSH_PORT_FILE");
    if (port_env && *port_env) {
        char* port_str = read_file_trimmed(port_env);
        if (!port_str) err_exit(127, "could not read port file: %s", port_env);
        port = atoi(port_str);
        if (port <= 0) err_exit(127, "invalid port in %s: %s", port_env, port_str);
        free(port_str);
    }

    char* secret = NULL;
    const char* secret_env = getenv("RELAYSH_SECRET_FILE");
    if (secret_env && *secret_env) {
        secret = read_file_trimmed(secret_env);
        if (!secret) err_exit(127, "could not read secret file: %s", secret_env);
    } else {
        secret = strdup(BAKED_SECRET);
    }

    if (verbose) fprintf(stderr, "+ %s\n", command);

    unsigned char key[32];
    if (proto_hex_decode32(secret, key) != 0)
        err_exit(127, "secret is not a 64-char hex string (v3 requires 32 raw bytes)");

    int fd = connect_daemon(port);
    proto_keys keys;
    if (v3_handshake(fd, key, &keys) != 0) {
        close(fd);
        err_exit(1, "server authentication failed (no daemon, or wrong secret)");
    }
    int code = 0;
    int64_t t0 = now_ns();
    if (v3_run(fd, &keys, command, opt_p, &code) != 0) {
        close(fd);
        if (!check) audit_log(command, -1, (long)((now_ns() - t0) / 1000000));
        err_exit(1, "connection failed mid-request (daemon died?)");
    }
    close(fd);
    if (!check) audit_log(command, code, (long)((now_ns() - t0) / 1000000));
    return code;
}
