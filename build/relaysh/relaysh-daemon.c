// SPDX-License-Identifier: GPL-3.0-only
// relaysh-daemon (v3) — persistent command relay at the `shell` UID, reached
// over TCP loopback from Termux. One access point on one (random) port.
//
// What changed from v2: the auth layer. v2 shipped a single `sha256(secret)`
// tag and sent the command in the clear. v3 does a challenge/response
// handshake so the CLIENT authenticates the SERVER, then runs two
// independent ChaCha20+HMAC AEAD streams (one per direction) so the command
// and its output are encrypted and authenticated. The pre-shared 32-byte
// secret (per-daemon, from ~/.config/relaysh/secrets) is the root key.
//
// The platform-forced core is unchanged and deliberate:
//   - one-time `adb shell` bootstrap, double-fork + setsid to persist;
//   - TCP loopback only (proved the only cross-domain call channel);
//   - kernel-verified peer UID via /proc/net/tcp, checked BEFORE any crypto;
//   - request/response with the command's real exit code;
//   - payload streaming for self-deploy (the new binary rides the AEAD
//     stream, so no world-readable /sdcard staging);
//   - stdout and stderr are separate authenticated streams.
//
// This is an access point, not an API: authenticate, run exactly the command
// given, relay what came back. No verbs, no allowlists.
//
// The daemon does not try to survive an adbd session recycle (nothing can,
// without root) — relaysh-deploy.sh recovers it externally.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "protocol.h"
#include "relaysh-crypto.h"

#define TRUSTED_UID __TRUSTED_UID_PLACEHOLDER__
#define TRUSTED_PORT __TRUSTED_PORT_PLACEHOLDER__
#define SECRET "__SECRET_PLACEHOLDER__"

#define MAX_NONCES 200
#define MAX_NONCE_AGE_SECONDS 10
#define COMMAND_TIMEOUT_SECONDS 30
#define CONN_IO_TIMEOUT_SECONDS 5
#define PAYLOAD_MARKER "\n__RELAYSH_PAYLOAD__\n"
#define PAYLOAD_MARKER_LEN 21

static unsigned char g_secret[32];
static int g_srv = -1;

// ------------------------------------------------------------------ helpers
static int64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static uint64_t get_be64(const unsigned char in[8]) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | in[i];
    return v;
}
static void put_be32(unsigned char out[4], uint32_t v) {
    out[0] = (unsigned char)((v >> 24) & 0xFF);
    out[1] = (unsigned char)((v >> 16) & 0xFF);
    out[2] = (unsigned char)((v >>  8) & 0xFF);
    out[3] = (unsigned char)( v        & 0xFF);
}

// Replay ring over client nonces (process-local: auth stays single-process).
static unsigned char seen_nonces[MAX_NONCES][PROTO_NONCE_LEN];
static int seen_count = 0;
static int nonce_seen(const unsigned char* n) {
    for (int i = 0; i < seen_count; i++)
        if (memcmp(seen_nonces[i], n, PROTO_NONCE_LEN) == 0) return 1;
    return 0;
}
static void nonce_record(const unsigned char* n) {
    if (seen_count < MAX_NONCES) {
        memcpy(seen_nonces[seen_count++], n, PROTO_NONCE_LEN);
    } else {
        memmove(seen_nonces[0], seen_nonces[1], sizeof(seen_nonces[0]) * (MAX_NONCES - 1));
        memcpy(seen_nonces[MAX_NONCES - 1], n, PROTO_NONCE_LEN);
    }
}

// Kernel-recorded uid of the peer, read from /proc/net/tcp (only possible at
// shell UID). Returns -1 if not found / not readable.
static int peer_uid_via_procfs(int conn) {
    struct sockaddr_in peer_addr = {0}, local_addr = {0};
    socklen_t plen = sizeof(peer_addr), llen = sizeof(local_addr);
    if (getpeername(conn, (struct sockaddr*)&peer_addr, &plen) != 0) return -1;
    if (getsockname(conn, (struct sockaddr*)&local_addr, &llen) != 0) return -1;

    char want_local[24], want_rem[24];
    snprintf(want_local, sizeof(want_local), "%08X:%04X", local_addr.sin_addr.s_addr, ntohs(peer_addr.sin_port));
    snprintf(want_rem, sizeof(want_rem), "%08X:%04X", local_addr.sin_addr.s_addr, ntohs(local_addr.sin_port));

    FILE* f = fopen("/proc/net/tcp", "r");
    if (!f) return -1;
    char line[512];
    fgets(line, sizeof(line), f);
    int found_uid = -1;
    while (fgets(line, sizeof(line), f)) {
        char lstr[64], rstr[64];
        int uid = -1;
        if (sscanf(line, "%*s %63s %63s %*s %*s %*s %*s %d", lstr, rstr, &uid) == 3) {
            if (strcmp(lstr, want_local) == 0 && strcmp(rstr, want_rem) == 0) { found_uid = uid; break; }
        }
    }
    fclose(f);
    return found_uid;
}

static void set_conn_timeouts(int conn) {
    struct timeval tv = { .tv_sec = CONN_IO_TIMEOUT_SECONDS, .tv_usec = 0 };
    setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(conn, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// ------------------------------------------------------------- command exec
static pid_t spawn_command(const char* command, int* out_fd, int* err_fd, int* in_fd) {
    int op[2], ep[2], ip[2];
    if (pipe(op) != 0 || pipe(ep) != 0 || pipe(ip) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(op[0]); close(op[1]); close(ep[0]); close(ep[1]); close(ip[0]); close(ip[1]); return -1; }
    if (pid == 0) {
        dup2(ip[0], STDIN_FILENO);
        dup2(op[1], STDOUT_FILENO);
        dup2(ep[1], STDERR_FILENO);
        close(op[0]); close(op[1]); close(ep[0]); close(ep[1]); close(ip[0]); close(ip[1]);
        execl("/system/bin/sh", "sh", "-c", command, (char*)NULL);
        _exit(127);
    }
    close(op[1]); close(ep[1]); close(ip[0]);
    *out_fd = op[0]; *err_fd = ep[0]; *in_fd = ip[1];
    return pid;
}

static volatile pid_t g_cmd_pid = -1;
static void on_command_alarm(int sig) { (void)sig; if (g_cmd_pid > 0) kill(g_cmd_pid, SIGKILL); }
static void arm_command_timeout(pid_t pid) {
    g_cmd_pid = pid;
    signal(SIGALRM, on_command_alarm);
    alarm(COMMAND_TIMEOUT_SECONDS);
}
static int reap_command(pid_t pid) {
    int status = 0;
    waitpid(pid, &status, 0);
    alarm(0);
    g_cmd_pid = -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

// Reads the whole AEAD request stream (command + optional payload), runs it,
// relays stdout/stderr as separate authenticated streams, then the exit code.
static void run_worker(int conn, const proto_keys* keys) {
    signal(SIGPIPE, SIG_IGN);

    unsigned char* req = malloc(PROTO_REQ_MAX);
    if (!req) { close(conn); return; }
    size_t total = 0;
    uint64_t rctr = 0, sctr = 0;
    for (;;) {
        unsigned char type;
        size_t n = 0;
        if (proto_recv_msg(conn, keys, 0, &rctr, &type, req + total,
                           PROTO_REQ_MAX - total, &n) != 0) {
            free(req); close(conn); return;
        }
        if (type == PROTO_T_END) break;
        total += n;
    }

    size_t cmd_len = total, payload_off = total;
    for (size_t i = 0; i + PAYLOAD_MARKER_LEN <= total; i++) {
        if (memcmp(req + i, PAYLOAD_MARKER, PAYLOAD_MARKER_LEN) == 0) {
            cmd_len = i;
            payload_off = i + PAYLOAD_MARKER_LEN;
            break;
        }
    }
    char* cmd = malloc(cmd_len + 1);
    if (!cmd) { free(req); close(conn); return; }
    memcpy(cmd, req, cmd_len);
    cmd[cmd_len] = 0;
    const unsigned char* payload = req + payload_off;
    size_t payload_len = total - payload_off;

    int ofd = -1, efd = -1, ifd = -1;
    pid_t pid = spawn_command(cmd, &ofd, &efd, &ifd);
    if (pid < 0) {
        unsigned char cb[4]; put_be32(cb, 1);
        proto_send_msg(conn, keys, 1, &sctr, PROTO_T_END, cb, 4);
        free(cmd); free(req); close(conn); return;
    }
    if (payload_len > 0) {
        size_t off = 0;
        while (off < payload_len) {
            ssize_t w = write(ifd, payload + off, payload_len - off);
            if (w <= 0) break;
            off += (size_t)w;
        }
    }
    close(ifd);
    free(req);

    arm_command_timeout(pid);

    struct pollfd pfd[2] = { { ofd, POLLIN, 0 }, { efd, POLLIN, 0 } };
    int open = 2;
    unsigned char out[4096];
    while (open > 0) {
        int r = poll(pfd, 2, -1);
        if (r < 0) { if (errno == EINTR) continue; break; }
        for (int i = 0; i < 2; i++) {
            if (!(pfd[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t n = read(pfd[i].fd, out, sizeof(out));
            if (n > 0) {
                unsigned char t = (i == 0) ? PROTO_T_DATA : PROTO_T_STDERR;
                if (proto_send_msg(conn, keys, 1, &sctr, t, out, (size_t)n) != 0) {
                    pfd[0].fd = pfd[1].fd = -1; open = 0; break;
                }
            } else {
                close(pfd[i].fd);
                pfd[i].fd = -1; pfd[i].events = 0; pfd[i].revents = 0;
                open--;
            }
        }
    }
    if (ofd >= 0 && pfd[0].fd >= 0) close(pfd[0].fd);
    if (efd >= 0 && pfd[1].fd >= 0) close(pfd[1].fd);

    int code = reap_command(pid);
    unsigned char cb[4];
    put_be32(cb, (uint32_t)code);
    proto_send_msg(conn, keys, 1, &sctr, PROTO_T_END, cb, 4);

    free(cmd);
    close(conn);
}

// Auth phase: peer UID, HELLO, freshness/replay, PROOF. Stays single-process
// (the replay ring is a plain array). Only running the command forks.
static void handle_conn(int conn) {
    int uid = peer_uid_via_procfs(conn);
    if (uid != TRUSTED_UID) { close(conn); return; }
    set_conn_timeouts(conn);

    unsigned char hello[PROTO_HELLO_LEN];
    if (proto_read_full(conn, hello, PROTO_HELLO_LEN) != 0) { close(conn); return; }
    if (memcmp(hello, PROTO_MAGIC, PROTO_MAGIC_LEN) != 0 || hello[PROTO_MAGIC_LEN] != PROTO_VERSION) {
        close(conn); return;
    }
    const unsigned char* cnonce = hello + PROTO_MAGIC_LEN + 1;
    uint64_t ts = get_be64(hello + PROTO_MAGIC_LEN + 1 + PROTO_NONCE_LEN);
    int64_t age = now_ns() - (int64_t)ts;
    if (age < 0) age = -age;
    if (age > (int64_t)MAX_NONCE_AGE_SECONDS * 1000000000LL) { close(conn); return; }
    if (nonce_seen(cnonce)) { close(conn); return; }
    nonce_record(cnonce);

    unsigned char dnonce[PROTO_NONCE_LEN];
    if (relaysh_random(dnonce, sizeof(dnonce)) != 0) { close(conn); return; }

    proto_keys keys;
    unsigned char proof[32];
    proto_derive(g_secret, cnonce, dnonce, &keys, proof);

    unsigned char resp[PROTO_PROOF_LEN];
    memcpy(resp, PROTO_MAGIC, PROTO_MAGIC_LEN);
    memcpy(resp + PROTO_MAGIC_LEN, dnonce, PROTO_NONCE_LEN);
    memcpy(resp + PROTO_MAGIC_LEN + PROTO_NONCE_LEN, proof, 32);
    if (proto_write_full(conn, resp, PROTO_PROOF_LEN) != 0) { close(conn); return; }

    pid_t worker = fork();
    if (worker < 0) { close(conn); return; }
    if (worker == 0) {
        signal(SIGCHLD, SIG_DFL);
        close(g_srv); // the worker/command must not hold the listen socket
        run_worker(conn, &keys);
        _exit(0);
    }
    close(conn);
}

// Standard double-fork daemonization: detach from the adb shell session that
// spawned us so a dropped connection doesn't SIGHUP us. (The cgroup is still
// adbd's — only root could change that; relaysh-deploy.sh recovers us.)
//
// Closing inherited fds is load-bearing, not cosmetic: a new daemon is
// usually launched as a *command through the old daemon*, so it inherits the
// old daemon's listening socket. Without this, every deploy would leave the
// previous port bound by a ghost listener held open by the new process.
static void close_inherited_fds(void) {
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++) close(fd);
}

static void daemonize(void) {
    pid_t pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    if (setsid() < 0) exit(1);
    signal(SIGHUP, SIG_IGN);
    pid = fork();
    if (pid < 0) exit(1);
    if (pid > 0) exit(0);
    umask(0);
    chdir("/");
    close_inherited_fds();
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO) close(null_fd);
    }
}

int main(void) {
    if (relaysh_crypto_selftest() != 0) {
        fprintf(stderr, "relaysh-daemon: crypto self-test FAILED, refusing to start\n");
        return 1;
    }
    if (proto_hex_decode32(SECRET, g_secret) != 0) {
        fprintf(stderr, "relaysh-daemon: SECRET is not 64 hex chars\n");
        return 1;
    }

    daemonize();
    signal(SIGCHLD, SIG_IGN);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return 1;
    g_srv = srv;
    int opt = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(TRUSTED_PORT);
    if (bind(srv, (struct sockaddr*)&addr, sizeof(addr)) != 0) return 1;
    listen(srv, 8);

    for (;;) {
        int conn = accept(srv, NULL, NULL);
        if (conn < 0) continue;
        handle_conn(conn);
    }
    return 0;
}
