// SPDX-License-Identifier: GPL-3.0-only
#include "protocol.h"
#include "relaysh-crypto.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

static const char LBL_PROOF[]  = "relaysh-v3-proof";
static const char LBL_MASTER[] = "relaysh-v3-master";
static const char LBL_C2D_ENC[] = "c2d-enc";
static const char LBL_C2D_MAC[] = "c2d-mac";
static const char LBL_D2C_ENC[] = "d2c-enc";
static const char LBL_D2C_MAC[] = "d2c-mac";

void proto_derive(const unsigned char secret[32],
                  const unsigned char cnonce[PROTO_NONCE_LEN],
                  const unsigned char dnonce[PROTO_NONCE_LEN],
                  proto_keys* keys, unsigned char proof[32]) {
    unsigned char tr[PROTO_NONCE_LEN * 2];
    memcpy(tr, cnonce, PROTO_NONCE_LEN);
    memcpy(tr + PROTO_NONCE_LEN, dnonce, PROTO_NONCE_LEN);

    unsigned char buf[64 + sizeof(tr)];
    unsigned char master[32];

    size_t lp = strlen(LBL_PROOF);
    memcpy(buf, LBL_PROOF, lp);
    memcpy(buf + lp, tr, sizeof(tr));
    relaysh_hmac_sha256(secret, 32, buf, lp + sizeof(tr), proof);

    size_t lm = strlen(LBL_MASTER);
    memcpy(buf, LBL_MASTER, lm);
    memcpy(buf + lm, tr, sizeof(tr));
    relaysh_hmac_sha256(secret, 32, buf, lm + sizeof(tr), master);

    relaysh_hmac_sha256(master, 32, (const unsigned char*)LBL_C2D_ENC, strlen(LBL_C2D_ENC), keys->c2d_enc);
    relaysh_hmac_sha256(master, 32, (const unsigned char*)LBL_C2D_MAC, strlen(LBL_C2D_MAC), keys->c2d_mac);
    relaysh_hmac_sha256(master, 32, (const unsigned char*)LBL_D2C_ENC, strlen(LBL_D2C_ENC), keys->d2c_enc);
    relaysh_hmac_sha256(master, 32, (const unsigned char*)LBL_D2C_MAC, strlen(LBL_D2C_MAC), keys->d2c_mac);

    memset(master, 0, sizeof(master));
    memset(buf, 0, sizeof(buf));
}

int proto_write_full(int fd, const unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

int proto_read_full(int fd, unsigned char* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t r = read(fd, buf + off, len - off);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        if (r == 0) return -1;
        off += (size_t)r;
    }
    return 0;
}

static void msg_nonce(unsigned char nonce[RELAYSH_NONCE_LEN], uint64_t ctr) {
    memset(nonce, 0, 4);
    for (int i = 0; i < 8; i++) nonce[4 + i] = (unsigned char)((ctr >> (56 - 8*i)) & 0xFF);
}

static const unsigned char* enc_key(const proto_keys* k, int dir) {
    return dir == 0 ? k->c2d_enc : k->d2c_enc;
}
static const unsigned char* mac_key(const proto_keys* k, int dir) {
    return dir == 0 ? k->c2d_mac : k->d2c_mac;
}

int proto_send_msg(int fd, const proto_keys* keys, int dir, uint64_t* ctr,
                   unsigned char type, const unsigned char* data, size_t len) {
    if (len > PROTO_MSG_MAX) return -1;
    unsigned char nonce[RELAYSH_NONCE_LEN];
    msg_nonce(nonce, *ctr);

    unsigned char* out = malloc(5 + len + RELAYSH_TAG_LEN);
    if (!out) return -1;
    out[0] = type;
    out[1] = (unsigned char)((len >> 24) & 0xFF);
    out[2] = (unsigned char)((len >> 16) & 0xFF);
    out[3] = (unsigned char)((len >>  8) & 0xFF);
    out[4] = (unsigned char)( len        & 0xFF);
    relaysh_aead_encrypt(enc_key(keys, dir), mac_key(keys, dir), nonce, type,
                         data, len, out + 5);
    int rc = proto_write_full(fd, out, 5 + len + RELAYSH_TAG_LEN);
    free(out);
    if (rc == 0) (*ctr)++;
    return rc;
}

int proto_recv_msg(int fd, const proto_keys* keys, int dir, uint64_t* ctr,
                   unsigned char* type_out, unsigned char* buf, size_t cap,
                   size_t* len_out) {
    unsigned char hdr[5];
    if (proto_read_full(fd, hdr, 5) != 0) return -1;
    unsigned char type = hdr[0];
    uint32_t len = ((uint32_t)hdr[1] << 24) | ((uint32_t)hdr[2] << 16) |
                   ((uint32_t)hdr[3] << 8)  | (uint32_t)hdr[4];
    if (len > PROTO_MSG_MAX || len > cap) return -1;
    if (proto_read_full(fd, buf, (size_t)len + RELAYSH_TAG_LEN) != 0) return -1;

    unsigned char nonce[RELAYSH_NONCE_LEN];
    msg_nonce(nonce, *ctr);
    if (relaysh_aead_decrypt(enc_key(keys, dir), mac_key(keys, dir), nonce, type,
                             buf, len, buf) != 0)
        return -1;
    (*ctr)++;
    *type_out = type;
    *len_out = len;
    return 0;
}

int proto_hex_decode32(const char* hex, unsigned char out[32]) {
    if (!hex || strlen(hex) < 64) return -1;
    for (int i = 0; i < 32; i++) {
        int hi, lo;
        char c = hex[i*2], d = hex[i*2 + 1];
        if (c >= '0' && c <= '9') hi = c - '0';
        else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
        else return -1;
        if (d >= '0' && d <= '9') lo = d - '0';
        else if (d >= 'a' && d <= 'f') lo = d - 'a' + 10;
        else if (d >= 'A' && d <= 'F') lo = d - 'A' + 10;
        else return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 0;
}
