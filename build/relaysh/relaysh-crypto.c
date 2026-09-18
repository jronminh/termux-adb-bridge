// SPDX-License-Identifier: GPL-3.0-only
// relaysh-crypto implementation. See relaysh-crypto.h for the construction
// and the KAT gating rationale.
#include "relaysh-crypto.h"
#include "sha256.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// ------------------------------------------------------------------ ChaCha20
static uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void chacha20_quarter(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static uint32_t le32(const unsigned char* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void chacha20_block(const uint32_t st[16], unsigned char out[64]) {
    uint32_t x[16];
    memcpy(x, st, sizeof(x));
    for (int i = 0; i < 10; i++) {
        chacha20_quarter(&x[0], &x[4], &x[8],  &x[12]);
        chacha20_quarter(&x[1], &x[5], &x[9],  &x[13]);
        chacha20_quarter(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter(&x[3], &x[7], &x[11], &x[15]);
        chacha20_quarter(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter(&x[2], &x[7], &x[8],  &x[13]);
        chacha20_quarter(&x[3], &x[4], &x[9],  &x[14]);
    }
    for (int i = 0; i < 16; i++) {
        uint32_t v = x[i] + st[i];
        out[i*4 + 0] = v & 0xFF;
        out[i*4 + 1] = (v >> 8) & 0xFF;
        out[i*4 + 2] = (v >> 16) & 0xFF;
        out[i*4 + 3] = (v >> 24) & 0xFF;
    }
}

void relaysh_chacha20_xor(const unsigned char key[RELAYSH_KEY_LEN],
                          const unsigned char nonce[RELAYSH_NONCE_LEN],
                          uint32_t counter,
                          const unsigned char* in, unsigned char* out, size_t len) {
    uint32_t st[16];
    st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) st[4 + i] = le32(key + i*4);
    st[12] = counter;
    st[13] = le32(nonce + 0);
    st[14] = le32(nonce + 4);
    st[15] = le32(nonce + 8);

    unsigned char ks[64];
    size_t off = 0;
    while (off < len) {
        chacha20_block(st, ks);
        st[12]++;
        size_t n = len - off;
        if (n > 64) n = 64;
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
        off += n;
    }
}

// ---------------------------------------------------------------------- HMAC
void relaysh_hmac_sha256(const unsigned char* key, size_t key_len,
                         const unsigned char* data, size_t len,
                         unsigned char out[32]) {
    unsigned char k[64];
    memset(k, 0, sizeof(k));
    if (key_len > 64) {
        sha256(key, key_len, k); // hashed to 32, rest stays zero
    } else {
        memcpy(k, key, key_len);
    }

    unsigned char ipad[64], opad[64];
    for (int i = 0; i < 64; i++) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }

    unsigned char* inner_buf = malloc(64 + len);
    if (!inner_buf) { memset(out, 0, 32); return; }
    memcpy(inner_buf, ipad, 64);
    if (len) memcpy(inner_buf + 64, data, len);
    unsigned char inner[32];
    sha256(inner_buf, 64 + len, inner);
    free(inner_buf);

    unsigned char outer_buf[64 + 32];
    memcpy(outer_buf, opad, 64);
    memcpy(outer_buf + 64, inner, 32);
    sha256(outer_buf, sizeof(outer_buf), out);

    memset(k, 0, sizeof(k));
    memset(ipad, 0, sizeof(ipad));
    memset(opad, 0, sizeof(opad));
    memset(inner, 0, sizeof(inner));
}

// ---------------------------------------------------------------------- AEAD
static void aead_tag(const unsigned char mac_key[RELAYSH_KEY_LEN],
                     const unsigned char nonce[RELAYSH_NONCE_LEN],
                     unsigned char type,
                     const unsigned char* ciphertext, size_t len,
                     unsigned char tag[32]) {
    size_t mlen = RELAYSH_NONCE_LEN + 1 + 4 + len;
    unsigned char* m = malloc(mlen);
    if (!m) { memset(tag, 0, 32); return; }
    memcpy(m, nonce, RELAYSH_NONCE_LEN);
    m[RELAYSH_NONCE_LEN] = type;
    m[RELAYSH_NONCE_LEN + 1] = (unsigned char)(len & 0xFF);
    m[RELAYSH_NONCE_LEN + 2] = (unsigned char)((len >> 8) & 0xFF);
    m[RELAYSH_NONCE_LEN + 3] = (unsigned char)((len >> 16) & 0xFF);
    m[RELAYSH_NONCE_LEN + 4] = (unsigned char)((len >> 24) & 0xFF);
    if (len) memcpy(m + RELAYSH_NONCE_LEN + 5, ciphertext, len);
    relaysh_hmac_sha256(mac_key, RELAYSH_KEY_LEN, m, mlen, tag);
    free(m);
}

void relaysh_aead_encrypt(const unsigned char enc_key[RELAYSH_KEY_LEN],
                          const unsigned char mac_key[RELAYSH_KEY_LEN],
                          const unsigned char nonce[RELAYSH_NONCE_LEN],
                          unsigned char type,
                          const unsigned char* in, size_t len, unsigned char* out) {
    relaysh_chacha20_xor(enc_key, nonce, 0, in, out, len);
    unsigned char tag[32];
    aead_tag(mac_key, nonce, type, out, len, tag);
    memcpy(out + len, tag, RELAYSH_TAG_LEN);
    memset(tag, 0, sizeof(tag));
}

int relaysh_aead_decrypt(const unsigned char enc_key[RELAYSH_KEY_LEN],
                         const unsigned char mac_key[RELAYSH_KEY_LEN],
                         const unsigned char nonce[RELAYSH_NONCE_LEN],
                         unsigned char type,
                         const unsigned char* in, size_t len, unsigned char* out) {
    unsigned char tag[32];
    aead_tag(mac_key, nonce, type, in, len, tag);
    if (relaysh_constant_time_eq(tag, in + len, RELAYSH_TAG_LEN) != 0) {
        memset(tag, 0, sizeof(tag));
        return -1;
    }
    relaysh_chacha20_xor(enc_key, nonce, 0, in, out, len);
    memset(tag, 0, sizeof(tag));
    return 0;
}

// ------------------------------------------------------------------- helpers
int relaysh_constant_time_eq(const unsigned char* a, const unsigned char* b, size_t n) {
    unsigned char d = 0;
    for (size_t i = 0; i < n; i++) d |= (unsigned char)(a[i] ^ b[i]);
    return d ? -1 : 0;
}

int relaysh_random(unsigned char* out, size_t len) {
    FILE* f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(out, 1, len, f);
    fclose(f);
    return r == len ? 0 : -1;
}

// ------------------------------------------------------------------ selftest
static int hex2bin(const char* hex, unsigned char* out, size_t out_len) {
    if (strlen(hex) != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; i++) {
        unsigned int b;
        if (sscanf(hex + i*2, "%2x", &b) != 1) return -1;
        out[i] = (unsigned char)b;
    }
    return 0;
}

int relaysh_crypto_selftest(void) {
    // RFC 8439 §A.1: ChaCha20 keystream block, counter=1.
    {
        const char* key_hex   = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        const char* nonce_hex = "000000090000004a00000000";
        const char* ks_hex =
            "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e";
        unsigned char key[32], nonce[12], expect[64], got[64], zero[64];
        memset(zero, 0, sizeof(zero));
        if (hex2bin(key_hex, key, 32) || hex2bin(nonce_hex, nonce, 12) || hex2bin(ks_hex, expect, 64))
            return -1;
        relaysh_chacha20_xor(key, nonce, 1, zero, got, 64);
        if (memcmp(got, expect, 64) != 0) return -1;
    }

    // RFC 4231 §4.2 Test Case 1: HMAC-SHA256.
    {
        unsigned char key[20];
        memset(key, 0x0b, sizeof(key));
        const unsigned char data[] = "Hi There";
        const char* expect_hex = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
        unsigned char expect[32], got[32];
        if (hex2bin(expect_hex, expect, 32)) return -1;
        relaysh_hmac_sha256(key, sizeof(key), data, sizeof(data) - 1, got);
        if (memcmp(got, expect, 32) != 0) return -1;
    }

    // AEAD round-trip + tamper rejection.
    {
        unsigned char enc[32], mac[32], nonce[12];
        memset(enc, 0x11, 32); memset(mac, 0x22, 32); memset(nonce, 0x33, 12);
        const unsigned char pt[] = "the quick brown fox";
        size_t n = sizeof(pt) - 1;
        unsigned char ct[64 + RELAYSH_TAG_LEN], back[64];
        relaysh_aead_encrypt(enc, mac, nonce, 0x01, pt, n, ct);
        if (relaysh_aead_decrypt(enc, mac, nonce, 0x01, ct, n, back) != 0) return -1;
        if (memcmp(back, pt, n) != 0) return -1;
        ct[0] ^= 0x01; // flip a ciphertext bit -> must fail
        if (relaysh_aead_decrypt(enc, mac, nonce, 0x01, ct, n, back) == 0) return -1;
        ct[0] ^= 0x01;
        if (relaysh_aead_decrypt(enc, mac, nonce, 0x02, ct, n, back) == 0) return -1; // wrong type
    }
    return 0;
}
