/*
 * spake2.c — SPAKE2 over Ed25519, byte-compatible with BoringSSL's
 * crypto/curve25519/spake25519.cc, which is what Android's Wireless
 * Debugging pairing speaks. The algorithm (roles, transcript layout, the
 * "password scalar" cofactor hack, M/N points) is transcribed from that
 * file; the Ed25519 arithmetic comes from the vendored ref10 in ed25519/.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#include "spake2.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

#include "ed25519/fe.h"
#include "ed25519/ge.h"
#include "ed25519/sc.h"

/* The two SPAKE2 mask points, from the comment atop BoringSSL's
 * spake25519.cc (compressed Ed25519 encoding). */
static const uint8_t kSpakeM[32] = {
    0x5a, 0xda, 0x7e, 0x4b, 0xf6, 0xdd, 0xd9, 0xad, 0xb6, 0x62, 0x6d, 0x32,
    0x13, 0x1c, 0x6b, 0x5c, 0x51, 0xa1, 0xe3, 0x47, 0xa3, 0x47, 0x8f, 0x53,
    0xcf, 0xcf, 0x44, 0x1b, 0x88, 0xee, 0xd1, 0x2e,
};
static const uint8_t kSpakeN[32] = {
    0x10, 0xe3, 0xdf, 0x0a, 0xe3, 0x7d, 0x8e, 0x7a, 0x99, 0xb5, 0xfe, 0x74,
    0xb4, 0x46, 0x72, 0x10, 0x3d, 0xbd, 0xdc, 0xbd, 0x06, 0xaf, 0x68, 0x0d,
    0x71, 0x32, 0x9a, 0x11, 0x69, 0x3b, 0xc7, 0x78,
};

/* Ed25519 base point, compressed. */
static const uint8_t kBasePoint[32] = {
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
};

/* Order of the prime-order subgroup of Ed25519, as 4 little-endian 64-bit
 * words. */
static const uint64_t kOrder[4] = {
    0x5812631a5cf5d3edULL, 0x14def9dea2f79cd6ULL,
    0x0000000000000000ULL, 0x1000000000000000ULL,
};

struct spake2_ctx {
    int alice;
    int state; /* 0 = init, 1 = msg generated, 2 = key generated */
    uint8_t my_name[64];
    size_t my_name_len;
    uint8_t their_name[64];
    size_t their_name_len;
    uint8_t my_msg[SPAKE2_MAX_MSG_SIZE];
    uint8_t private_key[32];
    uint8_t password_scalar[32];
    uint8_t password_hash[64];
};

static void scalar_add(uint64_t dest[4], const uint64_t src[4]) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < 4; i++) {
        unsigned __int128 v = (unsigned __int128)dest[i] + src[i] + carry;
        dest[i] = (uint64_t)v;
        carry = v >> 64;
    }
}

static void scalar_double(uint64_t s[4]) {
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t next = s[i] >> 63;
        s[i] = (s[i] << 1) | carry;
        carry = next;
    }
}

/* Multiply by 8, little-endian. */
static void left_shift_3(uint8_t n[32]) {
    uint8_t carry = 0;
    for (int i = 0; i < 32; i++) {
        uint8_t next = (uint8_t)(n[i] >> 5);
        n[i] = (uint8_t)((n[i] << 3) | carry);
        carry = next;
    }
}

/* ref10's decode returns the NEGATED point; BoringSSL's
 * x25519_ge_frombytes_vartime returns the plain one, so undo the negation. */
static int ge_frombytes(ge_p3 *h, const uint8_t *s) {
    if (ge_frombytes_negate_vartime(h, s) != 0) return -1;
    fe_neg(h->X, h->X);
    fe_neg(h->T, h->T);
    return 0;
}

/* Generic scalar multiplication (variable-time double-and-add). BoringSSL
 * uses a constant-time fixed-window routine; for a one-shot pairing on the
 * user's own device the timing channel isn't meaningful, and this matches
 * its output exactly. */
static void ge_scalarmult(ge_p3 *r, const uint8_t scalar[32], const ge_p3 *P) {
    ge_p3 acc, base = *P;
    ge_cached base_cached;
    ge_p1p1 t;
    ge_p3_to_cached(&base_cached, &base);
    ge_p3_0(&acc);
    for (int i = 255; i >= 0; i--) {
        ge_p3_dbl(&t, &acc);
        ge_p1p1_to_p3(&acc, &t);
        if ((scalar[i >> 3] >> (i & 7)) & 1) {
            ge_add(&t, &acc, &base_cached);
            ge_p1p1_to_p3(&acc, &t);
        }
    }
    *r = acc;
}

static void sha512(const uint8_t *data, size_t len, uint8_t out[64]) {
    unsigned int outlen = 0;
    EVP_Digest(data, len, out, &outlen, EVP_sha512(), NULL);
}

static void update_with_length_prefix(EVP_MD_CTX *sha, const uint8_t *data,
                                      size_t len) {
    uint8_t len_le[8];
    size_t l = len;
    for (int i = 0; i < 8; i++) {
        len_le[i] = (uint8_t)(l & 0xff);
        l >>= 8;
    }
    EVP_DigestUpdate(sha, len_le, sizeof(len_le));
    EVP_DigestUpdate(sha, data, len);
}

spake2_ctx *spake2_new(int alice, const uint8_t *my_name, size_t my_name_len,
                       const uint8_t *their_name, size_t their_name_len) {
    spake2_ctx *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return NULL;
    ctx->alice = alice;
    if (my_name_len > sizeof(ctx->my_name) ||
        their_name_len > sizeof(ctx->their_name)) {
        free(ctx);
        return NULL;
    }
    memcpy(ctx->my_name, my_name, my_name_len);
    ctx->my_name_len = my_name_len;
    memcpy(ctx->their_name, their_name, their_name_len);
    ctx->their_name_len = their_name_len;
    return ctx;
}

void spake2_free(spake2_ctx *ctx) {
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
        free(ctx);
    }
}

int spake2_generate_msg(spake2_ctx *ctx, uint8_t *out, size_t *out_len,
                        size_t max_out_len, const uint8_t *password,
                        size_t password_len) {
    if (ctx->state != 0) return 0;
    if (max_out_len < SPAKE2_MAX_MSG_SIZE) return 0;

    uint8_t private_tmp[64];
    if (RAND_bytes(private_tmp, sizeof(private_tmp)) != 1) return 0;
    sc_reduce(private_tmp);
    left_shift_3(private_tmp);
    memcpy(ctx->private_key, private_tmp, sizeof(ctx->private_key));

    /* NB: ref10's ge_scalarmult_base only handles clamped Ed25519 scalars;
     * SPAKE2's scalars are arbitrary, so use the generic multiply with the
     * decoded base point instead. */
    ge_p3 P, base_point;
    if (ge_frombytes(&base_point, kBasePoint) != 0) return 0;
    ge_scalarmult(&P, ctx->private_key, &base_point);

    uint8_t password_tmp[64];
    sha512(password, password_len, password_tmp);
    memcpy(ctx->password_hash, password_tmp, sizeof(ctx->password_hash));
    sc_reduce(password_tmp);

    /* BoringSSL's "password scalar hack": the reduced scalar is not a
     * multiple of 8, so add kOrder*1/2/4 to clear the low three bits and
     * keep the mask in the prime-order subgroup. The conditions are checked
     * against the progressively updated scalar, exactly as upstream. */
    uint64_t ps[4];
    memcpy(ps, password_tmp, sizeof(ps));
    uint64_t order2[4], order4[4];
    memcpy(order2, kOrder, sizeof(order2));
    scalar_double(order2);
    memcpy(order4, order2, sizeof(order4));
    scalar_double(order4);
    if (ps[0] & 1) scalar_add(ps, kOrder);
    if (ps[0] & 2) scalar_add(ps, order2);
    if (ps[0] & 4) scalar_add(ps, order4);
    memcpy(ctx->password_scalar, ps, sizeof(ctx->password_scalar));

    ge_p3 mask, mask_point;
    const uint8_t *mask_enc = ctx->alice ? kSpakeM : kSpakeN;
    if (ge_frombytes(&mask_point, mask_enc) != 0) return 0;
    ge_scalarmult(&mask, ctx->password_scalar, &mask_point);

    ge_cached mask_cached;
    ge_p3_to_cached(&mask_cached, &mask);
    ge_p1p1 Pstar;
    ge_add(&Pstar, &P, &mask_cached);
    ge_p2 Pstar_proj;
    ge_p1p1_to_p2(&Pstar_proj, &Pstar);
    ge_tobytes(ctx->my_msg, &Pstar_proj);

    memcpy(out, ctx->my_msg, sizeof(ctx->my_msg));
    *out_len = sizeof(ctx->my_msg);
    ctx->state = 1;
    return 1;
}

int spake2_process_msg(spake2_ctx *ctx, uint8_t *out_key, size_t *out_key_len,
                       size_t max_out_key_len, const uint8_t *their_msg,
                       size_t their_msg_len) {
    if (ctx->state != 1 || their_msg_len != 32) return 0;

    ge_p3 Qstar;
    if (ge_frombytes(&Qstar, their_msg) != 0) return 0;

    ge_p3 peers_mask, mask_point;
    const uint8_t *mask_enc = ctx->alice ? kSpakeN : kSpakeM;
    if (ge_frombytes(&mask_point, mask_enc) != 0) return 0;
    ge_scalarmult(&peers_mask, ctx->password_scalar, &mask_point);

    ge_cached peers_mask_cached;
    ge_p3_to_cached(&peers_mask_cached, &peers_mask);
    ge_p1p1 Q_compl;
    ge_p3 Q_ext;
    ge_sub(&Q_compl, &Qstar, &peers_mask_cached);
    ge_p1p1_to_p3(&Q_ext, &Q_compl);

    ge_p3 dh_shared;
    ge_scalarmult(&dh_shared, ctx->private_key, &Q_ext);
    uint8_t dh_shared_encoded[32];
    ge_p3_tobytes(dh_shared_encoded, &dh_shared);

    EVP_MD_CTX *sha = EVP_MD_CTX_new();
    if (!sha) return 0;
    EVP_DigestInit_ex(sha, EVP_sha512(), NULL);
    if (ctx->alice) {
        update_with_length_prefix(sha, ctx->my_name, ctx->my_name_len);
        update_with_length_prefix(sha, ctx->their_name, ctx->their_name_len);
        update_with_length_prefix(sha, ctx->my_msg, sizeof(ctx->my_msg));
        update_with_length_prefix(sha, their_msg, 32);
    } else {
        update_with_length_prefix(sha, ctx->their_name, ctx->their_name_len);
        update_with_length_prefix(sha, ctx->my_name, ctx->my_name_len);
        update_with_length_prefix(sha, their_msg, 32);
        update_with_length_prefix(sha, ctx->my_msg, sizeof(ctx->my_msg));
    }
    update_with_length_prefix(sha, dh_shared_encoded, sizeof(dh_shared_encoded));
    update_with_length_prefix(sha, ctx->password_hash,
                              sizeof(ctx->password_hash));

    uint8_t key[64];
    unsigned int keylen = 0;
    EVP_DigestFinal_ex(sha, key, &keylen);
    EVP_MD_CTX_free(sha);

    size_t to_copy = max_out_key_len > sizeof(key) ? sizeof(key) : max_out_key_len;
    memcpy(out_key, key, to_copy);
    *out_key_len = to_copy;
    ctx->state = 2;
    return 1;
}
