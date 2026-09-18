/*
 * spake2.h — SPAKE2 over Ed25519, byte-compatible with BoringSSL's
 * crypto/curve25519/spake25519.cc (which is what Android's Wireless
 * Debugging pairing uses). Only the pieces adbwire needs are exposed.
 *
 * SPDX-License-Identifier: GPL-3.0-only
 */
#ifndef ADBWIRE_SPAKE2_H
#define ADBWIRE_SPAKE2_H

#include <stddef.h>
#include <stdint.h>

#define SPAKE2_MAX_MSG_SIZE 32
#define SPAKE2_MAX_KEY_SIZE 64

typedef struct spake2_ctx spake2_ctx;

/* alice != 0 for the client role. Names are the raw bytes exchanged into the
 * transcript (adb passes C string literals *including* their NUL). */
spake2_ctx *spake2_new(int alice, const uint8_t *my_name, size_t my_name_len,
                       const uint8_t *their_name, size_t their_name_len);
void spake2_free(spake2_ctx *ctx);

int spake2_generate_msg(spake2_ctx *ctx, uint8_t *out, size_t *out_len,
                        size_t max_out_len, const uint8_t *password,
                        size_t password_len);
int spake2_process_msg(spake2_ctx *ctx, uint8_t *out_key, size_t *out_key_len,
                       size_t max_out_key_len, const uint8_t *their_msg,
                       size_t their_msg_len);

#endif
