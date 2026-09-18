// SPDX-License-Identifier: GPL-3.0-only
// relaysh-crypto — the v3 symmetric crypto for relaysh, self-contained
// (depends only on sha256.c). Deliberately small and auditable rather than
// a vendored library:
//
//   - ChaCha20 (RFC 8439) as the stream cipher, keyed per direction.
//   - HMAC-SHA256 (RFC 2104) as the authenticator.
//   - AEAD = ENCRYPT-THEN-MAC: ciphertext = ChaCha20(k_enc, nonce, ...);
//     tag = HMAC-SHA256(k_mac, nonce || type || len || ciphertext)[0..15].
//     Encrypt-then-MAC is the standard safe composition, and the tag covers
//     the nonce, the message type and the length, so reordering/truncation/
//     type-confusion all fail verification.
//
// Two independent keys (k_enc, k_mac) are derived per direction, so the
// stream cipher and the MAC never share a key. Nonces are per-message and
// unique by construction (the session keys are fresh per connection), so a
// plain 12-byte message counter is safe.
//
// Gated by relaysh_crypto_selftest() at daemon boot and client startup,
// against the RFC 8439 §A.1 ChaCha20 vector and RFC 4231 §4.2 HMAC vector —
// a typo in the algebra fails the run, never a live handshake.
#ifndef RELAYSH_CRYPTO_H
#define RELAYSH_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define RELAYSH_KEY_LEN   32
#define RELAYSH_TAG_LEN   16
#define RELAYSH_NONCE_LEN 12
#define RELAYSH_CHUNK_MAX 65536

// HMAC-SHA256. `out` is 32 bytes. (General key length; callers use 32.)
void relaysh_hmac_sha256(const unsigned char* key, size_t key_len,
                         const unsigned char* data, size_t len,
                         unsigned char out[32]);

// ChaCha20 keystream XOR. `counter` is the initial block counter.
void relaysh_chacha20_xor(const unsigned char key[RELAYSH_KEY_LEN],
                          const unsigned char nonce[RELAYSH_NONCE_LEN],
                          uint32_t counter,
                          const unsigned char* in, unsigned char* out, size_t len);

// AEAD encrypt: writes `len` ciphertext bytes then a 16-byte tag to `out`
// (which must hold len + RELAYSH_TAG_LEN). `in`/`out` may alias.
void relaysh_aead_encrypt(const unsigned char enc_key[RELAYSH_KEY_LEN],
                          const unsigned char mac_key[RELAYSH_KEY_LEN],
                          const unsigned char nonce[RELAYSH_NONCE_LEN],
                          unsigned char type,
                          const unsigned char* in, size_t len, unsigned char* out);

// AEAD decrypt: `in` holds `len` ciphertext bytes + 16-byte tag; writes `len`
// plaintext bytes to `out`. Returns 0 on success, -1 on tag mismatch.
int relaysh_aead_decrypt(const unsigned char enc_key[RELAYSH_KEY_LEN],
                         const unsigned char mac_key[RELAYSH_KEY_LEN],
                         const unsigned char nonce[RELAYSH_NONCE_LEN],
                         unsigned char type,
                         const unsigned char* in, size_t len, unsigned char* out);

// Constant-time equality: 0 if equal, -1 otherwise.
int relaysh_constant_time_eq(const unsigned char* a, const unsigned char* b, size_t n);

// Fills `out` with `len` cryptographically random bytes. Returns 0 on success.
int relaysh_random(unsigned char* out, size_t len);

// Runs the known-answer tests. Returns 0 if all pass, -1 otherwise.
int relaysh_crypto_selftest(void);

#endif
