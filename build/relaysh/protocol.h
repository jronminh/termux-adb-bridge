// SPDX-License-Identifier: GPL-3.0-only
// relaysh v3 wire protocol, shared by relaysh-daemon.c and relaysh-client.c.
//
// Shape (all over the same TCP-loopback connection):
//
//   client -> HELLO   : "RSH3" | version(1) | client_nonce(32) | ts_ns(8)
//   daemon -> PROOF   : "RSH3" | daemon_nonce(32) | proof(32)
//                       proof = HMAC(secret, "relaysh-v3-proof" || cnonce || dnonce)
//                       -> the client verifies this, authenticating the SERVER
//   then two independent AEAD streams (one per direction), each message:
//     type(1) | len_be32(4) | ciphertext(len) | tag(16)
//   request  plaintext = command [+ "\n__RELAYSH_PAYLOAD__\n" + payload]
//   response: type DATA=stdout, STDERR=stderr, END=exit code (4 bytes BE)
//
// Keys are derived from the pre-shared 32-byte secret + both nonces; each
// direction gets its own enc/mac keys, and each message uses a fresh
// implicit counter nonce. Fresh nonces per connection => no nonce reuse.
#ifndef RELAYSH_PROTOCOL_H
#define RELAYSH_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#define PROTO_MAGIC      "RSH3"
#define PROTO_MAGIC_LEN  4
#define PROTO_VERSION    3

#define PROTO_NONCE_LEN  32
#define PROTO_HELLO_LEN  (PROTO_MAGIC_LEN + 1 + PROTO_NONCE_LEN + 8) /* 45 */
#define PROTO_PROOF_LEN  (PROTO_MAGIC_LEN + PROTO_NONCE_LEN + 32)    /* 68 */

/* AEAD message types. Request uses DATA/END; response uses DATA(stdout),
 * STDERR, END(exit code). */
#define PROTO_T_DATA    0x00
#define PROTO_T_STDERR  0x01
#define PROTO_T_END     0x02

/* Bounds. */
#define PROTO_MSG_MAX   65536          /* per AEAD message plaintext cap */
#define PROTO_REQ_MAX   (16 * 1024 * 1024) /* whole request (cmd+payload) cap */

typedef struct {
    unsigned char c2d_enc[32], c2d_mac[32];
    unsigned char d2c_enc[32], d2c_mac[32];
} proto_keys;

/* Derives the per-connection keys and the server-auth proof from the secret
 * and both nonces. */
void proto_derive(const unsigned char secret[32],
                  const unsigned char cnonce[PROTO_NONCE_LEN],
                  const unsigned char dnonce[PROTO_NONCE_LEN],
                  proto_keys* keys, unsigned char proof[32]);

/* dir: 0 = client->daemon, 1 = daemon->client. Counter is per direction. */
int proto_send_msg(int fd, const proto_keys* keys, int dir, uint64_t* ctr,
                   unsigned char type, const unsigned char* data, size_t len);
int proto_recv_msg(int fd, const proto_keys* keys, int dir, uint64_t* ctr,
                   unsigned char* type_out, unsigned char* buf, size_t cap,
                   size_t* len_out);

/* Exact read/write; returns 0 on success, -1 on EOF/error. */
int proto_write_full(int fd, const unsigned char* buf, size_t len);
int proto_read_full(int fd, unsigned char* buf, size_t len);

/* Decodes a 64-char lowercase/uppercase hex string into 32 bytes.
 * Returns 0 on success. */
int proto_hex_decode32(const char* hex, unsigned char out[32]);

#endif
