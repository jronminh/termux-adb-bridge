// SPDX-License-Identifier: GPL-3.0-only
// Minimal SHA-256 (raw 32-byte digest), used by HMAC-SHA256 in
// relaysh-crypto.c. The daemon and client link this exact file.
#ifndef RELAYSH_SHA256_H
#define RELAYSH_SHA256_H

#include <stddef.h>

// Raw 32-byte digest.
void sha256(const unsigned char* data, size_t len, unsigned char out[32]);

#endif
