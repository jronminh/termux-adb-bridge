#!/data/data/com.termux/files/usr/bin/bash
# build.sh — compile adbwire (the minimal Wireless-Debugging ADB client).
#
# adbwire links against OpenSSL for the TLS layer; everything else is plain C.
# Run from anywhere; paths resolve relative to this file.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${OUT_DIR:-$(dirname "$HERE")/out}"
PKGS="clang openssl"

mkdir -p "$OUT_DIR"
pkg install -y $PKGS >/dev/null 2>&1 || true

clang -O2 -Wall -Wextra -o "$OUT_DIR/adbwire" \
    "$HERE/adbwire.c" "$HERE/spake2.c" \
    "$HERE/ed25519/fe.c" "$HERE/ed25519/ge.c" "$HERE/ed25519/sc.c" \
    -lssl -lcrypto
echo "built $OUT_DIR/adbwire"
