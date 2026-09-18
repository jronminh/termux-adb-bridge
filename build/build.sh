#!/data/data/com.termux/files/usr/bin/bash
# build.sh — build stage: compile every artifact this project ships, from the
# sources beside it, into build/out/.
#
#   out/relaysh-daemon      device binary; uid + port + secret baked in
#   out/relaysh-client      Termux-side client; same port + secret baked in
#   out/adbwire             Wireless-Debugging ADB client (pair/connect/shell)
#   out/adbwifi-helper.apk  Wireless-Debugging toggle helper
#
# One random secret and port are generated per run and compiled into BOTH the
# daemon and the client, so no secret is ever written to a file: it exists only
# inside those two binaries, and the scratch sources that carry it during the
# build are wiped before this script exits. Nothing here touches the device -
# deploying the artifacts is maintain/deploy.sh's job.
#
# Usage:
#   ./build.sh
#   ./build.sh --help
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$HERE/out"
SCRATCH="$OUT_DIR/.scratch"
RELAYSH_SRC="$HERE/relaysh"
ADBWIRE_DIR="$HERE/adbwire"
HELPER_DIR="$HERE/adbwifi-helper"

for arg in "$@"; do
    case "$arg" in
        -h|--help)
            awk 'NR>1 && /^set -euo pipefail/{exit} NR>1{sub(/^# ?/,""); print}' "${BASH_SOURCE[0]}"
            exit 0
            ;;
        *) echo "build.sh: unknown argument: $arg (see --help)" >&2; exit 1 ;;
    esac
done

if [ -z "${PREFIX:-}" ] || [ ! -x "$PREFIX/bin/pkg" ]; then
    echo "build.sh: not running inside Termux (\$PREFIX unset or 'pkg' missing)" >&2
    exit 1
fi

# The scratch copies hold the live secret; never leave them behind, on any
# exit path.
cleanup() { rm -rf "$SCRATCH"; }
trap cleanup EXIT

PKGS="clang python openssl"
echo "pkg install -y $PKGS"
pkg install -y $PKGS

rm -rf "$SCRATCH"
mkdir -p "$OUT_DIR" "$SCRATCH"

# One secret + port for this whole build, shared by daemon and client.
SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
PORT=$(( (RANDOM << 15 | RANDOM) % 20000 + 40000 ))
UID_="$(id -u)"

echo "building relaysh-daemon (port $PORT)..."
sed -e "s/__TRUSTED_UID_PLACEHOLDER__/$UID_/" \
    -e "s/__TRUSTED_PORT_PLACEHOLDER__/$PORT/" \
    -e "s/__SECRET_PLACEHOLDER__/$SECRET/" \
    "$RELAYSH_SRC/relaysh-daemon.c" > "$SCRATCH/relaysh-daemon.c"
clang -target aarch64-unknown-linux-android24 -O2 -I"$RELAYSH_SRC" \
    -o "$OUT_DIR/relaysh-daemon" "$SCRATCH/relaysh-daemon.c" \
    "$RELAYSH_SRC/protocol.c" "$RELAYSH_SRC/relaysh-crypto.c" \
    "$RELAYSH_SRC/sha256.c"

echo "building relaysh-client (same port + secret)..."
sed -e "s/__TRUSTED_PORT_PLACEHOLDER__/$PORT/" \
    -e "s/__SECRET_PLACEHOLDER__/$SECRET/" \
    "$RELAYSH_SRC/relaysh-client.c" > "$SCRATCH/relaysh-client.c"
clang -O2 -I"$RELAYSH_SRC" -o "$OUT_DIR/relaysh-client" \
    "$SCRATCH/relaysh-client.c" "$RELAYSH_SRC/protocol.c" \
    "$RELAYSH_SRC/relaysh-crypto.c" "$RELAYSH_SRC/sha256.c"

echo "building adbwire..."
( cd "$ADBWIRE_DIR" && OUT_DIR="$OUT_DIR" ./build.sh )

echo "building adbwifi-helper..."
( cd "$HELPER_DIR" && OUT_DIR="$OUT_DIR" ./build.sh )

cleanup

echo
echo "built:"
ls -la "$OUT_DIR"
echo
echo "Next: deploy with maintain/deploy.sh"
