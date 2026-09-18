#!/data/data/com.termux/files/usr/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# deploy.sh — maintain stage: put the built daemon on the device and keep it
# alive. It compiles nothing; artifacts come from build/out/ (run
# build/build.sh first). Deployment goes over Wireless Debugging via adbwire;
# if the toggle is off it asks adbwifi-helper to flip it back on first (the
# only step Termux can't do itself).
#
# The daemon's port + secret are baked in, so there is no rotation and no
# config file: (re)deploy = stop any running daemon, push the new binary,
# launch it, verify with the matching client.
#
# It also installs the `dsh` wrapper (bin/dsh) into $PREFIX/bin, so there is
# a stable user-facing command over the client.
#
# Usage:
#   ./deploy.sh            # push + (re)launch the daemon, then verify
#
# This is a deliberate, human-run action: it (re)starts a shell-UID daemon,
# so it is not meant to be pointed at a scheduler.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$HERE")"
OUT_DIR="$REPO_ROOT/build/out"
DAEMON="$OUT_DIR/relaysh-daemon"
CLIENT="$OUT_DIR/relaysh-client"
ADBWIRE="$OUT_DIR/adbwire"
DAEMON_REMOTE="/data/local/tmp/relaysh-daemon"
DAEMON_REMOTE_NEW="$DAEMON_REMOTE.new"
DSH_SRC="$REPO_ROOT/bin/dsh"
DSH_DEST="${PREFIX:-/data/data/com.termux/files/usr}/bin/dsh"
# Persistent copy of the client (and daemon) that match the running daemon.
# build/build.sh overwrites build/out with a new secret, which would leave a
# still-running old daemon unreachable; this store is the recovery key.
STORE_DIR="${RELAYSH_STORE_DIR:-$HOME/.local/share/relaysh}"
STORE_CLIENT="$STORE_DIR/client"
STORE_DAEMON="$STORE_DIR/daemon"

log() { printf '[maintain] %s\n' "$1" >&2; }
die() { log "$1"; exit 1; }

for arg in "$@"; do
    case "$arg" in
        -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg (see --help)" >&2; exit 1 ;;
    esac
done

[ -x "$DAEMON" ] || die "no daemon at $DAEMON - run build/build.sh first"
[ -x "$CLIENT" ] || die "no client at $CLIENT - run build/build.sh first"
[ -x "$ADBWIRE" ] || die "no adbwire at $ADBWIRE - run build/build.sh first"

# Install the local `dsh` command first: it's independent of the device
# deploy below, so it's there even if Wireless Debugging can't be reached.
if [ -f "$DSH_SRC" ]; then
    if install -m 755 "$DSH_SRC" "$DSH_DEST" 2>/dev/null; then
        log "installed dsh -> $DSH_DEST"
    else
        log "could not install dsh to $DSH_DEST (skipping)"
    fi
fi

daemon_alive() { "$CLIENT" id 2>/dev/null | grep -q '^uid='; }

# store_pair — persist the just-deployed client+daemon as the recovery pair.
# Rotates one generation (.prev) so a bad build doesn't clobber the good one.
store_pair() {
    mkdir -p "$STORE_DIR" 2>/dev/null || { log "could not create $STORE_DIR (skipping store)"; return 0; }
    chmod 700 "$STORE_DIR" 2>/dev/null
    [ -f "$STORE_CLIENT" ] && cp -f "$STORE_CLIENT" "$STORE_CLIENT.prev" 2>/dev/null
    [ -f "$STORE_DAEMON" ] && cp -f "$STORE_DAEMON" "$STORE_DAEMON.prev" 2>/dev/null
    install -m 700 "$CLIENT" "$STORE_CLIENT" 2>/dev/null
    install -m 700 "$DAEMON" "$STORE_DAEMON" 2>/dev/null
    log "stored paired client+daemon -> $STORE_DIR"
}

adbwire_available() { timeout 10 "$ADBWIRE" -t 3 -d >/dev/null 2>&1; }

if ! adbwire_available; then
    log "Wireless Debugging unreachable - triggering adbwifi-helper"
    timeout 10 am broadcast -a local.adbwifi.helper.ENABLE \
        -n local.adbwifi.helper/.EnableReceiver >/dev/null 2>&1 || true
    sleep 3
fi
adbwire_available \
    || die "Wireless Debugging could not be enabled - pair first (adbwire --pair) or fix by hand"

# Push to a fresh path: the running daemon's own file is busy and can't be
# overwritten in place. Then stop any running main daemon (matched by exact
# argv[0], so unrelated processes are never touched),
# rename the new binary into place, and launch it.
log "pushing daemon..."
timeout 90 "$ADBWIRE" -p "$DAEMON" \
    "cat > $DAEMON_REMOTE_NEW && chmod 700 $DAEMON_REMOTE_NEW" \
    || die "push failed"

log "stopping any running daemon..."
KILL_SCRIPT='
for p in /proc/[0-9]*; do
  a=$(tr "\0" "\n" < "$p/cmdline" 2>/dev/null | head -1)
  case "$a" in
    '"$DAEMON_REMOTE"'|'"$DAEMON_REMOTE"'.new) kill -9 "${p#/proc/}" 2>/dev/null ;;
  esac
done
sleep 1
mv '"$DAEMON_REMOTE_NEW"' '"$DAEMON_REMOTE"'
echo swept
'
timeout 20 "$ADBWIRE" "$KILL_SCRIPT" >/dev/null 2>&1 || true

log "launching daemon..."
timeout 40 "$ADBWIRE" "$DAEMON_REMOTE" >/dev/null 2>&1 || true
sleep 1

daemon_alive || die "daemon did not come up - check with: $ADBWIRE 'ps -A | grep relaysh-daemon'"
log "deploy complete: $("$CLIENT" id)"
store_pair
