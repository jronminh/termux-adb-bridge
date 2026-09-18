#!/data/data/com.termux/files/usr/bin/bash
# SPDX-License-Identifier: GPL-3.0-only
# bootstrap.sh — self-deploy through the daemon that is ALREADY running,
# with no Wireless Debugging and no adbwire. Use this when the toggle is
# off/unreachable but a live daemon still answers: it pipes the freshly
# built daemon over the running daemon's authenticated channel (payload
# streaming), sweeps the old process, swaps the new binary into place, and
# relaunches it.
#
# Why it exists: maintain/deploy.sh needs adbwire (Wireless Debugging on).
# This path needs neither — the old daemon is the transport.
#
# The trick that makes it safe: the sweep runs as a child of a worker that
# is itself a fork of the old daemon, so a naive argv[0] match would kill
# the worker relaying our response. The sweep explicitly skips its own PID
# and its parent (the worker) and only then kills matching daemons.
#
# Usage:
#   ./bootstrap.sh              # capture driver, build, self-deploy, verify
#   ./bootstrap.sh --no-build   # skip build/build.sh; deploy build/out as-is
#   ./bootstrap.sh --help
#
# Requires a currently-reachable daemon matching build/out/relaysh-client
# (i.e. the last build/deploy). If it can't reach one, use maintain/deploy.sh.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$HERE")"
OUT_DIR="$REPO_ROOT/build/out"
DAEMON="$OUT_DIR/relaysh-daemon"
CLIENT="$OUT_DIR/relaysh-client"
DSH_SRC="$REPO_ROOT/bin/dsh"
DSH_DEST="${PREFIX:-/data/data/com.termux/files/usr}/bin/dsh"
DAEMON_REMOTE="/data/local/tmp/relaysh-daemon"

NO_BUILD=0
for arg in "$@"; do
    case "$arg" in
        --no-build) NO_BUILD=1 ;;
        -h|--help) sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown argument: $arg (see --help)" >&2; exit 1 ;;
    esac
done

log() { printf '[bootstrap] %s\n' "$1" >&2; }
die() { log "$1"; exit 1; }

[ -x "$CLIENT" ] || die "no client at $CLIENT - run build/build.sh first"

TMP="${TMPDIR:-/tmp}/relaysh-bootstrap.$$"
mkdir -p "$TMP" || die "could not create $TMP"
trap 'rm -rf "$TMP"' EXIT

# The driver is a copy of the client that matches the CURRENTLY running
# daemon — captured before any rebuild, since a rebuild bakes in a new
# secret/port the old daemon can't speak.
DRIVER="$TMP/driver"
cp "$CLIENT" "$DRIVER" && chmod 700 "$DRIVER" || die "could not stage driver client"

driver_alive() { timeout 10 "$DRIVER" id >/dev/null 2>&1; }
driver_alive || die "running daemon not reachable with the current client - use maintain/deploy.sh (adbwire) instead"

# Install the local dsh command first (independent of the device step).
if [ -f "$DSH_SRC" ]; then
    install -m 755 "$DSH_SRC" "$DSH_DEST" 2>/dev/null \
        && log "installed dsh -> $DSH_DEST" \
        || log "could not install dsh to $DSH_DEST (skipping)"
fi

if [ "$NO_BUILD" -eq 1 ]; then
    log "--no-build: using existing $OUT_DIR"
else
    log "building (build/build.sh)..."
    bash "$REPO_ROOT/build/build.sh" || die "build failed"
fi
[ -x "$DAEMON" ] || die "no daemon at $DAEMON after build"

log "pushing new daemon through the running daemon..."
timeout 90 "$DRIVER" -p "$DAEMON" \
    "cat > $DAEMON_REMOTE.new && chmod 700 $DAEMON_REMOTE.new" \
    || die "push failed (old daemon died mid-push?)"

# Sweep + swap + relaunch. Generated with the real paths substituted; the
# $SELF/$PARENT guards keep this command's own worker alive so the response
# can still be relayed back.
SWEEP="$TMP/sweep.sh"
cat > "$SWEEP" <<EOF
SELF=\$\$; PARENT=\$PPID
for p in /proc/[0-9]*; do
  pid=\${p#/proc/}
  [ "\$pid" = "\$SELF" ] && continue
  [ "\$pid" = "\$PARENT" ] && continue
  a=\$(tr "\0" "\n" < "\$p/cmdline" 2>/dev/null | head -1)
  case "\$a" in
    $DAEMON_REMOTE|$DAEMON_REMOTE.new) kill -9 "\$pid" 2>/dev/null ;;
  esac
done
sleep 1
mv $DAEMON_REMOTE.new $DAEMON_REMOTE
$DAEMON_REMOTE
echo swept
EOF

log "sweeping old daemon, swapping in new, relaunching..."
timeout 40 "$DRIVER" -f "$SWEEP" >/dev/null 2>&1 || true
sleep 1

if timeout 15 "$CLIENT" id 2>/dev/null | grep -q '^uid='; then
    log "bootstrap complete: $(timeout 15 "$CLIENT" id 2>/dev/null)"
else
    die "new daemon did not come up - recover with maintain/deploy.sh (adbwire), or check: $CLIENT 'ps -A | grep relaysh-daemon'"
fi
