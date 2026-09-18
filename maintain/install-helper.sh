#!/data/data/com.termux/files/usr/bin/bash
# install-helper.sh — one-time: install adbwifi-helper and grant it
# WRITE_SECURE_SETTINGS. Runs over Wireless Debugging via adbwire (shell UID),
# no adb. Needed once per device so the pipeline can re-enable Wireless
# Debugging by itself later.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$(dirname "$HERE")/build/out"
APK="$OUT_DIR/adbwifi-helper.apk"
ADBWIRE="$OUT_DIR/adbwire"
PKG="local.adbwifi.helper"
REMOTE="/data/local/tmp/adbwifi-helper.apk"

log() { printf '[maintain] %s\n' "$1" >&2; }
die() { log "$1"; exit 1; }

[ -f "$APK" ] || die "no APK at $APK - run build/build.sh first"
[ -x "$ADBWIRE" ] || die "no adbwire at $ADBWIRE - run build/build.sh first"

log "pushing APK..."
timeout 60 "$ADBWIRE" -p "$APK" "cat > $REMOTE" || die "push failed"

log "installing..."
timeout 60 "$ADBWIRE" "pm install -r $REMOTE" || die "pm install failed"

log "granting WRITE_SECURE_SETTINGS..."
timeout 20 "$ADBWIRE" "pm grant $PKG android.permission.WRITE_SECURE_SETTINGS" \
    || die "pm grant failed"

log "adbwifi-helper installed and granted"
