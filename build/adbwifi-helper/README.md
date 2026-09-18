# adbwifi-helper

A tiny, **receiver-only** Android app whose only job is to flip Android's
"Wireless Debugging" toggle back on **in software**, so `relaysh-watchdog.sh`
can recover even when the toggle itself has been turned off (not just
the wifi radio, and not just an ordinary adb disconnect — both of those
the daemon/watchdog already handle without this app).

It has **no activity and no launcher entry**, so it never shows up in the
app drawer. It is triggered two ways:

- an explicit broadcast from Termux (the normal path), and
- the system's `BOOT_COMPLETED` broadcast, so Wireless Debugging comes
  back by itself after a reboot.

It is **not** Shizuku and does **not** touch Termux's own APK — a
separate, minimal, purpose-built package (`local.adbwifi.helper`),
because that's the only way found to get a `Context` with a real,
AMS-recognized app identity (see `docs/RESEARCH.md` for the full story
of why that matters; in short: every app-UID route Termux has —
`settings`/`cmd`/`content` CLIs and bare `app_process` — is rejected by
Android, so a real installed app is the only software way to write the
setting without the shell UID).

## Build

```sh
# One android.jar per API level from a community mirror (the device's own
# /system/framework/framework.jar is raw DEX, unusable by javac):
curl -sL -o android.jar \
    https://raw.githubusercontent.com/Reginer/aosp-android-jar/main/android-34/android.jar
./build.sh
```

Produces `adbwifi-helper.apk`, signed with a throwaway debug key
generated on first run (`debug.keystore`, gitignored).

## Install (one-time, needs the shell UID)

Via `adb`:

```sh
adb install -r adbwifi-helper.apk
adb shell pm grant local.adbwifi.helper android.permission.WRITE_SECURE_SETTINGS
```

Or via the relaysh daemon (also shell UID), if you'd rather not use `adb`:

```sh
# from Termux, with the daemon already running:
adbwire -p adbwifi-helper.apk 'cat > /data/local/tmp/adbwifi-helper.apk'
dsh 'pm install -r /data/local/tmp/adbwifi-helper.apk'
dsh 'pm grant local.adbwifi.helper android.permission.WRITE_SECURE_SETTINGS'
```

`WRITE_SECURE_SETTINGS` is `protectionLevel="signature|...|development|..."`
— grantable via `pm grant` specifically because of the `development` flag,
even though it's otherwise a signature-level permission. This grant is
permanent (package-manager state), survives reboots and wifi cycling, and
never needs redoing unless the app is uninstalled.

## Trigger (no adb, ever again)

```sh
am broadcast -a local.adbwifi.helper.ENABLE -n local.adbwifi.helper/.EnableReceiver
```

Use **Termux's own bundled `am`** (`$PREFIX/bin/am`, i.e. just `am` if
it's on `PATH`) — **not** `/system/bin/am`. The system binary hardcodes
a `shell`/`com.android.shell` calling identity internally and always
throws `SecurityException: package com.android.shell does not belong to
uid=<termux's uid>` no matter what it's asked to do. Termux ships its own
reimplementation (`com.termux.termuxam.Am`) that genuinely uses Termux's
real identity instead, which is what lets this work at all.

## Why a `BroadcastReceiver`, not an `Activity`

An `Activity`-based version was tried first and *appeared* to silently
fail — no crash, no log output, no process ever visible in `ps`. It
turned out the broadcast/launch was actually being delivered fine
(confirmed via `adb shell dumpsys activity broadcasts`, showing
`DELIVERED ... reason: remote app`); the real problem was that a
third-party app's `READ_LOGS` grant only exposes *that app's own* log
lines on this device, so Termux could never have seen the Activity's
`Log.i` output regardless of whether it worked. Separately, and still
worth knowing: `Activity`-based launches from a non-foreground caller
like `am` can hit Android's Background Activity Launch restrictions
(API 29+) outright; a `BroadcastReceiver`'s `onReceive()` never calls
`startActivity()`, so BAL doesn't apply to it at all. Verified this
version actually works with a clean before/after test: set
`adb_allowed_connection_time` to an arbitrary marker via `adb`, disconnect
`adb` completely, trigger the broadcast from Termux, reconnect `adb`,
confirm the marker reverted to `0` (exactly what `EnableReceiver` writes).

The receiver-only redesign keeps that mechanism and additionally makes
the app invisible in the launcher: with no activity there is no
`CATEGORY_LAUNCHER` component, so no icon is ever shown.

### `BOOT_COMPLETED` caveat

A freshly installed app is in Android's "stopped" state until it is first
launched or explicitly targeted, and stopped apps do not receive implicit
broadcasts like `BOOT_COMPLETED`. The install step above sends the app an
explicit `ENABLE` broadcast (or it is triggered normally on first use),
which clears the stopped state; after that the boot receiver works. If
you install and never trigger it, it will not auto-enable on the next
boot until triggered once.

## What this does not fix

- If the wifi radio itself is off, this is a no-op — `Settings.Global`
  writes flip a software flag; they can't power on hardware. That always
  needs a human.
- The app still appears under Settings → Apps → (show system/all apps);
  hiding it there would require installing it as a system app (root).
  It is gone from the launcher/app drawer, which is what matters for
  day-to-day use.
