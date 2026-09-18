# termux-adb-bridge

> **CAUTION — READ BEFORE YOU INSTALL**
>
> This gives Termux the Android **`shell` UID** and keeps it available at
> all times. That is a serious privilege tier, not a toy: anything running
> as Termux can then inject input events, change secure settings, dump
> system state, list and control apps, and run nearly anything the ADB
> `shell` can. It is **not** root, but treat it as close to one.
>
> Concretely, that means: **only run code you trust in Termux**, because a
> malicious script, a compromised `$PREFIX`, or a leaked daemon binary
> (which carries the shared secret) hands an attacker `shell` on your
> device. Do **not** expose the daemon beyond loopback, do **not** wire it
> into unattended automation, and **uninstall/stop the daemon when you no
> longer need it.** You accept this risk by installing it.

Run commands at Android's `shell` UID from Termux, without Shizuku.
Bootstrapped once over ADB Wireless Debugging (Android 11+), then
self-healing from Termux alone — no `adb`, no laptop, no cable after setup.

**For your own device only.** Every code path requires physically enabling
Developer Options and pairing Wireless Debugging yourself. It is not, and
cannot be, a remote exploit.

## How it works

1. **One-time bootstrap.** `adb shell` (via `adbwire`, no `android-tools`)
   runs a small C binary once — the only privileged action needed.
2. **Daemonize.** It double-forks and `setsid()`s, detaching from the `adb
   shell` session so a dropped connection can't kill it.
3. **Loopback only.** It binds `127.0.0.1:<port>`; Termux talks to it
   directly from then on.
4. **Authenticated, encrypted channel.** A kernel-verified peer-UID check
   (`/proc/net/tcp`, only possible at `shell` UID) is the primary boundary;
   a v3 challenge/response handshake authenticates the daemon, and requests
   travel as ChaCha20 + HMAC-SHA256 AEAD streams keyed by a 32-byte secret
   baked into both binaries at build time (no secret file).
5. **Recovery is external.** The daemon never resurrects itself.
   `maintain/deploy.sh` detects a dead daemon and redeploys it over
   Wireless Debugging, re-enabling the toggle via `adbwifi-helper` first if
   needed, then verifies the new daemon before retiring the old one.

## Quick start

On the device: **Settings → System → Developer options → Wireless
debugging → Pair device with pairing code** — leave that screen open. Then:

```sh
pkg install -y git
git clone https://github.com/jronminh/termux-adb-bridge.git
cd termux-adb-bridge
build/build.sh                    # compiles everything into build/out/
build/out/adbwire --pair <code>   # one-time; <code> is shown on the device
maintain/deploy.sh                # push + launch + verify the daemon
```

Check it: `build/out/relaysh-client 'id'` should print `uid=2000(shell)`.

`maintain/deploy.sh` is a deliberate, human-run action — it (re)starts a
`shell`-UID daemon. Don't point a scheduler at it; keep running it by hand
and with the privilege in mind.

## What's in here

- **`build/`** — compiles all artifacts into `build/out/`:
  - `build.sh` — generates one random secret + port and bakes them into
    **both** the daemon and the client in the same run.
  - `relaysh/` — the privilege bridge: `relaysh-daemon.c`,
    `relaysh-client.c`, the v3 wire protocol, and ChaCha20/HMAC-SHA256.
  - `adbwire/` — a minimal OpenSSL-only ADB client for Wireless Debugging:
    SPAKE2 pairing, TLS 1.3, `shell,v2` with real exit codes, file push, and
    mDNS discovery. Replaces the `android-tools` dependency.
  - `adbwifi-helper/` — a tiny receiver-only Android app (not Shizuku, not
    Termux's APK) that flips the Wireless Debugging toggle back on **in
    software**, with no adb. See its own README.
- **`maintain/`** — consumes `build/out/`: `deploy.sh` pushes, launches and
  verifies the daemon. Compiles nothing. Run it by hand, not from a
  scheduler.

## Requirements

- **Android 11+**, where the Wireless Debugging menu exists.
- **Termux from F-Droid or GitHub** (not Play Store).
- **`pkg install termux-am`** — `adbwifi-helper` depends on it.
- **An aarch64 device** — the build is hardcoded to that target.
- No `android-tools` needed; `adbwire` links only OpenSSL.

## Known limitations

- **Nothing here can turn the wifi radio on**, and a radio cycle may need an
  on-screen human touch to re-arm the TLS listener. Both need a human.
- **A stuck "offline" state can follow a toggle** (an AOSP teardown race):
  a stale listener accepts TCP then rejects the cert. A manual Wireless
  Debugging off/on clears it; `adbwire` surfaces the failure rather than
  faking success.
- **The device may advertise multiple `_adb-tls-connect._tcp` mDNS
  records** — stale ones from previous sessions. The newest is the
  unsuffixed name, which `discover_adb_port()` prefers.
- **Pairing can appear to fail for three reasons**: stale host-side `adb`
  state (`adb kill-server`), the on-screen touch-gate, or genuine trust
  revocation (rare).

## References

The design was root-caused against primary sources, not guessed. The main
ones:

- AOSP [`AdbService.java`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/adb/AdbService.java)
  and [`AdbDebuggingManager.java`](https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/adb/AdbDebuggingManager.java)
  (`frameworks/base/services/core/java/com/android/server/adb/`) — the
  `ctl.stop adbd` condition and the teardown race.
- [Linux cgroup v2](https://www.kernel.org/doc/html/v4.18/admin-guide/cgroup-v2.html)
  — why the daemon is tied to `adbd`'s cgroup, not a debug session.
- [RFC 6763 §9](https://datatracker.ietf.org/doc/html/rfc6763#section-9) —
  mDNS-SD name-collision rules behind the stale
  `_adb-tls-connect._tcp` records.
- [Shizuku `starter.cpp`](https://github.com/RikkaApps/Shizuku/blob/master/manager/src/main/jni/starter.cpp)
  and [scrcpy #4639](https://github.com/Genymobile/scrcpy/issues/4639) —
  prior art for the `app_process`/Wireless-Debugging paths.
- [GrapheneOS #3770](https://github.com/GrapheneOS/os-issue-tracker/issues/3770)
  and this [Samsung developer forum thread](https://forum.developer.samsung.com/t/wireless-debugging-or-why-must-samsung-break-things-via-updates/28200)
  — Wireless-Debugging behavior and OEM variation.

## License

[GPL-3.0](LICENSE) — any fork or derivative must stay open source under the
same terms.
