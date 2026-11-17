# Field test: Windows PC ↔ Android phone

Everything here has been verified on loopback only. This is the checklist for
the first real run, and the place to write down what actually happened.

## Before you start

- **Same Wi-Fi, same subnet.** Not a guest network, and not one with "client
  isolation" / "AP isolation" turned on — that blocks phone↔PC traffic and
  looks exactly like a Rin bug. Phone on Wi-Fi, mobile data off for now.
- **Builds.** PC: the `Rin-Setup-*.exe` artifact from the latest green
  [Windows Actions run](https://github.com/MrGrimJoe/Rin-windows/actions).
  Phone: the `rin-debug-apk` artifact from the latest green
  [Android run](https://github.com/MrGrimJoe/Rin-android-/actions).
- **Firewall.** The installer adds inbound allow rules for `RinWindows.exe`
  and `rin-console.exe` on the **Private** network profile. Check the Wi-Fi is
  set to Private (Settings → Network → Wi-Fi → your network). If you run a
  self-built exe instead, allow it on Private when Windows asks. Ports: TCP
  45990 (packets), UDP 45991 (discovery).
- **One identity per install.** `rin_tests` no longer touches your real
  identity (it uses a temp database), but if you built from an older commit,
  back up `%APPDATA%\Rin\mesh.db` first.

## 1. Start the PC as the host

1. Launch Rin. First run: choose **Yes — Create a new mesh**.
2. Click **Add Device**. A QR window appears.
3. Optional sanity check with the console: run `rin-console`, type `token`.
   The JSON must contain `"hostIp"` and it must be this PC's address **on the
   Wi-Fi the phone is on**. If it's a VPN/WSL/Hyper-V address, set
   `RIN_ADVERTISE_IP=<wifi ip>` in the environment and relaunch.

## 2. Pair the phone

1. Phone: open Rin → onboarding → **Join** → scan the QR on the PC.
2. Expected on the phone: the PC appears in the device list.
3. Expected on the PC, within roughly 6–12 seconds (the beacon interval):
   the phone appears in the list as **trusted**. The console `events` /
   `devices` commands show the same.

### What the PC log should look like

| Line | Meaning |
|---|---|
| `[OK] SIGNATURE_VERIFICATION … packet #…` | The phone's join packet reached the PC and its signature checked out. **If this never appears, the phone never reached the PC** (firewall, wrong IP, client isolation). |
| `[ERROR] DECRYPTION_ECDH … Targeted ECDH decryption failed` | **Expected right now, not a failure.** `JOIN_ACCEPT` is encrypted with the mesh key but the host tries the per-peer key; known gap, see DESIGN_NOTES "Pairing flow". |
| `Discovery verified, now trusted: <phone>` | The real trust event. Comes from the beacon + challenge/response, not from the join packet. |

If `SIGNATURE_VERIFICATION` appears but "now trusted" never does, discovery
isn't working: the UDP 45991 broadcast isn't getting through (router blocks
broadcast, different subnet, firewall on UDP) or the two sides derived
different mesh keys.

## 3. Feature checks

Tick each as you go. Note the direction.

- [ ] Clipboard PC → phone (copy on PC, paste on phone)
- [ ] Clipboard phone → PC (copy on phone, Ctrl+V on PC)
- [ ] URL handoff phone → PC (opens in PC's default browser)
- [ ] ~~URL handoff PC → phone~~ — not testable yet: the engine can send it
      but neither the GUI nor the console has a control for it
- [ ] File phone → PC, small (< 1 MB). Lands in `Downloads\Rin Downloads`
- [ ] File phone → PC, large (≥ 100 MB). Note speed and whether it completes
- [ ] File PC → phone (console: `sendfile <key> <path>`; key from `devices`)
- [ ] Remove the phone from the PC (Remove Selected); phone should drop the PC
- [ ] Quit and relaunch both apps: both still know each other (persistence)
- [ ] Put the phone to sleep for a few minutes, wake it, send a clipboard
- [ ] ~~Relay fallback~~ — not testable from the phone yet: the Android app
      never calls `configureRelay()` and has no setting for it, so its relay
      client is never started. Windows↔Windows relay works on loopback only.

## 4. If something fails

| Symptom | Most likely cause | Check |
|---|---|---|
| Phone pairs but PC never sees a join packet | Firewall / client isolation / wrong `hostIp` | `token` JSON's `hostIp`; ping the PC from the phone; Wi-Fi profile is Private |
| Phone scans, then says unreachable immediately | QR had no `hostIp` (PC offline at the time) | Reconnect Wi-Fi, click Add Device again |
| Join packet arrives, PC never lists the phone | Beacons not crossing, or mesh keys differ | UDP 45991 allowed; both sides show the **same mesh name** (a mismatch breaks every mesh-key packet) |
| Clipboard works one way only | One side trusts the other but not vice versa | `devices` on each side; wait one more beacon cycle |
| Everything works for minutes, then stops | Phone changed IP / slept | Next beacon should refresh the address; note how long it takes |
| Large file fails midway | Per-packet TCP connection + 64 KB chunks over flaky Wi-Fi | Note the percentage reached; try 5 GHz, closer to the router |

Useful sources: PC console `events` (recent mesh events); PC stderr (every
audit-log line, `[CATEGORY] message`); the Android **Packet Inspector** sheet.
The categories use the same names on both sides so lines can be matched up.

## Result log

Copy this block per attempt.

```
Date:
PC build (Actions run #):            Phone build (Actions run #):
Phone model / Android version:
Network (router, 2.4/5 GHz, isolation off?):
Paired?  yes / no       Seconds until PC trusted the phone:
Clipboard PC→phone / phone→PC:
URL handoff:
File small / large (MB, seconds):
Persistence after restart:
First failing step, and the exact log lines around it:
```
