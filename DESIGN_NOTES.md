# Rin Windows Core — Design Notes

Companion to the v2.1 Product & Architecture Document. This file exists
because the actual Android implementation (github.com/MrGrimJoe/Rin-android-)
diverged from that doc in several load-bearing ways. This core targets
the **real Android wire protocol**, verified by reading source, not the
doc's original protobuf/libsodium/libjuice plan.

## Why OpenSSL instead of libsodium

The doc specified libsodium + Ed25519/X25519. Android's actual
`CryptoEngine.kt` uses JCA (`KeyPairGenerator("EC")`, curve
`secp256r1`/P-256, `SHA256withECDSA`, `AES/GCM/NoPadding`) — standard
NIST-curve primitives, not libsodium's Ed25519/X25519. OpenSSL's EC/EVP
API is the natural match for wire compatibility here; introducing
libsodium would mean translating between two different curve families
for no benefit.

## Why JSON instead of Protocol Buffers

Android's `MeshRuntimeEngine` sends one JSON object per line
(`PrintWriter.println` / `BufferedReader.readLine`), not protobuf. This
core matches that framing exactly (`packet_to_wire_json` /
`packet_from_wire_json` in `protocol.cpp`). If the project moves to
protobuf later, both sides need to move together — this core does not
support both.

## What's verified vs. what's assumed

**Verified by automated tests** (`tests/test_crypto.cpp`,
`tests/test_protocol.cpp`, `tests/test_qr.cpp`; run via `ctest` or
`./build/tests/rin_tests`):
- AES-256-GCM and ECDSA round-trip correctly and use standard, JCA-
  interoperable formats (X.509 SPKI, PKCS8, IV‖ciphertext‖tag).
- All fail-closed guarantees actually fail closed: tampered ciphertext,
  wrong keys, malformed/non-ECDSA signatures, and too-short payloads are
  rejected with an exception or `false` — never silently degraded or
  passed through.
- ECDH shared secrets and HKDF-derived session keys agree from both
  sides of a simulated exchange.
- Wire JSON field names and enum spellings match what `MeshRuntimeEngine.kt`
  actually emits (`v`, `sess`, `seq`, `senderKey`, `sig`, `rail`, `ts`,
  `CLIPBOARD_SYNC`, etc.) — not the friendlier names implied by the README.
- **QR generation actually produces a scannable code**, not just pixels
  that compile: `test_qr.cpp` decodes the generated QR image using
  ZXing — an independent decoder from our own encoder, and the same
  decoder family behind most real-world phone camera QR scanning — and
  confirms the decoded bytes are byte-for-byte identical to the original
  join token JSON, and that the round-tripped JSON still parses back
  into a valid `QrJoinToken`.

**NOT yet verified — needs a real device test:**
- End-to-end interop against the actual Android app. This environment
  has no JVM/Android toolchain, so the tests above prove "standard,
  spec-compliant EC P-256 / AES-GCM / JSON" and "a real QR decoder can
  read this," not "a Pixel's actual camera, at actual screen distances
  and lighting, running the actual APK, completes a full join." The
  `rin_console` and `rin_gui` binaries exist specifically to let you
  test this by hand.
- **The Win32 GUI itself is UNCOMPILED on this environment.** This
  sandbox is Linux with no Windows SDK, so `win32_shell.cpp`/`main_gui.cpp`
  have been reviewed carefully and written directly against the real
  Win32 API, but have never actually been run through MSVC or linked
  against real `user32.lib`/`gdi32.lib`/`comctl32.lib`. Build this on
  your actual Windows machine first and expect to fix at least minor
  compile issues — see "Building the GUI on Windows" below for what to
  watch for.
- The TCP connect/read timeout behavior under real network conditions
  (Wi-Fi Direct, different subnets, a phone with mobile data instead of
  Wi-Fi) — only tested here against localhost/loopback-adjacent conditions.
- Multi-hop / full-mesh trust propagation (Phase 9 in the roadmap) —
  this core only implements pairwise join handshakes so far, matching
  where the Android side currently is.
- **Camera-based QR scanning does not exist yet.** The GUI can *display*
  a QR (Add Device button → `show_qr_window`), but joining a mesh from
  Windows currently means pasting the other device's token JSON as text
  into a dialog (`run_join_paste_dialog`) rather than pointing a webcam
  at the phone's QR. See "Next steps" below.

## Building the GUI on Windows

`rin_gui` is a separate CMake target, only built when `WIN32` is true.
On your actual Windows box:

```
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --target rin_gui
```

You'll need `openssl`, `nlohmann-json`, and `libqrencode` installed via
vcpkg (`vcpkg install openssl nlohmann-json libqrencode`). Things worth
double-checking on first compile, since none of this has been run
through MSVC yet:
- `#pragma comment(lib, "comctl32.lib")` in `win32_shell.cpp` plus the
  explicit `comctl32` link in CMakeLists — MSVC usually only needs one
  of these, having both should be harmless but is untested.
- The manifest requirement for Common Controls v6 (ListView, themed
  buttons) — modern Windows usually resolves this automatically, but if
  `rin_gui` shows unthemed/classic controls, you likely need an
  application manifest requesting `comctl32.dll` version 6.
- `CreateDIBSection`'s top-down DIB (`biHeight = -height`) plus a 32bpp
  BGRA buffer — this is standard and should be fine, but hasn't been
  visually confirmed against a real display yet.

## Current GUI capabilities

- First launch: a Yes/No chooser (Create vs. Join a mesh) — currently a
  `MessageBoxW`, not a polished dialog. Functionally matches doc §02's
  "two choices only," visually it's a placeholder.
- Main window: a `ListView` showing the live device list (name,
  platform, connection state, address), an Add Device button, and a
  Remove Selected button, refreshed once per second via a timer (see
  the comment in `win32_shell.cpp` on why polling instead of pushing
  from transport threads).
- Add Device: renders the local join token as a real QR code (via
  `qr_code.hpp`/`libqrencode`) in a popup window, blitted with
  `BitBlt`/`CreateDIBSection`.
- Join (the other device's side, today): a small paste-a-token-JSON
  dialog, since camera-based scanning isn't built yet.
- Remove: calls `MeshEngine::revoke_device`, which signs and broadcasts
  a revocation packet before dropping the local trust entry — matches
  doc §02/§07.

## Known compromises in this milestone

- **No Win32 clipboard/browser/file integration yet.** `on_packet_received`
  in `mesh_engine.cpp` logs these events but doesn't act on them (no
  `SetClipboardData`, no `ShellExecute`). Deliberately deferred until the
  core handshake proves out against a real phone — see the `TODO` comments
  at the relevant switch cases.
- **Auto-trust on UDP discovery.** `on_peer_discovered` adds any peer
  broadcasting the same mesh name straight into the trusted-devices map,
  matching Android's current `handleDiscoveredPeer` behavior. This is
  *not* the doc's QR-is-the-security-boundary model — it works today
  because unsigned/unencrypted traffic from an untrusted peer still gets
  rejected downstream (signature verification, AES-GCM auth), but a
  peer that merely knows the mesh name can still show up in your device
  list. Worth tightening before this ships to real users.
- **New TCP connection per packet, synchronous send.** Matches Android's
  current behavior exactly (simple, not fast). Fine for control traffic
  and clipboard sync; will need a persistent-connection or streaming path
  before file transfer throughput matters (Phase 7+).
- **Legacy mesh-key fallback is not a real secret.** `derive_mesh_encryption_key`
  falls back to `SHA-256(mesh_name)` when no `meshSecret` is supplied, for
  compatibility with any mesh created before the mesh-secret fix. Mesh
  name is shown on-screen and in the QR payload, so this path provides no
  real confidentiality — it exists only so old and new installs can still
  talk, not as a security boundary. See the loud comment in `crypto.hpp`.

## Testing this against your phone

1. Build: `cmake -B build && cmake --build build`
2. Run tests first: `./build/tests/rin_tests` — should print `ALL TESTS PASSED.`
3. Run `./build/rin_console`, create a mesh, run `token`, copy the JSON.
4. On the phone, add `"hostIp":"<this PC's LAN IP>"` to that JSON (the
   real QR flow embeds this automatically once camera/QR UI exists on
   Windows — see "Next steps" below) and feed it into whatever the
   Android app's join path expects.
5. Alternatively, let UDP discovery do the work: both devices on the same
   LAN/Wi-Fi, same mesh name, should show up in each other's `devices`
   list within ~6 seconds without manually exchanging tokens — though
   note the auto-trust caveat above means this isn't actually testing
   the QR security boundary, just connectivity.

## Suggested next steps (not built yet)

- Camera-based QR **scanning** to replace `run_join_paste_dialog`'s
  copy-paste flow — capture a frame (e.g. via Media Foundation or an
  OpenCV `VideoCapture`), decode with ZXing (already a test dependency;
  promoting it to a runtime `rin_core` dependency for this is
  reasonable), and feed the result into `MeshEngine::complete_join_handshake`
  the same way the pasted-JSON path does today.
- Replace the `MessageBoxW` first-launch chooser and the hand-built
  paste dialog with proper `.rc`-based dialog templates for correct
  modal behavior, tab order, and visual polish.
- Wire up `on_packet_received`'s clipboard/browser-handoff cases to
  actual Win32 APIs.
- BLE and Wi-Fi Direct rails (currently LAN/TCP + UDP discovery only).
- Persist identity/trusted-devices to disk (currently in-memory only —
  restarting `rin_console`/`rin_gui` forgets everything, unlike
  Android's Room database). This also means the GUI's first-launch
  chooser fires on every run right now — see the comment in
  `Win32Shell::run()`.
- System tray icon / minimize-to-tray, since a background mesh app
  shouldn't need a visible window at all times once this is polished.
