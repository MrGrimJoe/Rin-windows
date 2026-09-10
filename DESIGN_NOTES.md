# Rin Windows Core — Design Notes

Companion to the v2.1 Product & Architecture Document. This file exists
because the actual Android implementation (github.com/MrGrimJoe/Rin-android-)
diverged from that doc in several load-bearing ways. This core targets
the **real Android wire protocol**, verified by reading source, not the
doc's original protobuf/libsodium/libjuice plan.

## Discovery hardening (this pass)

Two things were deliberately left unfixed in earlier passes and flagged
for later, because they're wire-protocol-level and need Android and
Windows updated together to stay compatible: **auto-trust on
discovery**, and the **cleartext beacon** (mesh name + device name sent
unencrypted over UDP broadcast, readable by anyone on the LAN). Both are
fixed now, on both platforms, in lockstep. See `rin-android/DESIGN_NOTES.md`'s
matching section for the Kotlin side of this -- the two should be read
together, since the whole point is that they agree byte-for-byte on the
wire.

**Beacon wire format bumped to v2.** The old beacon broadcast
`{"mesh":<name>,"key":<pubkey>,"name":<device>,"port":...}` in the
clear. v2 (`transport.hpp`/`transport.cpp`'s `UdpBeacon`) drops `mesh`
and `name` entirely and replaces them with a `meshTag`:
`base64(HKDF(meshKey, info="rin-beacon-tag-v1:"+bucket)[:9])`, where
`bucket = unixSeconds / 300`. Only a device that already holds the real
mesh secret can compute a matching tag, so a passive LAN observer now
sees an opaque blob instead of "mesh 'Family' has a device named
'Ali-Phone'". The tag rotates every 5 minutes so it isn't a long-lived
tracking identifier either. This is a **coordinated breaking bump, not
a soft migration** -- v1 and v2 peers simply can't discover each other.
`CryptoEngine::derive_beacon_tag` must stay byte-for-byte identical to
Android's `CryptoEngine.deriveBeaconTag` (same HKDF info string, same
9-byte truncation) or the two platforms silently stop discovering each
other -- confirmed identical for matching inputs during this pass (see
"Not verified by a real build" below for exactly how, given this
environment has no JVM). `stunIp`/`stunPort` stay in cleartext on the
beacon -- they're NAT-traversal server hints, not identifying metadata
about the mesh or device, so they don't need to move behind the
handshake the way mesh name and device name did.

**A beacon match no longer grants trust.** It used to: knowing the mesh
name (or, now, guessing/replaying a meshTag) was sufficient to get
auto-added to the trusted-devices map via `on_peer_discovered`'s old
"auto-join" branch. Now a match only triggers a **discovery
challenge/response handshake** over TCP (two new `PacketType` values,
`DiscoveryChallenge`/`DiscoveryResponse`, wire strings
`DISCOVERY_CHALLENGE`/`DISCOVERY_RESPONSE` -- must match Android's exactly)
where each side proves it can actually encrypt/decrypt with the real
mesh key -- not just produce a matching tag guess. Only on a valid
echoed nonce does a peer get promoted from "seen" to trusted
(`promote_to_trusted`), and that's also the point where its device name
is finally revealed (encrypted, inside the response). A lexicographic
tie-break on public keys (`local_public_key > peer.public_key` ->
initiate) stops both sides from challenging each other simultaneously
when they discover each other around the same time -- this comparison
must match Android's `handleDiscoveredPeer` tie-break exactly, since
both sides independently compute it and need to agree on who initiates.

Concurrent discovery of the same peer from more than one signal at once
is handled via `std::unordered_map::emplace`'s return value on
`pending_challenges_` (reject if the key already exists), reserving the
slot atomically rather than as a separate check-then-insert -- the same
race Android closes with `ConcurrentHashMap.putIfAbsent`. A mismatched
or undecryptable `DiscoveryResponse` deliberately does **not** clear the
pending entry -- a stray or forged packet shouldn't be able to cancel a
legitimate in-flight handshake by arriving first.

Windows has no mDNS or BLE discovery rails at all, so unlike Android
this fix only had one channel (the UDP beacon) to close -- no equivalent
of Android's "still-cleartext Wi-Fi-Direct HELLO probe, deliberately out
of scope" caveat applies here.

**Test coverage:** `test_crypto.cpp` covers the new primitives --
`derive_beacon_tag`'s determinism, rotation, and mesh-key-dependence;
`generate_discovery_nonce` non-collision; a full encrypt/decrypt round
trip for both challenge and response payloads through the real
AES-256-GCM mesh key; and confirming a payload encrypted with the
*wrong* mesh key fails to decrypt (the actual security property the
whole handshake rests on). `test_discovery.cpp` goes further than
Android could in this pass: it runs a **real two-party round trip** --
a real `MeshEngine` instance's actual `send_discovery_challenge()` path
connects over a real loopback TCP socket to a raw listener standing in
for "the other device," which decrypts the captured packet for real and
sends back a real, correctly-encrypted `DiscoveryResponse` -- rather
than only hand-constructing packets and feeding them to the receive-side
handlers directly (which it also does, for the challenged-side and
rejection cases). A genuine two-full-`MeshEngine`-instances-broadcasting-
real-UDP-beacons-at-each-other test was considered and deliberately
**not** done: two `UdpBeacon`s in one process both binding port 45991
has undefined-per-OS delivery semantics and would be a flaky test, not a
more thorough one.

**Not verified by a real build on the Android side in this pass** (their
words, from `rin-android/DESIGN_NOTES.md`) -- no Gradle wrapper jar, no
network access to Google's Maven repo in that environment. What *was*
independently confirmed cross-platform: `derive_beacon_tag` with a fixed
32-byte test key and bucket 100 produces `mX9hdhPSjPB+` on this
(compiled, tested) Windows implementation -- which matches a value
already independently verified elsewhere against the real, unmodified
Android `CryptoEngine.kt` compiled and run against a real `org.json` for
the same inputs. That's strong evidence the two derivations agree, even
though this pass didn't run a live two-device test between an actual
phone and this actual Windows binary.

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
- **The new relay fallback tier** (`tests/test_relay.cpp`): a real
  `RelayClient` registers with a real relay server over real loopback
  TCP sockets (not mocked), and a packet sent via `send_via_relay()`
  arrives at the other registered peer byte-for-byte unchanged, proving
  the relay never touches the encrypted payload. Also covers the
  "target never registered" case returning cleanly instead of hanging.
  This test caught two real bugs during development worth knowing about
  if you touch this code: (1) reusing a single-line-per-connection
  `read_line()` helper for a connection that reads *multiple* lines
  silently drops already-buffered bytes and hangs the next read — see
  the comment on `read_line()` in `relay.cpp`; (2) on Linux, closing a
  socket/acceptor fd from a different thread than the one blocked in
  `recv()`/`accept()` on it does not reliably unblock that call —
  `shutdown()` first is required. Both are fixed, but if you add more
  relay-adjacent networking code, know that these are the two sharp
  edges that bit this one.

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
- **The relay fallback tier's real-world/adversarial behavior.** What's
  verified is the happy path over loopback (register, forward, deliver,
  unchanged payload) plus one clean-failure case. NOT yet exercised:
  behavior over an actual internet path (latency, partial reads,
  reconnect-storms if a relay flaps); a hostile or overloaded relay
  server (the reference `rin_relay` has no auth beyond "knows a public
  key," no rate limiting, and no TLS — see the trust-model comment at
  the top of `relay_server.cpp`); and interop with an Android-side relay
  client, which does not exist yet (the Android app has no relay
  fallback of its own — see the wire protocol note in `relay.hpp` for
  why this doesn't affect the message format itself).

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
- **Auto-trust on UDP discovery -- FIXED.** See "Discovery hardening"
  below. `on_peer_discovered` used to add any peer broadcasting the same
  mesh name straight into the trusted-devices map; it now only refreshes
  an already-trusted device's connection info, and new trust requires
  proving mesh-secret possession via a challenge/response handshake.
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
- BLE and Wi-Fi Direct rails (currently LAN/TCP + UDP discovery + the
  new opt-in relay fallback — see `relay.hpp`). Realistically these two
  are Android-only concepts; Windows' practical ceiling is LAN + relay,
  which is now in place, rather than trying to replicate Wi-Fi Direct
  group formation on a platform with no equivalent API.
- An Android-side relay client speaking the same register/forward
  protocol as `relay.hpp`/`relay_server.cpp`, so the relay fallback
  actually helps cross-platform, not just Windows-to-Windows.
- Harden `rin_relay` before pointing it at anything but your own
  devices: TLS, real client authentication (right now "knowing a public
  key" is sufficient to register as that key — see the trust-model
  comment in `relay_server.cpp`), and rate limiting.
- Persist identity/trusted-devices to disk — DONE (`persistence.cpp`,
  SQLite-backed, covered by `test_persistence.cpp`). This note is being
  left here crossed out rather than deleted since the GUI's first-launch
  chooser still has an open bug around re-firing on every run (see the
  comment in `Win32Shell::run()`) — the underlying storage works, the
  GUI's use of it on startup is what still needs the follow-up.
- System tray icon / minimize-to-tray, since a background mesh app
  shouldn't need a visible window at all times once this is polished.
