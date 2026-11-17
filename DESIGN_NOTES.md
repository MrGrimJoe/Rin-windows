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

**NOT yet verified — needs a real device test** (see
[`docs/FIELD_TEST.md`](docs/FIELD_TEST.md)):
- End-to-end interop against the actual Android app. The tests prove
  "standard, spec-compliant EC P-256 / AES-GCM / JSON", "a real QR decoder
  can read this PC's QR", and "two engines in one process complete a join
  over real loopback TCP" — not "a Pixel's camera, at real distances and
  lighting, running the real APK, completes a full join".
- TCP connect/read timeout behavior under real network conditions
  (Wi-Fi Direct, different subnets, a phone on mobile data).
- Multi-hop / full-mesh trust propagation (Phase 9 in the roadmap) — only
  pairwise join handshakes exist so far, matching the Android side.
- The relay fallback over a real internet path, and against a hostile or
  overloaded relay (`rin_relay` has no auth beyond "knows a public key", no
  rate limiting, no TLS — see the trust-model comment in `relay_server.cpp`).
  The Android app has a relay client (`RelayClient.kt`, same register/forward
  wire protocol), but nothing in the Android app ever calls
  `configureRelay()` and there is no setting for it, so on a phone the relay
  tier is unreachable today.

## Pairing flow (how a join actually works today)

1. The **host** shows a token: mesh name, public key, device name, an
   ephemeral token, the mesh secret, TCP port, and its **LAN IP**
   (`detect_local_lan_ip()`; override with `RIN_ADVERTISE_IP`). The Windows
   GUI renders it as a QR; the console's `token` prints the JSON. Without
   the IP a scanning phone has nothing to reach the host by — Android falls
   back to the INTERNET_P2P rail when `hostIp` is absent.
2. The **joiner** scans/pastes it, adopts the host's mesh **secret and
   name**, and sends a signed `JOIN_ACCEPT` to the host's address. The name
   matters as much as the secret: it is the HKDF salt in
   `derive_mesh_encryption_key`, so a joiner that keeps its own name derives
   a different mesh key than the host and nothing mesh-key-encrypted
   decrypts. (Windows previously never adopted the name; Android did so only
   on first launch. Both fixed.)
3. Windows only ever plays the **host** in this flow for phones — it
   generates QR codes and never scans them. Joining *another* device's mesh
   from this PC is a manual paste of that device's token JSON.

**Known gaps in the pairing flow (verified by a real loopback run, not
just by reading the code):**
- **`JOIN_ACCEPT` is dropped by the host with an ECDH decryption failure.**
  The packet is targeted at the host's key, so the receiver tries the
  per-peer ECDH session key, but the joiner encrypted it with the mesh key.
  The signature verifies, the decrypt fails, the packet is discarded, and
  the audit log shows a `[ERROR] DECRYPTION_ECDH` line on every otherwise
  successful join. Android's receive path has the same shape.
- Consequently **the host never adds the joiner to its trusted devices from
  the join itself.** Reverse trust only arrives via UDP beacon discovery +
  the challenge/response handshake, so it needs both devices on the same
  broadcast domain; a join across subnets or via relay only is one-way until
  that happens.
- The ephemeral token in the QR is never checked by the host (it would be
  inside the dropped `JOIN_ACCEPT` anyway). The mesh secret in the QR is the
  actual credential: anyone who photographs the QR can join.

Fixing the first two together is the natural next protocol change: have the
host decrypt `JOIN_ACCEPT` with the mesh key, check the ephemeral token it
issued, and trust the joiner immediately. It needs both platforms to change
in lockstep.

## Current GUI capabilities

- First launch: a Yes/No chooser (Create vs. Join a mesh) — a
  `MessageBoxW`, not a polished dialog. Join means pasting the other
  device's token JSON.
- Main window: a `ListView` of live devices (name, platform, connection
  state, address), refreshed once per second; Add Device and Remove
  Selected buttons; minimize-to-tray with a right-click menu.
- Add Device: renders this PC's join token as a QR (`qr_code.hpp` /
  libqrencode, blitted with `BitBlt`/`CreateDIBSection`) for a phone to scan.
- Remove: `MeshEngine::revoke_device` signs and broadcasts a revocation
  before dropping the local trust entry.
- Received clipboard text → `SetClipboardData`; received URLs →
  `ShellExecute` (URL-validated); received files → `Downloads\Rin Downloads`,
  SHA-256 verified.
- Identity and trusted devices persist in SQLite at `%APPDATA%\Rin\mesh.db`
  (override with `RIN_DB_PATH`). The GUI and CI installer are built by
  `.github/workflows/build.yml`.

## Known compromises

- **New TCP connection per packet, synchronous send.** Matches Android's
  current behavior (simple, not fast). Fine for control traffic and
  clipboard; file transfer is chunked on top of it.
- **`TcpTransport::send_packet` refuses `127.0.0.1`** by design (Android
  ignores loopback peers too). Same-machine experiments need another
  loopback address such as `127.0.0.2`.
- **Legacy mesh-key fallback is not a real secret.** `derive_mesh_encryption_key`
  falls back to `SHA-256(mesh_name)` when no `meshSecret` is supplied, for
  compatibility with meshes created before the mesh-secret fix. See the loud
  comment in `crypto.hpp`.
- **Stale challenge entries never expire** (`pending_challenges_`); a peer
  that never replies just won't be re-challenged until restart.
- **Cleartext Wi-Fi-Direct HELLO / BLE mesh hash on Android** are outside
  this core and still leak mesh metadata on those rails.

## Testing this against your phone

See [`docs/FIELD_TEST.md`](docs/FIELD_TEST.md).

## Suggested next steps

- Run the field test; record real behavior.
- Android: a setting (and a call to `configureRelay()`) so the relay tier can
  actually be turned on; a GUI/console control for URL handoff from the PC.
- Host-side `JOIN_ACCEPT` handling (decrypt with the mesh key, verify the
  ephemeral token, trust immediately) — coordinated with Android.
- A phone-scans-PC pairing flow that lets the PC join an *existing* phone
  mesh without pasting JSON (needs a protocol addition: the QR owner is the
  one being added, so the phone must hand the mesh credentials over under
  the PC's public key).
- Proper `.rc` dialog templates to replace the `MessageBoxW` chooser and the
  hand-built paste dialog.
- Harden `rin_relay` before pointing it at anything but your own devices:
  TLS, real client authentication, rate limiting.
- Enable the ZXing QR round-trip test in CI (`zxing-cpp` via vcpkg).
