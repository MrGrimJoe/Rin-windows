# Rin — Windows Core

**A private, self-hosted mesh for your own devices — no cloud, no account, no
one else's server in the middle.**

Rin syncs clipboard text, hands off URLs, and transfers files directly
between your own devices over your LAN (with an opt-in relay fallback for
when they're not on the same network), end-to-end encrypted the whole way.
This is the Windows C++ core, a console shell, and a Win32 GUI (tray app with
a device list and QR display), wire-compatible with the Android app at
[github.com/MrGrimJoe/Rin-android-](https://github.com/MrGrimJoe/Rin-android-).

[![Build status](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml/badge.svg)](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml)
[![License: MrMIB v1.0](https://img.shields.io/badge/license-MrMIB%20v1.0-blue)](LICENSE)

---

## What it does

- **Clipboard sync** — copy on one device, paste on another, encrypted the
  whole way.
- **URL handoff** — push a link from one device to open on another.
- **File transfer** — chunked, checksummed, streamed peer-to-peer.
- **QR-based pairing** — this PC shows a QR code (which carries its LAN
  address, mesh name and secret) and a phone running Rin scans it. Windows
  only generates QR codes; it never scans them. No account, no server-side
  signup.
- **Opt-in relay fallback** — devices with no direct LAN path to each other
  can still reach each other through a relay you point them at (your own,
  or none at all — nothing is configured by default). The relay only ever
  forwards the same AES-256-GCM ciphertext that would've gone over the LAN;
  it can't read your data.

## Security model

- **AES-256-GCM**, end-to-end, for every packet payload.
- **ECDSA (P-256) signatures** on top, so a tampered or forged packet is
  rejected outright, not silently accepted.
- **Discovery beacon is encrypted metadata, not a name tag.** The old
  format broadcast your mesh and device names in the clear on the LAN;
  the current one broadcasts a rotating HKDF-derived tag that only a
  device holding the real mesh secret can compute. A passive observer
  on your Wi-Fi sees an opaque blob, not "Ali's mesh has a device called
  Ali-Phone."
- **A beacon match doesn't grant trust by itself.** It only triggers a
  challenge/response handshake where each side has to prove it can
  actually decrypt with the real mesh key. Device names are only ever
  revealed, encrypted, after that handshake succeeds.

None of this is marketing copy — see [`DESIGN_NOTES.md`](DESIGN_NOTES.md)
for the actual protocol writeup, and what's verified versus merely assumed.

## Status

CI builds the Release binaries, runs the full test suite, and compiles the
Windows installer on every push. That is green as of the latest runs.
What CI *can't* tell you: this hasn't yet been run against a real Android
device over a real network, so cross-platform discovery, pairing and the
relay path are implemented and tested on loopback, not field-verified.
[`docs/FIELD_TEST.md`](docs/FIELD_TEST.md) is the checklist for doing that,
and the place to record what actually happens.

## Get it

Grab the installer from the latest
[Actions run](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml)
(build artifact) or a tagged
[Release](https://github.com/MrGrimJoe/Rin-windows/releases), if one's
been published. Otherwise, build from source below.

## Build

Requires: CMake 3.20+, a C++17 compiler, OpenSSL and libqrencode dev
packages. Asio, nlohmann-json and (on Windows) the SQLite amalgamation are
downloaded by CMake at configure time, so the first configure needs network
access.

```
cmake -B build
cmake --build build -j
```

On Windows with MSVC/vcpkg, install `openssl` and `libqrencode` via vcpkg
and pass `-DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake`.
CI uses the `x64-windows-static` triplet with the static CRT so the exe is
fully self-contained (see `.github/workflows/build.yml`).

## Run tests

```
./build/tests/rin_tests
```

Should end with `ALL TESTS PASSED.` — covers crypto round-trips, fail-closed
behavior (tampered/wrong-key rejection), the wire format's field names,
QR generation, SQLite persistence, chunked file transfer, the relay
fallback, and the discovery/trust-boundary handshake (including a real
two-party loopback round trip and join-token contents).

Tests point `RIN_DB_PATH` at a temp file, so running them never overwrites
the identity of a Rin install on the same machine. If libzxing is
installed (`libzxing-dev` on Linux, `zxing-cpp` in vcpkg), one extra test
decodes the generated QR with an independent decoder; without it that one
test is skipped. ZXing is test-only — it is not linked into the app.

## Run the console

```
./build/rin-console
```

Creates (or loads) a mesh identity, starts the TCP listener (port 45990,
auto-incrementing) and UDP discovery beacon (port 45991), and drops into a
command prompt. Type `help` for commands (`token`, `join`, `devices`,
`events`, `clipboard`, `sendfile`). To use a relay fallback, set
`RIN_RELAY_HOST` (and optionally `RIN_RELAY_PORT`, default 45992) before
launching.

Environment variables: `RIN_ADVERTISE_IP` (LAN address to put in the join
token if auto-detection picks the wrong adapter, e.g. VPN/WSL/Hyper-V),
`RIN_DB_PATH` (use a different database file than `%APPDATA%\Rin\mesh.db`).

## Run the Win32 GUI (Windows only)

```
cmake --build build --config Release --target RinWindows
build\Release\RinWindows.exe
```

A tray app: device list, **Add Device** (shows this PC's join QR for a phone
to scan), **Remove Selected** (signed revocation), minimize-to-tray, and a
Windows installer built by CI (`installer.iss`). Received clipboard text is
written to the Windows clipboard, handed-off URLs open in the default
browser, and received files land in `Downloads\Rin Downloads`. Joining
*another* device's mesh from this PC is a manual paste of that device's
token JSON (first-launch "Join" option, or the console's `join` command).

## Run your own relay (optional)

```
cmake --build build --target rin_relay
./build/rin_relay.exe
```

A dumb, self-hostable forwarder — it never sees plaintext, only the same
metadata already visible on the LAN beacon. Not required; if you never
point a client at one, this code path is never exercised and behavior is
identical to not having it.

## Layout

```
include/rin/       Public headers
src/               Implementation (core, console, Win32 shell)
tests/             Test suites, one binary (rin_tests)
docs/              FIELD_TEST.md — real-device test checklist
DESIGN_NOTES.md    Design decisions, verified vs. assumed, known gaps
installer.iss      Inno Setup script (compiled by CI)
```

## The Android side

This core is wire-compatible with the Android app at
[github.com/MrGrimJoe/Rin-android-](https://github.com/MrGrimJoe/Rin-android-)
— same crypto, same discovery handshake, same packet types. The two
repos' `DESIGN_NOTES.md` files are meant to be read together, since the
whole point is that they agree byte-for-byte on the wire.

## License

Custom license — see [`LICENSE`](LICENSE). Short version: you're free to
build, run, and use this (including commercially), and to review or write
about it, as long as you credit the original author. Forking or building
derivative works isn't permitted by default (this README doesn't grant
that exception), and the software itself can't be resold or repackaged.
Not OSI-approved open source — read the full terms before relying on
anything here.
