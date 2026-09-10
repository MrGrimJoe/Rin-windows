# Rin — Windows Core

**A private, self-hosted mesh for your own devices — no cloud, no account, no
one else's server in the middle.**

Rin syncs clipboard text, hands off URLs, and transfers files directly
between your own devices over your LAN (with an opt-in relay fallback for
when they're not on the same network), end-to-end encrypted the whole way.
This is the Windows C++ core + console shell, wire-compatible with the
Android app at [github.com/MrGrimJoe/Rin-android-](https://github.com/MrGrimJoe/Rin-android-).

[![Build status](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml/badge.svg)](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml)
[![License: MrMIB v1.0](https://img.shields.io/badge/license-MrMIB%20v1.0-blue)](LICENSE)

---

## What it does

- **Clipboard sync** — copy on one device, paste on another, encrypted the
  whole way.
- **URL handoff** — push a link from one device to open on another.
- **File transfer** — chunked, checksummed, streamed peer-to-peer.
- **QR-based pairing** — join a mesh by scanning/pasting a token, no
  account, no server-side signup.
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

CI (above) builds the release binary, runs the full test suite, and
compiles the Windows installer on every push — that's genuinely green,
not aspirational. What CI *can't* tell you: this hasn't yet been run
against a real Android device over a real network, so cross-platform
discovery and the relay path are implemented and unit-tested on paper,
not field-verified yet. If you try it against the Android app, feedback
on what actually happens is welcome.

## Get it

Grab the installer from the latest
[Actions run](https://github.com/MrGrimJoe/Rin-windows/actions/workflows/build.yml)
(build artifact) or a tagged
[Release](https://github.com/MrGrimJoe/Rin-windows/releases), if one's
been published. Otherwise, build from source below.

## Build

Requires: CMake 3.16+, a C++17 compiler, OpenSSL dev headers,
nlohmann-json dev headers. Standalone Asio is vendored under
`third_party/asio/`.

```
cmake -B build
cmake --build build -j
```

On Windows with MSVC/vcpkg, install `openssl` and `nlohmann-json` via
vcpkg and pass `-DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake`
to the configure step; the CMakeLists already handles `WIN32` linking
against `ws2_32`/`wsock32`.

## Run tests

```
./build/tests/rin_tests
```

Should print `ALL TESTS PASSED.` — covers crypto round-trips, fail-closed
behavior (tampered/wrong-key rejection), discovery-tag/challenge-response
primitives (including a real two-party loopback round trip), wire-format
field names, and the relay fallback path.

## Run the console milestone

```
./build/rin_console
```

Creates a mesh identity, starts the TCP listener (port 45990, auto-
incrementing) and UDP discovery beacon (port 45991), and drops into a
command prompt. Type `help` for commands. To use a relay fallback, set
`RIN_RELAY_HOST` (and optionally `RIN_RELAY_PORT`, default 45992) before
launching — there's no in-console command for it, it's read once at
startup. See `DESIGN_NOTES.md` for how to test this against a real phone.

## Run the Win32 GUI (Windows only)

```
cmake --build build --target rin_gui
./build/rin_gui.exe
```

Shows the actual doc-described UI: a device list, Add Device (renders a
real scannable QR code), and Remove Selected. Camera-based QR *scanning*
isn't built yet — joining from Windows currently means pasting the other
device's token JSON into a small dialog. See `DESIGN_NOTES.md` for build
requirements and what's untested (this has never been compiled with a
real Windows SDK/MSVC — only reviewed against the Win32 API directly).

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
include/rin/       Public headers (protocol, crypto, transport, mesh_engine,
                    relay, qr_code, win32_shell)
src/                Implementation
tests/              Crypto, protocol, QR, discovery, and relay tests
third_party/asio/   Vendored standalone Asio (headers only)
DESIGN_NOTES.md     Design decisions, verified vs. assumed, known gaps
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
