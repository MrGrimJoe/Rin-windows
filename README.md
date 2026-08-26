# Rin — Windows Core

The C++ core + console shell for Rin's Windows side, wire-compatible
with the Android app at github.com/MrGrimJoe/Rin-android-.

See `DESIGN_NOTES.md` for what's verified, what's assumed, and what's
deliberately deferred.

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
behavior (tampered/wrong-key rejection), and wire-format field names.

## Run the console milestone

```
./build/rin_console
```

Creates a mesh identity, starts the TCP listener (port 45990, auto-
incrementing) and UDP discovery beacon (port 45991), and drops into a
command prompt. Type `help` for commands. See `DESIGN_NOTES.md` for how
to test this against a real phone.

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

## Layout

```
include/rin/       Public headers (protocol, crypto, transport, mesh_engine, qr_code, win32_shell)
src/                Implementation
tests/              Crypto + protocol + QR wire-format/round-trip tests
third_party/asio/   Vendored standalone Asio (headers only)
DESIGN_NOTES.md     Design decisions, verified vs. assumed, known gaps
```
