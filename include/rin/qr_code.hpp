#pragma once
// QR code generation for the join-token bootstrap flow (doc §05).
//
// Uses libqrencode (LGPL, available via apt on Linux and vcpkg on
// Windows: `vcpkg install libqrencode`) rather than hand-rolling a QR
// encoder -- this is exactly the kind of well-audited, narrow-purpose
// library the project's "no custom cryptography" philosophy (§07)
// extends naturally to: don't hand-roll a QR encoder either.
//
// This module is platform-agnostic: it produces a plain pixel grid.
// Turning that into something on-screen is the platform shell's job --
// Win32Shell::render_qr_to_window() (win32_shell.cpp, Windows-only)
// converts the QrImage below into a DIB and blits it with StretchDIBits.

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace rin {

// A decoded QR symbol as a square grid of modules (1 = dark/black,
// 0 = light/white), before any scaling for display.
struct QrImage {
    int module_count = 0;              // symbol width/height in modules
    std::vector<uint8_t> modules;      // module_count * module_count, row-major, 0 or 1
};

class QrCodeException : public std::runtime_error {
public:
    explicit QrCodeException(const std::string& message) : std::runtime_error(message) {}
};

class QrCode {
public:
    // Encodes arbitrary UTF-8/binary data (our join tokens are JSON, so
    // this always goes through the 8-bit/binary path, never the
    // alphanumeric-only encodeString path which would mangle JSON's
    // punctuation). Throws QrCodeException if the data is too large for
    // a QR symbol (~2950 bytes at the lowest error-correction level) --
    // callers should check token size well before that in practice.
    static QrImage encode(const std::string& data);

    // Renders a QrImage to a grayscale bitmap, `scale` pixels per module,
    // plus a `quiet_zone_modules`-wide white border (the spec requires a
    // quiet zone for scanners to reliably find the finder patterns --
    // don't render at scale 1 with zero border, mobile cameras won't
    // decode it reliably at typical screen distances).
    // Output: row-major, 1 byte per pixel, 0 = black, 255 = white.
    static std::vector<uint8_t> render_grayscale(const QrImage& qr, int scale = 8,
                                                  int quiet_zone_modules = 4, int* out_width = nullptr,
                                                  int* out_height = nullptr);

    // Convenience: encode + render in one call, writing a standard
    // grayscale BMP file to disk. Useful for testing without a GUI, and
    // as a fallback "save QR as image" path in the Windows shell.
    static void save_as_bmp(const std::string& data, const std::string& file_path, int scale = 8);
};

}  // namespace rin
