// QR code tests.
//
// The most important test here is the round-trip via ZXing (an
// INDEPENDENT decoder, not our own encoder read backwards) -- proving
// this produces an actually-scannable QR code, not just "code that
// compiles and produces some pixels." ZXing is the same decoder family
// underlying most real-world QR scanning (including phone camera apps),
// so a successful decode here is a meaningful signal, not a tautology.

#include "rin/qr_code.hpp"
#include "rin/protocol.hpp"

#ifdef RIN_HAVE_ZXING
#include <ZXing/ImageView.h>
#include <ZXing/ReadBarcode.h>
#endif

#include <iostream>

using namespace rin;

namespace {
int g_failures = 0;

void check(bool condition, const std::string& name) {
    if (condition) {
        std::cout << "  [PASS] " << name << "\n";
    } else {
        std::cout << "  [FAIL] " << name << "\n";
        g_failures++;
    }
}
}  // namespace

void run_qr_tests() {
    std::cout << "\n== QR code tests ==\n";

    // -- Basic encode produces a plausible grid -----------------------
    {
        QrImage qr = QrCode::encode("hello rin");
        check(qr.module_count > 0, "encode produces a non-empty module grid");
        check(qr.modules.size() == static_cast<size_t>(qr.module_count) * qr.module_count,
              "module buffer size matches module_count^2");
    }

    // -- Round-trip through an INDEPENDENT decoder (ZXing), when available --
#ifdef RIN_HAVE_ZXING
    {
        QrJoinToken token;
        token.mesh_name = "Ali's Devices";
        token.host_public_key =
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1huj6IRXTiozlpP9DF5VadLRi1ZvEbxFjxyx0HV3y0oL80vaV/"
            "dRMgwUymQI0NJRETSAYf4ik8un3LtcLzAC9A==";
        token.host_device_name = "Windows PC";
        token.ephemeral_token = "rin_join_f34cd27a303890f33421763764bf3dff";
        token.mesh_secret = "3e07b30678a7c874c2120968595c3e0cd19a7a59ad01b24ddf3fa1e76423a176";
        token.host_port = 45990;
        token.host_ip = "192.168.1.42";
        token.timestamp_ms = 1787296698077;

        std::string json = token.to_json();

        int width = 0, height = 0;
        QrImage qr = QrCode::encode(json);
        std::vector<uint8_t> gray = QrCode::render_grayscale(qr, 6, 4, &width, &height);

        ZXing::ImageView view(gray.data(), width, height, ZXing::ImageFormat::Lum);
        ZXing::ReaderOptions options;
        options.setFormats(ZXing::BarcodeFormat::QRCode);
        ZXing::Result result = ZXing::ReadBarcode(view, options);

        check(result.isValid(), "an independent decoder (ZXing) successfully reads the generated QR");
        if (result.isValid()) {
            check(result.text() == json,
                  "decoded content is byte-for-byte identical to the original join token JSON");

            auto reparsed = QrJoinToken::from_json(result.text());
            check(reparsed.has_value(), "content decoded off a QR image still parses as a valid QrJoinToken");
            if (reparsed.has_value()) {
                check(reparsed->host_ip.has_value() && *reparsed->host_ip == "192.168.1.42",
                      "fields survive the full pipeline: token -> JSON -> QR -> decode -> parse");
            }
        }
    }
#else
    std::cout << "  [SKIP] ZXing round-trip decode test (libzxing-dev not found at configure time)\n";
#endif

    // -- Larger payload (a real token with a long public key) still fits --
    {
        std::string large_payload(600, 'x');  // bigger than a typical token to check headroom
        bool threw = false;
        QrImage qr;
        try {
            qr = QrCode::encode(large_payload);
        } catch (const QrCodeException&) {
            threw = true;
        }
        check(!threw && qr.module_count > 0, "a 600-byte payload (larger than a typical join token) still encodes");
    }

    // -- Rendering respects requested scale ------------------------------
    {
        QrImage qr = QrCode::encode("scale test");
        int w1 = 0, h1 = 0, w2 = 0, h2 = 0;
        QrCode::render_grayscale(qr, 4, 4, &w1, &h1);
        QrCode::render_grayscale(qr, 8, 4, &w2, &h2);
        check(w2 == w1 * 2 && h2 == h1 * 2, "doubling scale doubles the rendered pixel dimensions");
    }

    std::cout << (g_failures == 0 ? "All QR tests passed.\n" : "SOME QR TESTS FAILED.\n");
}

int g_qr_test_failures() { return g_failures; }
