#pragma once
// Camera-based QR scanner for the "Add Device" / join flow.
//
// On Windows: uses WinRT (Windows.Media.Capture.Frames) to grab frames
// from the system's default camera, feeds each frame as a grayscale
// luminance buffer into ZXing's ReadBarcode, and fires the callback the
// moment a valid QR payload is decoded. Stops scanning automatically on
// first successful decode so the user isn't asked to stand still while
// the app processes the same QR a hundred times.
//
// On non-Windows (Linux/macOS): stub that immediately returns false from
// start() -- the console join-paste dialog remains the fallback path.
//
// Why WinRT over DirectShow / Media Foundation directly:
//   - Windows.Media.Capture.Frames is the API Android's CameraX was
//     modelled on conceptually -- both use a FrameReader/ImageReader
//     pattern. Having parallel code structures on both sides makes future
//     maintenance easier to reason about.
//   - WinRT is available on every Windows 10+ machine, which is the
//     project's minimum anyway (WinRT Bluetooth, DPAPI, Shell APIs all
//     assume 10+ already).
//   - The DirectShow alternative is three times the boilerplate for the
//     same result.
//
// Build requirement: Windows SDK 10.0.17763+ and C++/WinRT headers
//   (included with VS 2019+ and via `vcpkg install cppwinrt`).
//   Add `/await` (MSVC) or `-fcoroutines` (clang-cl) to compiler flags.

#ifdef _WIN32

#include <functional>
#include <memory>
#include <string>
#include <atomic>

namespace rin {

// Callback type: called exactly once with the raw decoded string from the
// QR (our join token JSON) when a valid QR code is recognised.
using QrScanCallback = std::function<void(const std::string& decoded_json)>;

class CameraQrScanner {
public:
    CameraQrScanner();
    ~CameraQrScanner();

    // Opens the default camera, starts the frame reader, and begins
    // feeding frames to ZXing. Returns true if the camera was opened
    // successfully; false if no camera is available or initialisation
    // failed (e.g., permission denied). Non-blocking: the actual scanning
    // runs on a background WinRT thread pool thread.
    bool start(QrScanCallback on_decoded);

    // Stops the frame reader and releases the camera. Safe to call even
    // if start() was never called or returned false.
    void stop();

    bool is_running() const { return running_.load(); }

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::atomic<bool> running_{false};
};

}  // namespace rin

#else  // non-Windows stub

#include <functional>
#include <string>

namespace rin {
using QrScanCallback = std::function<void(const std::string&)>;
class CameraQrScanner {
public:
    bool start(QrScanCallback) { return false; }
    void stop() {}
    bool is_running() const { return false; }
};
}  // namespace rin

#endif  // _WIN32
