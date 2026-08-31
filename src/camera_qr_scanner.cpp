#ifdef _WIN32

// C++/WinRT and Windows SDK headers -- must come before anything that
// might include <windows.h> so the WinRT headers control the include
// order. NOMINMAX prevents the min/max macros from conflicting with
// std::min/std::max used later.
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN

// C++/WinRT coroutine support
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Media.Capture.h>
#include <winrt/Windows.Media.Capture.Frames.h>
#include <winrt/Windows.Graphics.Imaging.h>
#include <winrt/Windows.Devices.Enumeration.h>

// ZXing for QR decode -- same library used in the test suite. Only needed
// for the actual decode step inside start(); everything else here is pure
// WinRT and builds fine without it. RIN_HAVE_ZXING is defined by
// CMakeLists.txt only when ZXing was actually found (it's an optional
// dependency, per the "camera QR scanner disabled" message it prints
// otherwise).
#ifdef RIN_HAVE_ZXING
#include <ZXing/ReadBarcode.h>
#include <ZXing/ImageView.h>
#endif

#include "rin/camera_qr_scanner.hpp"
#include "rin/audit_logger.hpp"

#include <mutex>

using namespace winrt;
using namespace Windows::Media::Capture;
using namespace Windows::Media::Capture::Frames;
using namespace Windows::Graphics::Imaging;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Devices::Enumeration;

namespace rin {

// -----------------------------------------------------------------------
// Pimpl -- keeps WinRT types out of the header (they pull in a LOT of
// Windows SDK and don't play nicely with forward declarations).
// -----------------------------------------------------------------------
struct CameraQrScanner::Impl {
    MediaCapture capture{nullptr};
    MediaFrameReader frame_reader{nullptr};
    QrScanCallback callback;
    std::mutex callback_mutex;
    bool fired = false;  // single-fire guard, matching Android's AtomicBoolean
};

CameraQrScanner::CameraQrScanner() : impl_(std::make_unique<Impl>()) {}

CameraQrScanner::~CameraQrScanner() { stop(); }

#ifdef RIN_HAVE_ZXING
bool CameraQrScanner::start(QrScanCallback on_decoded) {
    if (running_.load()) return true;

    // Initialise the WinRT apartment for this thread.
    // If the calling thread already has an apartment (e.g. the Win32
    // message-loop thread is STA), this is a no-op.
    try {
        winrt::init_apartment();
    } catch (...) {}  // already initialised -- fine

    try {
        {
            std::lock_guard<std::mutex> lk(impl_->callback_mutex);
            impl_->callback = std::move(on_decoded);
            impl_->fired = false;
        }

        // Find the first colour video source from the system's frame source
        // groups -- prefer a camera explicitly tagged as a front/back facing
        // sensor; fall back to the first usable one if no tag is available.
        auto source_groups = MediaFrameSourceGroup::FindAllAsync().get();
        MediaFrameSourceGroup chosen_group{nullptr};
        MediaFrameSourceInfo chosen_info{nullptr};

        for (const auto& group : source_groups) {
            for (const auto& info : group.SourceInfos()) {
                if (info.MediaStreamType() == MediaStreamType::VideoRecord &&
                    info.SourceKind() == MediaFrameSourceKind::Color) {
                    chosen_group = group;
                    chosen_info = info;
                    break;
                }
            }
            if (chosen_group) break;
        }

        if (!chosen_group || !chosen_info) {
            MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                              "CameraQrScanner: no colour camera found -- falling back to manual token paste");
            return false;
        }

        // Initialise MediaCapture against the chosen source group.
        MediaCaptureInitializationSettings settings;
        settings.SourceGroup(chosen_group);
        settings.SharingMode(MediaCaptureSharingMode::SharedReadOnly);
        settings.StreamingCaptureMode(StreamingCaptureMode::Video);
        settings.MemoryPreference(MediaCaptureMemoryPreference::Cpu);  // CPU-accessible for ZXing

        impl_->capture = MediaCapture();
        impl_->capture.InitializeAsync(settings).get();

        // Create a frame reader for the colour source.
        auto source = impl_->capture.FrameSources().Lookup(chosen_info.Id());
        impl_->frame_reader = impl_->capture.CreateFrameReaderAsync(source).get();

        // Register the FrameArrived handler -- fires on a WinRT thread-pool
        // thread, so we guard the single-fire flag and the callback with a mutex.
        impl_->frame_reader.FrameArrived(
            [this](const MediaFrameReader& reader, const MediaFrameArrivedEventArgs&) {
                if (!running_.load()) return;

                {
                    std::lock_guard<std::mutex> lk(impl_->callback_mutex);
                    if (impl_->fired) return;  // already fired, scanner stopped
                }

                // Acquire the latest frame -- TryAcquireLatestFrame() returns
                // null if no frame is ready yet; in that case just return and
                // wait for the next FrameArrived event.
                auto ref = reader.TryAcquireLatestFrame();
                if (!ref) return;

                auto video_frame = ref.VideoMediaFrame();
                if (!video_frame) return;

                auto bitmap = video_frame.SoftwareBitmap();
                if (!bitmap) return;

                // Convert to Bgra8 if it isn't already (ZXing needs a known
                // pixel format; we'll extract luma from Bgra8 manually).
                if (bitmap.BitmapPixelFormat() != BitmapPixelFormat::Bgra8 ||
                    bitmap.BitmapAlphaMode() != BitmapAlphaMode::Premultiplied) {
                    bitmap = SoftwareBitmap::Convert(bitmap, BitmapPixelFormat::Bgra8,
                                                      BitmapAlphaMode::Premultiplied);
                }

                auto buffer = bitmap.LockBuffer(BitmapBufferAccessMode::Read);
                auto ref2 = buffer.CreateReference();
                auto bytes = ref2.data();
                uint32_t byte_count = ref2.Length();
                int width = bitmap.PixelWidth();
                int height = bitmap.PixelHeight();

                // Extract luma (greyscale) from Bgra8 -- ZXing's ImageFormat::Lum
                // expects one byte per pixel. We use the standard BT.601 coefficients
                // that match Android's YUV_420_888 plane-0 luminance extraction.
                std::vector<uint8_t> luma(static_cast<size_t>(width) * height);
                for (int i = 0; i < width * height; ++i) {
                    uint8_t b = bytes[i * 4 + 0];
                    uint8_t g = bytes[i * 4 + 1];
                    uint8_t r = bytes[i * 4 + 2];
                    luma[static_cast<size_t>(i)] =
                        static_cast<uint8_t>((r * 299 + g * 587 + b * 114) / 1000);
                }

                // Decode with ZXing -- same library and same ImageFormat::Lum path
                // as the test suite, which already proved it decodes our QR codes.
                ZXing::ReaderOptions opts;
                opts.setFormats(ZXing::BarcodeFormat::QRCode);
                opts.setTryHarder(true);  // matches Android's DecodeHintType.TRY_HARDER

                auto result = ZXing::ReadBarcode(
                    ZXing::ImageView(luma.data(), width, height, ZXing::ImageFormat::Lum), opts);

                if (result.isValid()) {
                    std::string decoded = result.text();
                    QrScanCallback cb;
                    {
                        std::lock_guard<std::mutex> lk(impl_->callback_mutex);
                        if (impl_->fired) return;
                        impl_->fired = true;
                        cb = impl_->callback;
                    }
                    // Stop the reader *before* firing the callback so any UI
                    // actions taken in the callback (e.g. closing the QR window)
                    // don't race with in-flight frames.
                    running_.store(false);
                    try { reader.StopAsync().get(); } catch (...) {}
                    if (cb) cb(decoded);
                }
            });

        impl_->frame_reader.StartAsync().get();
        running_.store(true);

        MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::Connection,
                                          "Camera QR scanner started -- waiting for a Rin join token");
        return true;

    } catch (const winrt::hresult_error& e) {
        char msg[256];
        std::snprintf(msg, sizeof(msg), "CameraQrScanner::start() WinRT error 0x%08X",
                      static_cast<uint32_t>(e.code()));
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection, msg);
        running_.store(false);
        return false;
    } catch (const std::exception& e) {
        MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                          std::string("CameraQrScanner::start() failed: ") + e.what());
        running_.store(false);
        return false;
    }
}
#else
bool CameraQrScanner::start(QrScanCallback) {
    // Built without ZXing (optional dependency, not found at configure
    // time -- see the "camera QR scanner disabled" message CMakeLists.txt
    // already prints in that case). Camera-based scanning just isn't
    // available in this build; callers fall back to manual token paste.
    MeshAuditLogger::instance().log(AuditLevel::SecurityWarning, AuditCategory::Connection,
                                      "CameraQrScanner: built without ZXing -- camera scanning "
                                      "unavailable, use manual token paste");
    return false;
}
#endif  // RIN_HAVE_ZXING

void CameraQrScanner::stop() {
    if (!running_.exchange(false)) return;
    try {
        if (impl_->frame_reader) {
            impl_->frame_reader.StopAsync().get();
            impl_->frame_reader = nullptr;
        }
        if (impl_->capture) {
            impl_->capture = nullptr;
        }
    } catch (...) {}
    MeshAuditLogger::instance().log(AuditLevel::Info, AuditCategory::Connection,
                                      "Camera QR scanner stopped");
}

}  // namespace rin

#endif  // _WIN32
