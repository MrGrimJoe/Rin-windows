#pragma once
// Win32 GUI shell -- the actual "one screen" UI described in the doc's
// §02 (User Experience): a live device list, an Add Device button, and
// a remove action per device. No login screen, no settings maze.
//
// WINDOWS-ONLY. This file is excluded from the CMake build on non-Windows
// platforms (see CMakeLists.txt: rin_gui target is WIN32-gated) because
// it depends on <windows.h>/<commctrl.h>, which don't exist here. The
// console shell (main.cpp / rin_console) remains the cross-platform way
// to exercise MeshEngine directly, including in this Linux sandbox and
// in CI.
//
// Design mirrors doc §02 exactly:
//  - First launch: two choices only, Create a mesh or Join a mesh.
//  - Every time after: one screen, live device list, Add Device button,
//    remove action per device. Nothing else to configure.
//  - Permissions/QR camera access requested contextually -- irrelevant
//    on Windows (no OS permission prompt for local network/camera the
//    way Android has one), but the *contextual* principle carries over:
//    we don't pop the QR/camera window until "Add Device" is clicked.

#ifdef _WIN32

#include <windows.h>

#include <memory>
#include <string>

#include "rin/mesh_engine.hpp"

namespace rin {

class Win32Shell {
public:
    explicit Win32Shell(MeshEngine& engine);
    ~Win32Shell();

    // Runs the first-launch chooser (Create/Join) if no identity exists
    // yet, then shows the main device-list window and pumps the Win32
    // message loop until the window is closed. Blocks until then.
    int run(HINSTANCE instance);

private:
    // -- Window procedures (static trampolines -> instance methods) -----
    static LRESULT CALLBACK main_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    static LRESULT CALLBACK qr_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    static INT_PTR CALLBACK chooser_dlg_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);
    static INT_PTR CALLBACK join_paste_dlg_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

    LRESULT handle_main_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

    // -- First-launch flow ------------------------------------------------
    // Returns true if the user chose to create a mesh, false if they
    // chose to join (matching doc §02's "Two choices only").
    bool run_first_launch_chooser(HINSTANCE instance);

    // -- Main window setup/refresh -----------------------------------
    void create_main_window(HINSTANCE instance);
    void create_device_list_view(HWND parent);
    void refresh_device_list();
    void on_add_device_clicked();
    void on_remove_device_clicked();
    void poll_engine_events();  // timer callback: refresh list + surface new events

    // -- QR display (doc §02's "show/scan QR flow") ------------------
    // Renders build_join_token_json() as a QR bitmap in a small popup
    // window -- the on-screen half of the "Add Device" flow. This build
    // does not yet include camera-based QR *scanning*; see
    // run_join_paste_dialog() for the interim text-paste path, and
    // DESIGN_NOTES.md for what a real scanner needs.
    void show_qr_window(HWND parent);

    // -- Join flow (interim: paste token text instead of camera scan) ---
    // The doc's real flow is "scan the other device's QR with the
    // camera." Implementing an actual camera capture + ZXing decode
    // pipeline is a follow-up (see DESIGN_NOTES.md) -- for now, Add
    // Device on the joining side opens a small dialog to paste in the
    // token JSON (which a phone's Rin app would show as text, or which
    // you transcribe from the QR by hand/phone-to-phone AirDrop-style
    // sharing in the meantime).
    bool run_join_paste_dialog(HWND parent, std::string& out_token_json);

    MeshEngine& engine_;
    HWND main_hwnd_ = nullptr;
    HWND list_view_ = nullptr;
    HWND qr_hwnd_ = nullptr;
    HBITMAP qr_bitmap_ = nullptr;
    UINT_PTR poll_timer_id_ = 1;

    static constexpr UINT kIdListView = 1001;
    static constexpr UINT kIdAddDeviceButton = 1002;
    static constexpr UINT kIdRemoveDeviceButton = 1003;
    static constexpr UINT kIdStatusLabel = 1004;
};

}  // namespace rin

#endif  // _WIN32
