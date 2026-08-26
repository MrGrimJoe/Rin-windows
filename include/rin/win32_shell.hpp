#pragma once
#ifdef _WIN32

#include <windows.h>
#include <memory>
#include <string>

#include "rin/mesh_engine.hpp"
#include "rin/camera_qr_scanner.hpp"

namespace rin {

class Win32Shell {
public:
    explicit Win32Shell(MeshEngine& engine);
    ~Win32Shell();

    // Blocks until the main window is closed. Returns the WinMain exit code.
    int run(HINSTANCE instance);

private:
    // -- First-launch ----------------------------------------------------
    bool run_first_launch_chooser();
    bool run_join_paste_dialog(HWND parent, std::string& out_json);

    // -- Main window -----------------------------------------------------
    void create_main_window();
    void refresh_device_list();
    void on_add_device_clicked();
    void on_remove_device_clicked();
    void show_qr_window();

    // -- System tray -----------------------------------------------------
    void add_tray_icon();
    void remove_tray_icon();
    void show_tray_context_menu();
    void restore_from_tray();

    // -- WndProcs --------------------------------------------------------
    static LRESULT CALLBACK main_wnd_proc(HWND, UINT, WPARAM, LPARAM);
    static LRESULT CALLBACK qr_wnd_proc(HWND, UINT, WPARAM, LPARAM);
    static INT_PTR CALLBACK chooser_dlg_proc(HWND, UINT, WPARAM, LPARAM);
    static INT_PTR CALLBACK join_paste_dlg_proc(HWND, UINT, WPARAM, LPARAM);

    LRESULT handle_main(HWND, UINT, WPARAM, LPARAM);
    LRESULT handle_qr(HWND, UINT, WPARAM, LPARAM);

    MeshEngine&  engine_;
    HINSTANCE    instance_    = nullptr;
    HWND         main_hwnd_   = nullptr;
    HWND         list_view_   = nullptr;
    HWND         qr_hwnd_     = nullptr;
    HBITMAP      qr_bitmap_   = nullptr;

    std::unique_ptr<CameraQrScanner> camera_scanner_;

    static constexpr UINT kPollTimerId = 1;
};

} // namespace rin

#endif // _WIN32
