#ifdef _WIN32

#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commctrl.h>
#include <shellapi.h>

#include "rin/win32_shell.hpp"
#include "rin/camera_qr_scanner.hpp"
#include "rin/qr_code.hpp"

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")

namespace rin {

namespace {

// -----------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------
constexpr wchar_t kMainClassName[]  = L"RinWindowsMain";
constexpr wchar_t kQrClassName[]    = L"RinWindowsQr";
constexpr wchar_t kAppName[]        = L"Rin Windows";
constexpr UINT    kTrayIconId       = 1;
constexpr UINT    kTrayCallbackMsg  = WM_APP + 1;
constexpr UINT    kIdListView       = 1001;
constexpr UINT    kIdAddBtn         = 1002;
constexpr UINT    kIdRemoveBtn      = 1003;
constexpr UINT    kIdStatusLabel    = 1004;
constexpr UINT    kMenuShow         = 2001;
constexpr UINT    kMenuQuit         = 2002;

// WM_TASKBARCREATED: re-add the tray icon if Explorer restarts.
static UINT WM_TASKBARCREATED = 0;

// Global instance pointer for static WndProc trampolines.
Win32Shell* g_shell = nullptr;

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------
std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring r(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n);
    return r;
}
std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
    std::string r(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), r.data(), n, nullptr, nullptr);
    return r;
}

const wchar_t* platform_label(PlatformType p) {
    switch (p) {
        case PlatformType::Android: return L"Android";
        case PlatformType::Windows: return L"Windows";
        case PlatformType::Linux:   return L"Linux";
        case PlatformType::MacOS:   return L"macOS";
        case PlatformType::Tablet:  return L"Tablet";
    }
    return L"Unknown";
}
const wchar_t* state_label(ConnectionState s) {
    switch (s) {
        case ConnectionState::Connected:     return L"Connected";
        case ConnectionState::Active:        return L"This device";
        case ConnectionState::Reconnecting:  return L"Reconnecting…";
        case ConnectionState::Idle:          return L"Idle";
        case ConnectionState::Offline:       return L"Offline";
        case ConnectionState::Lost:          return L"Lost";
        case ConnectionState::Discovered:    return L"Discovered";
        case ConnectionState::Authenticating:return L"Authenticating…";
    }
    return L"?";
}

HBITMAP qr_to_hbitmap(const std::string& json, int scale) {
    try {
        QrImage qr = QrCode::encode(json);
        int w = 0, h = 0;
        auto gray = QrCode::render_grayscale(qr, scale, 4, &w, &h);

        BITMAPINFO bmi{};
        bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth       = w;
        bmi.bmiHeader.biHeight      = -h;   // top-down
        bmi.bmiHeader.biPlanes      = 1;
        bmi.bmiHeader.biBitCount    = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        void* bits = nullptr;
        HDC screen = GetDC(nullptr);
        HBITMAP bmp = CreateDIBSection(screen, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
        ReleaseDC(nullptr, screen);
        if (!bmp || !bits) return nullptr;

        auto* px = static_cast<uint32_t*>(bits);
        for (int i = 0; i < w * h; ++i) {
            uint8_t v = gray[(size_t)i];
            px[i] = (0xFFu << 24) | ((uint32_t)v << 16) | ((uint32_t)v << 8) | v;
        }
        return bmp;
    } catch (...) { return nullptr; }
}

} // anonymous namespace

// -----------------------------------------------------------------------
// Construction / destruction
// -----------------------------------------------------------------------
Win32Shell::Win32Shell(MeshEngine& engine)
    : engine_(engine)
    , camera_scanner_(std::make_unique<CameraQrScanner>())
{
    g_shell = this;
    WM_TASKBARCREATED = RegisterWindowMessageW(L"TaskbarCreated");
}

Win32Shell::~Win32Shell() {
    remove_tray_icon();
    if (qr_bitmap_) DeleteObject(qr_bitmap_);
    g_shell = nullptr;
}

// -----------------------------------------------------------------------
// run() -- entry point called from WinMain
// -----------------------------------------------------------------------
int Win32Shell::run(HINSTANCE instance) {
    instance_ = instance;

    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES };
    InitCommonControlsEx(&icc);

    // Attempt to load a saved identity. If none exists, show the first-launch
    // chooser (Create / Join). Either way engine_.start() is called before
    // the main window is shown.
    bool loaded = engine_.try_load_persisted();
    if (!loaded) {
        if (!run_first_launch_chooser()) return 0;
    }
    engine_.start();

    create_main_window();
    if (!main_hwnd_) return 1;
    add_tray_icon();

    // Refresh device list every second via a WM_TIMER.
    SetTimer(main_hwnd_, kPollTimerId, 1000, nullptr);

    ShowWindow(main_hwnd_, SW_SHOW);
    UpdateWindow(main_hwnd_);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    camera_scanner_->stop();
    KillTimer(main_hwnd_, kPollTimerId);
    return (int)msg.wParam;
}

// -----------------------------------------------------------------------
// First-launch chooser
// -----------------------------------------------------------------------
bool Win32Shell::run_first_launch_chooser() {
    int choice = MessageBoxW(nullptr,
        L"Welcome to Rin Windows.\n\n"
        L"Yes  \u2014 Create a new mesh\n"
        L"No   \u2014 Join an existing mesh",
        kAppName, MB_YESNOCANCEL | MB_ICONQUESTION);

    if (choice == IDCANCEL) return false;

    if (choice == IDYES) {
        // Simple input dialogs via a tiny helper window are omitted here
        // for brevity; the default names match the console shell's defaults.
        engine_.create_initial_mesh("My Mesh", "Windows PC");
        return true;
    }

    // Join path: try camera first, fall back to paste dialog.
    std::string token_json;
    bool got_token = false;

    // Show a "scanning…" message while we try the camera.
    MessageBoxW(nullptr,
        L"Point the camera at the Rin QR code shown on your other device.\n"
        L"Click OK to open the scanner, or Cancel to enter the token manually.",
        kAppName, MB_OKCANCEL | MB_ICONINFORMATION);

    // Camera scanner result arrives on a background thread; we use a simple
    // blocking wait via a local message loop for the first-launch case.
    bool camera_done = false;
    bool camera_ok   = camera_scanner_->start([&](const std::string& decoded) {
        token_json   = decoded;
        got_token    = true;
        camera_done  = true;
        PostMessageW(nullptr, WM_APP + 10, 0, 0);   // wake the local loop below
    });

    if (camera_ok) {
        // Tiny modal loop: pump messages until the camera fires or the user
        // presses a key / closes a notional cancel button.
        HWND wait_dlg = CreateWindowExW(0, L"STATIC",
            L"Scanning for QR code — press Escape to cancel",
            WS_POPUP | WS_BORDER | WS_VISIBLE,
            CW_USEDEFAULT, CW_USEDEFAULT, 340, 60,
            nullptr, nullptr, instance_, nullptr);

        MSG msg;
        while (!camera_done && GetMessage(&msg, nullptr, 0, 0)) {
            if (msg.message == WM_KEYDOWN && msg.wParam == VK_ESCAPE) break;
            if (msg.message == WM_APP + 10) { camera_done = true; break; }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        if (wait_dlg) DestroyWindow(wait_dlg);
        camera_scanner_->stop();
    }

    // Fall back to paste dialog if camera wasn't available or scan was cancelled.
    if (!got_token) got_token = run_join_paste_dialog(nullptr, token_json);

    if (!got_token || token_json.empty()) {
        // Still no token -- create a placeholder mesh so the app isn't
        // completely broken; user can retry the join later via Add Device.
        engine_.create_initial_mesh("Joining…", "Windows PC");
        return true;
    }

    engine_.create_initial_mesh("Joining…", "Windows PC");

    auto token = QrJoinToken::from_json(token_json);
    if (token.has_value()) {
        engine_.complete_join_handshake(*token);
    } else {
        MessageBoxW(nullptr, L"Could not parse the join token.", kAppName, MB_ICONERROR);
    }
    return true;
}

// -----------------------------------------------------------------------
// Main window
// -----------------------------------------------------------------------
void Win32Shell::create_main_window() {
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = main_wnd_proc;
    wc.hInstance     = instance_;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kMainClassName;
    // Use the first icon from the executable if one is embedded, otherwise
    // fall back to the generic application icon.
    wc.hIcon = ExtractIconW(instance_, nullptr, 0);
    if (!wc.hIcon) wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = wc.hIcon;
    RegisterClassExW(&wc);

    std::wstring title = std::wstring(kAppName) + L" \u2014 " +
                         to_wstring(engine_.identity().mesh_name);

    main_hwnd_ = CreateWindowExW(0, kMainClassName, title.c_str(),
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 520, 440,
        nullptr, nullptr, instance_, nullptr);

    if (!main_hwnd_) return;

    // ListView (device list)
    list_view_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
        WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL,
        10, 10, 480, 300, main_hwnd_,
        (HMENU)(INT_PTR)kIdListView, instance_, nullptr);
    ListView_SetExtendedListViewStyle(list_view_, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);

    auto add_col = [&](int idx, const wchar_t* name, int cx) {
        LVCOLUMNW c{};
        c.mask = LVCF_TEXT | LVCF_WIDTH;
        c.pszText = const_cast<wchar_t*>(name);
        c.cx = cx;
        ListView_InsertColumn(list_view_, idx, &c);
    };
    add_col(0, L"Device",    180);
    add_col(1, L"Platform",   90);
    add_col(2, L"Status",    130);
    add_col(3, L"Address",   160);

    CreateWindowExW(0, L"BUTTON", L"Add Device",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        10, 320, 130, 30, main_hwnd_,
        (HMENU)(INT_PTR)kIdAddBtn, instance_, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Remove",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
        150, 320, 100, 30, main_hwnd_,
        (HMENU)(INT_PTR)kIdRemoveBtn, instance_, nullptr);

    CreateWindowExW(0, L"STATIC", L"",
        WS_CHILD | WS_VISIBLE,
        10, 360, 480, 20, main_hwnd_,
        (HMENU)(INT_PTR)kIdStatusLabel, instance_, nullptr);

    refresh_device_list();
}

void Win32Shell::refresh_device_list() {
    if (!list_view_) return;
    ListView_DeleteAllItems(list_view_);

    int idx = 0;
    for (const auto& d : engine_.trusted_devices()) {
        LVITEMW item{};
        item.mask  = LVIF_TEXT;
        item.iItem = idx;
        auto name  = to_wstring(d.name);
        item.pszText = const_cast<wchar_t*>(name.c_str());
        ListView_InsertItem(list_view_, &item);

        ListView_SetItemText(list_view_, idx, 1, const_cast<wchar_t*>(platform_label(d.platform)));
        ListView_SetItemText(list_view_, idx, 2, const_cast<wchar_t*>(state_label(d.connection_state)));

        std::wstring addr = d.ip_address.has_value()
            ? to_wstring(*d.ip_address + ":" + std::to_string(d.port))
            : L"—";
        ListView_SetItemText(list_view_, idx, 3, const_cast<wchar_t*>(addr.c_str()));
        idx++;
    }

    // Status bar: most recent audit event.
    if (HWND status = GetDlgItem(main_hwnd_, kIdStatusLabel)) {
        auto events = engine_.recent_events(1);
        SetWindowTextW(status, events.empty() ? L"" : to_wstring(events.back().message).c_str());
    }
}

// -----------------------------------------------------------------------
// Add Device flow (QR display + camera scan)
// -----------------------------------------------------------------------
void Win32Shell::on_add_device_clicked() {
    // Show this device's QR so another device can scan it.
    show_qr_window();

    // Simultaneously start scanning for the other device's QR, in case they
    // clicked "Add Device" too and are showing their own QR.
    if (!camera_scanner_->is_running()) {
        camera_scanner_->start([this](const std::string& decoded) {
            // Fired on a background thread -- PostMessage to reach the UI thread.
            std::string* heap = new std::string(decoded);
            PostMessageW(main_hwnd_, WM_APP + 20, 0, (LPARAM)heap);
        });
    }
}

void Win32Shell::show_qr_window() {
    if (qr_bitmap_) { DeleteObject(qr_bitmap_); qr_bitmap_ = nullptr; }

    std::string token_json = engine_.build_join_token_json();
    qr_bitmap_ = qr_to_hbitmap(token_json, 6);
    if (!qr_bitmap_) {
        MessageBoxW(main_hwnd_, L"Could not generate QR code.", kAppName, MB_ICONERROR);
        return;
    }

    BITMAP binfo;
    GetObject(qr_bitmap_, sizeof(binfo), &binfo);
    int ww = binfo.bmWidth + 40;
    int wh = binfo.bmHeight + 80;

    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = qr_wnd_proc;
    wc.hInstance     = instance_;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)GetStockObject(WHITE_BRUSH);
    wc.lpszClassName = kQrClassName;
    RegisterClassExW(&wc);

    qr_hwnd_ = CreateWindowExW(WS_EX_DLGMODALFRAME, kQrClassName,
        L"Rin Windows — Add Device",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, ww, wh,
        main_hwnd_, nullptr, instance_, nullptr);

    CreateWindowExW(0, L"STATIC",
        L"Scan this on your other device's Rin app",
        WS_CHILD | WS_VISIBLE | SS_CENTER,
        10, binfo.bmHeight + 16, ww - 20, 30,
        qr_hwnd_, nullptr, instance_, nullptr);

    ShowWindow(qr_hwnd_, SW_SHOW);
    UpdateWindow(qr_hwnd_);
}

void Win32Shell::on_remove_device_clicked() {
    int sel = ListView_GetNextItem(list_view_, -1, LVNI_SELECTED);
    if (sel < 0) return;

    auto devices = engine_.trusted_devices();
    if (sel >= (int)devices.size()) return;
    const auto& d = devices[(size_t)sel];
    if (d.is_self) {
        MessageBoxW(main_hwnd_, L"You can't remove this device (it's this PC).",
                    kAppName, MB_ICONWARNING);
        return;
    }

    std::wstring prompt = L"Remove \"" + to_wstring(d.name) + L"\" from the mesh?";
    if (MessageBoxW(main_hwnd_, prompt.c_str(), kAppName, MB_YESNO | MB_ICONQUESTION) != IDYES)
        return;

    engine_.revoke_device(d.public_key);
    refresh_device_list();
}

// -----------------------------------------------------------------------
// Join via paste (fallback when camera is unavailable)
// -----------------------------------------------------------------------
bool Win32Shell::run_join_paste_dialog(HWND parent, std::string& out_json) {
    static std::string* s_result = nullptr;
    static bool s_ok = false;
    s_result = &out_json;
    s_ok = false;

    constexpr wchar_t kCls[] = L"RinJoinPasteDlg";
    WNDCLASSEXW wc{};
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = DefWindowProcW;
    wc.hInstance     = instance_;
    wc.hCursor       = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = kCls;
    RegisterClassExW(&wc);

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, kCls,
        L"Rin Windows — Join a Mesh",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
        CW_USEDEFAULT, CW_USEDEFAULT, 440, 260, parent, nullptr, instance_, nullptr);

    CreateWindowExW(0, L"STATIC",
        L"Paste the join token JSON shown on the other device:",
        WS_CHILD | WS_VISIBLE,
        10, 10, 410, 36, dlg, nullptr, instance_, nullptr);

    HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
        10, 52, 410, 130, dlg, nullptr, instance_, nullptr);

    CreateWindowExW(0, L"BUTTON", L"Join", WS_CHILD | WS_VISIBLE,
        240, 196, 80, 28, dlg, (HMENU)1, instance_, nullptr);
    CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE,
        330, 196, 80, 28, dlg, (HMENU)2, instance_, nullptr);

    ShowWindow(dlg, SW_SHOW);

    MSG msg;
    bool done = false;
    while (!done && GetMessage(&msg, nullptr, 0, 0)) {
        if ((msg.hwnd == dlg || IsChild(dlg, msg.hwnd))) {
            if (msg.message == WM_COMMAND) {
                WORD id = LOWORD(msg.wParam);
                if (id == 1) {
                    int len = GetWindowTextLengthW(edit);
                    std::wstring buf(len + 1, L'\0');
                    GetWindowTextW(edit, buf.data(), len + 1);
                    buf.resize(len);
                    out_json = to_utf8(buf);
                    s_ok = true;
                    done = true;
                } else if (id == 2) { done = true; }
            }
            if (msg.message == WM_CLOSE) done = true;
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    DestroyWindow(dlg);
    return s_ok && !out_json.empty();
}

// -----------------------------------------------------------------------
// System tray
// -----------------------------------------------------------------------
void Win32Shell::add_tray_icon() {
    NOTIFYICONDATAW nid{};
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = main_hwnd_;
    nid.uID              = kTrayIconId;
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.uCallbackMessage = kTrayCallbackMsg;
    nid.hIcon            = LoadIcon(nullptr, IDI_APPLICATION);
    wcsncpy_s(nid.szTip, kAppName, _TRUNCATE);
    Shell_NotifyIconW(NIM_ADD, &nid);

    // Use NOTIFYICON_VERSION_4 for better taskbar behaviour on Win7+.
    nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIconW(NIM_SETVERSION, &nid);
}

void Win32Shell::remove_tray_icon() {
    if (!main_hwnd_) return;
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd   = main_hwnd_;
    nid.uID    = kTrayIconId;
    Shell_NotifyIconW(NIM_DELETE, &nid);
}

void Win32Shell::show_tray_context_menu() {
    HMENU menu = CreatePopupMenu();
    AppendMenuW(menu, MF_STRING, kMenuShow, L"Show Rin Windows");
    AppendMenuW(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenuW(menu, MF_STRING, kMenuQuit, L"Quit");
    SetMenuDefaultItem(menu, kMenuShow, FALSE);

    // GetCursorPos required for TrackPopupMenu to work correctly.
    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(main_hwnd_);     // required to dismiss the menu on click-away
    TrackPopupMenuEx(menu, TPM_RIGHTBUTTON | TPM_BOTTOMALIGN | TPM_LEFTALIGN,
                     pt.x, pt.y, main_hwnd_, nullptr);
    DestroyMenu(menu);
}

void Win32Shell::restore_from_tray() {
    ShowWindow(main_hwnd_, SW_RESTORE);
    SetForegroundWindow(main_hwnd_);
}

// -----------------------------------------------------------------------
// WndProcs (static trampolines)
// -----------------------------------------------------------------------
LRESULT CALLBACK Win32Shell::main_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (g_shell) return g_shell->handle_main(hwnd, msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}
LRESULT CALLBACK Win32Shell::qr_wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    if (g_shell) return g_shell->handle_qr(hwnd, msg, wp, lp);
    return DefWindowProcW(hwnd, msg, wp, lp);
}

LRESULT Win32Shell::handle_main(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    // Re-add tray icon if Explorer restarted.
    if (msg == WM_TASKBARCREATED) { add_tray_icon(); return 0; }

    switch (msg) {
    case WM_TIMER:
        if (wp == kPollTimerId) refresh_device_list();
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case kIdAddBtn:    on_add_device_clicked();  break;
        case kIdRemoveBtn: on_remove_device_clicked(); break;
        case kMenuShow:    restore_from_tray();       break;
        case kMenuQuit:
            remove_tray_icon();
            engine_.stop();
            DestroyWindow(hwnd);
            break;
        }
        return 0;

    // Tray icon callback message.
    case WM_APP + 1:
        switch (LOWORD(lp)) {
        case NIN_SELECT:           // left single-click
        case NIN_KEYSELECT:        // keyboard activation
            restore_from_tray();
            break;
        case WM_CONTEXTMENU:       // right-click
            show_tray_context_menu();
            break;
        }
        return 0;

    // Camera decoder result arrives on a background thread; it posted
    // WM_APP+20 with a heap-allocated std::string as LPARAM.
    case WM_APP + 20: {
        auto* decoded = reinterpret_cast<std::string*>(lp);
        if (decoded) {
            auto token = QrJoinToken::from_json(*decoded);
            if (token.has_value()) {
                engine_.complete_join_handshake(*token);
                if (qr_hwnd_) { DestroyWindow(qr_hwnd_); qr_hwnd_ = nullptr; }
                MessageBoxW(hwnd, L"Joined successfully!", kAppName, MB_ICONINFORMATION);
            } else {
                MessageBoxW(hwnd, L"Scanned QR is not a valid Rin join token.",
                            kAppName, MB_ICONWARNING);
            }
            delete decoded;
        }
        return 0;
    }

    case WM_CLOSE:
        // Minimise to tray instead of quitting.
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        remove_tray_icon();
        PostQuitMessage(0);
        return 0;

    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

LRESULT Win32Shell::handle_qr(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_PAINT: {
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(hwnd, &ps);
        if (qr_bitmap_) {
            HDC mem = CreateCompatibleDC(hdc);
            HBITMAP old = (HBITMAP)SelectObject(mem, qr_bitmap_);
            BITMAP b;
            GetObject(qr_bitmap_, sizeof(b), &b);
            BitBlt(hdc, 20, 10, b.bmWidth, b.bmHeight, mem, 0, 0, SRCCOPY);
            SelectObject(mem, old);
            DeleteDC(mem);
        }
        EndPaint(hwnd, &ps);
        return 0;
    }
    case WM_CLOSE:
        camera_scanner_->stop();
        DestroyWindow(hwnd);
        qr_hwnd_ = nullptr;
        return 0;
    default:
        return DefWindowProcW(hwnd, msg, wp, lp);
    }
}

// -----------------------------------------------------------------------
// Stub implementations for unused dialog procs declared in header
// -----------------------------------------------------------------------
INT_PTR CALLBACK Win32Shell::chooser_dlg_proc(HWND, UINT, WPARAM, LPARAM) { return FALSE; }
INT_PTR CALLBACK Win32Shell::join_paste_dlg_proc(HWND, UINT, WPARAM, LPARAM) { return FALSE; }

} // namespace rin

#endif // _WIN32
