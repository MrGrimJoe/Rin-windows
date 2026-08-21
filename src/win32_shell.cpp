#ifdef _WIN32

#include "rin/win32_shell.hpp"

#include <commctrl.h>

#include <sstream>

#include "rin/qr_code.hpp"

#pragma comment(lib, "comctl32.lib")

namespace rin {

namespace {
constexpr wchar_t kMainClassName[] = L"RinMainWindow";
constexpr wchar_t kQrClassName[] = L"RinQrWindow";

// Global pointer used by the static WndProc trampolines to reach the
// instance. Fine here: this app opens exactly one main window and one
// QR popup at a time, matching the doc's "one screen" design -- there is
// no multi-window case to disambiguate.
Win32Shell* g_shell_instance = nullptr;

std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return L"";
    int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(len), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), len);
    return result;
}

std::string to_utf8(const std::wstring& s) {
    if (s.empty()) return "";
    int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0,
                                   nullptr, nullptr);
    std::string result(static_cast<size_t>(len), '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), result.data(), len,
                         nullptr, nullptr);
    return result;
}

const wchar_t* platform_label(PlatformType p) {
    switch (p) {
        case PlatformType::Android: return L"Android";
        case PlatformType::Windows: return L"Windows";
        case PlatformType::Linux: return L"Linux";
        case PlatformType::MacOS: return L"macOS";
        case PlatformType::Tablet: return L"Tablet";
    }
    return L"Unknown";
}

const wchar_t* state_label(ConnectionState s) {
    switch (s) {
        case ConnectionState::Connected: return L"Connected";
        case ConnectionState::Active: return L"Active (this device)";
        case ConnectionState::Reconnecting: return L"Reconnecting...";
        case ConnectionState::Idle: return L"Idle";
        case ConnectionState::Offline: return L"Offline";
        case ConnectionState::Lost: return L"Lost";
        case ConnectionState::Discovered: return L"Discovered";
        case ConnectionState::Authenticating: return L"Authenticating...";
    }
    return L"?";
}

// Converts a QrImage to a Win32 DIB section HBITMAP for display. Kept
// here rather than in qr_code.cpp since HBITMAP is a Win32-specific
// concept -- qr_code.cpp/hpp stay platform-agnostic (they're also linked
// into rin_console, which builds on Linux).
HBITMAP qr_to_hbitmap(const std::string& token_json, int scale) {
    QrImage qr = QrCode::encode(token_json);
    int width = 0, height = 0;
    std::vector<uint8_t> gray = QrCode::render_grayscale(qr, scale, 4, &width, &height);

    BITMAPINFO bmi{};
    bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
    bmi.bmiHeader.biWidth = width;
    bmi.bmiHeader.biHeight = -height;  // negative = top-down DIB, matches our row-major top-to-bottom buffer
    bmi.bmiHeader.biPlanes = 1;
    bmi.bmiHeader.biBitCount = 32;
    bmi.bmiHeader.biCompression = BI_RGB;

    void* bits = nullptr;
    HDC screen_dc = GetDC(nullptr);
    HBITMAP bitmap = CreateDIBSection(screen_dc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
    ReleaseDC(nullptr, screen_dc);
    if (!bitmap || !bits) return nullptr;

    auto* pixels = static_cast<uint32_t*>(bits);
    for (int i = 0; i < width * height; ++i) {
        uint8_t v = gray[static_cast<size_t>(i)];
        pixels[i] = (0xFFu << 24) | (v << 16) | (v << 8) | v;  // opaque grayscale BGRA
    }

    return bitmap;
}
}  // namespace

Win32Shell::Win32Shell(MeshEngine& engine) : engine_(engine) { g_shell_instance = this; }

Win32Shell::~Win32Shell() {
    if (qr_bitmap_) DeleteObject(qr_bitmap_);
    g_shell_instance = nullptr;
}

int Win32Shell::run(HINSTANCE instance) {
    INITCOMMONCONTROLSEX icc{sizeof(icc), ICC_LISTVIEW_CLASSES | ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    // Doc §02: "First launch -- starting a mesh. Two choices only." This
    // engine is created fresh (no persisted identity yet -- see
    // DESIGN_NOTES.md on the missing persistence layer), so every run of
    // this shell currently hits the first-launch path. Once identity
    // persistence exists, this should branch on "does a saved identity
    // exist" rather than always chooser-ing.
    bool created = run_first_launch_chooser(instance);
    if (!created) {
        // run_first_launch_chooser's Join path collects a token and calls
        // complete_join_handshake itself before returning false; either
        // way, by this point identity_ exists (either fresh mesh or
        // adopted via join) and it's safe to show the main window.
    }

    create_main_window(instance);
    if (!main_hwnd_) return 1;

    ShowWindow(main_hwnd_, SW_SHOW);
    UpdateWindow(main_hwnd_);

    // Poll the engine every second for newly discovered peers / state
    // changes and refresh the list view -- MeshEngine's callbacks fire
    // on background transport threads (see transport.cpp), and touching
    // Win32 UI controls off the UI thread is unsafe, so this timer-based
    // poll from the UI thread is the simple, correct approach here
    // rather than PostMessage-ing from the transport threads.
    poll_timer_id_ = SetTimer(main_hwnd_, 1, 1000, nullptr);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    KillTimer(main_hwnd_, poll_timer_id_);
    return static_cast<int>(msg.wParam);
}

bool Win32Shell::run_first_launch_chooser(HINSTANCE instance) {
    // A simple two-button MessageBox-style chooser stands in for a
    // dedicated dialog resource (.rc file) -- functionally identical to
    // doc §02's "Two choices only: Create a mesh or Join a mesh," without
    // requiring a resource compiler step for this milestone. Swap for a
    // proper DialogBox + .rc template when polishing the visuals.
    int result = MessageBoxW(nullptr,
                              L"Welcome to Rin.\n\nYes = Create a new mesh\nNo = Join an existing mesh",
                              L"Rin Setup", MB_YESNO | MB_ICONQUESTION);

    if (result == IDYES) {
        std::wstring mesh_name_w(128, L'\0');
        std::wstring device_name_w(128, L'\0');

        // Doc §02: user types a name (e.g. "Ali's Devices"). A real build
        // should use a proper input dialog; for this milestone we reuse
        // the join-paste dialog's text-entry pattern via a tiny inline
        // prompt through GetWindowText on an edit control created here.
        // Kept simple: default names, matching the console shell's
        // blank-input defaults, with a chance to rename later once
        // settings/rename UI exists.
        engine_.create_initial_mesh("My Mesh", "Windows PC");
        engine_.start();
        return true;
    } else {
        std::string token_json;
        HWND temp_owner = nullptr;
        bool got_token = run_join_paste_dialog(temp_owner, token_json);

        // Need an identity to join WITH, even before we've adopted the
        // host's mesh -- create_initial_mesh gives us the local keypair
        // the join handshake signs with. The mesh_name gets overwritten
        // by whatever's in the scanned token once complete_join_handshake
        // runs, mirroring Android's join flow.
        engine_.create_initial_mesh("Joining...", "Windows PC");
        engine_.start();

        if (got_token) {
            auto token = QrJoinToken::from_json(token_json);
            if (token.has_value()) {
                engine_.complete_join_handshake(*token);
            } else {
                MessageBoxW(nullptr, L"Could not parse the pasted token JSON.", L"Rin", MB_ICONERROR);
            }
        }
        return false;
    }
}

void Win32Shell::create_main_window(HINSTANCE instance) {
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &Win32Shell::main_wnd_proc;
    wc.hInstance = instance;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kMainClassName;
    RegisterClassExW(&wc);

    std::wstring title = to_wstring(std::string("Rin - ") + engine_.identity().mesh_name);

    main_hwnd_ = CreateWindowExW(0, kMainClassName, title.c_str(), WS_OVERLAPPEDWINDOW, CW_USEDEFAULT,
                                  CW_USEDEFAULT, 480, 420, nullptr, nullptr, instance, nullptr);

    create_device_list_view(main_hwnd_);

    CreateWindowExW(0, L"BUTTON", L"Add Device", WS_CHILD | WS_VISIBLE, 10, 320, 130, 32, main_hwnd_,
                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdAddDeviceButton)), instance,
                     nullptr);
    CreateWindowExW(0, L"BUTTON", L"Remove Selected", WS_CHILD | WS_VISIBLE, 150, 320, 140, 32,
                     main_hwnd_, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdRemoveDeviceButton)),
                     instance, nullptr);
    CreateWindowExW(0, L"STATIC", L"", WS_CHILD | WS_VISIBLE, 10, 360, 440, 20, main_hwnd_,
                     reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdStatusLabel)), instance, nullptr);

    refresh_device_list();
}

void Win32Shell::create_device_list_view(HWND parent) {
    list_view_ = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, L"",
                                  WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL, 10, 10, 440, 300,
                                  parent, reinterpret_cast<HMENU>(static_cast<INT_PTR>(kIdListView)),
                                  GetModuleHandle(nullptr), nullptr);
    ListView_SetExtendedListViewStyle(list_view_, LVS_EX_FULLROWSELECT);

    LVCOLUMNW col{};
    col.mask = LVCF_TEXT | LVCF_WIDTH;

    col.pszText = const_cast<wchar_t*>(L"Device");
    col.cx = 160;
    ListView_InsertColumn(list_view_, 0, &col);

    col.pszText = const_cast<wchar_t*>(L"Platform");
    col.cx = 90;
    ListView_InsertColumn(list_view_, 1, &col);

    col.pszText = const_cast<wchar_t*>(L"Status");
    col.cx = 130;
    ListView_InsertColumn(list_view_, 2, &col);

    col.pszText = const_cast<wchar_t*>(L"Address");
    col.cx = 150;
    ListView_InsertColumn(list_view_, 3, &col);
}

void Win32Shell::refresh_device_list() {
    if (!list_view_) return;

    // Doc §02: "Opening the app shows the live device list -- who's
    // currently reachable, who's not." Full rebuild each poll tick is
    // simple and correct at mesh sizes this app targets (a handful of
    // personal devices, not hundreds) -- no need for incremental diffing.
    ListView_DeleteAllItems(list_view_);

    auto devices = engine_.trusted_devices();
    int index = 0;
    for (const auto& device : devices) {
        std::wstring name = to_wstring(device.name);

        LVITEMW item{};
        item.mask = LVIF_TEXT;
        item.iItem = index;
        item.pszText = const_cast<wchar_t*>(name.c_str());
        ListView_InsertItem(list_view_, &item);

        ListView_SetItemText(list_view_, index, 1, const_cast<wchar_t*>(platform_label(device.platform)));
        ListView_SetItemText(list_view_, index, 2, const_cast<wchar_t*>(state_label(device.connection_state)));

        std::wstring address = device.ip_address.has_value()
                                    ? to_wstring(*device.ip_address + ":" + std::to_string(device.port))
                                    : L"-";
        ListView_SetItemText(list_view_, index, 3, const_cast<wchar_t*>(address.c_str()));

        index++;
    }

    HWND status = GetDlgItem(main_hwnd_, kIdStatusLabel);
    if (status) {
        auto events = engine_.recent_events(1);
        std::wstring text = events.empty() ? L"" : to_wstring(events.back().message);
        SetWindowTextW(status, text.c_str());
    }
}

void Win32Shell::poll_engine_events() { refresh_device_list(); }

void Win32Shell::on_add_device_clicked() { show_qr_window(main_hwnd_); }

void Win32Shell::on_remove_device_clicked() {
    int selected = ListView_GetNextItem(list_view_, -1, LVNI_SELECTED);
    if (selected < 0) return;

    auto devices = engine_.trusted_devices();
    if (selected >= static_cast<int>(devices.size())) return;
    const auto& device = devices[static_cast<size_t>(selected)];
    if (device.is_self) {
        MessageBoxW(main_hwnd_, L"You can't remove this device (it's this PC).", L"Rin", MB_ICONWARNING);
        return;
    }

    // Doc §02: "Removing a device is one tap ... the removed device is
    // dropped instantly and the rest of the mesh is unaffected." Matches
    // MeshEngine::revoke_device, which signs+broadcasts a revocation
    // packet before dropping the local trust entry.
    engine_.revoke_device(device.public_key);
    refresh_device_list();
}

void Win32Shell::show_qr_window(HWND parent) {
    std::string token_json = engine_.build_join_token_json();

    if (qr_bitmap_) {
        DeleteObject(qr_bitmap_);
        qr_bitmap_ = nullptr;
    }

    try {
        qr_bitmap_ = qr_to_hbitmap(token_json, 6);
    } catch (const QrCodeException& e) {
        MessageBoxA(parent, e.what(), "Rin - QR generation failed", MB_ICONERROR);
        return;
    }
    if (!qr_bitmap_) {
        MessageBoxW(parent, L"Failed to render QR bitmap.", L"Rin", MB_ICONERROR);
        return;
    }

    BITMAP bmp_info;
    GetObject(qr_bitmap_, sizeof(bmp_info), &bmp_info);
    int window_w = bmp_info.bmWidth + 40;
    int window_h = bmp_info.bmHeight + 90;

    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = &Win32Shell::qr_wnd_proc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(GetStockObject(WHITE_BRUSH));
    wc.lpszClassName = kQrClassName;
    RegisterClassExW(&wc);  // benign if already registered from a prior Add Device click

    qr_hwnd_ = CreateWindowExW(WS_EX_DLGMODALFRAME, kQrClassName, L"Rin - Add Device",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
                                window_w, window_h, parent, nullptr, GetModuleHandle(nullptr), nullptr);

    CreateWindowExW(0, L"STATIC",
                     L"Scan this with the Rin app on the other device, "
                     L"or use 'Join a mesh' there and paste the token shown on that device here.",
                     WS_CHILD | WS_VISIBLE | SS_CENTER, 10, bmp_info.bmHeight + 20, window_w - 20, 50,
                     qr_hwnd_, nullptr, GetModuleHandle(nullptr), nullptr);

    ShowWindow(qr_hwnd_, SW_SHOW);
    UpdateWindow(qr_hwnd_);
}

bool Win32Shell::run_join_paste_dialog(HWND parent, std::string& out_token_json) {
    // Interim text-paste flow -- see the header doc comment and
    // DESIGN_NOTES.md. A minimal modal window with a multi-line edit box
    // and OK/Cancel, built directly rather than via a .rc dialog
    // template to avoid needing a resource compiler for this milestone.
    static std::string* s_result_ptr = nullptr;
    static bool s_confirmed = false;
    out_token_json.clear();
    s_result_ptr = &out_token_json;
    s_confirmed = false;

    constexpr wchar_t kClassName[] = L"RinJoinPasteDialog";
    WNDCLASSEXW wc{};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = DefWindowProcW;  // real control handling done via WM_COMMAND below through a subclass in a fuller build
    wc.hInstance = GetModuleHandle(nullptr);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszClassName = kClassName;
    RegisterClassExW(&wc);

    HWND dlg = CreateWindowExW(WS_EX_DLGMODALFRAME, kClassName, L"Rin - Join a Mesh",
                                WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU, CW_USEDEFAULT, CW_USEDEFAULT,
                                420, 260, parent, nullptr, GetModuleHandle(nullptr), nullptr);

    CreateWindowExW(0, L"STATIC",
                     L"Paste the join token JSON shown on the other device's 'Add Device' screen:",
                     WS_CHILD | WS_VISIBLE, 10, 10, 390, 40, dlg, nullptr, GetModuleHandle(nullptr),
                     nullptr);

    HWND edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                 WS_CHILD | WS_VISIBLE | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL, 10,
                                 55, 390, 130, dlg, nullptr, GetModuleHandle(nullptr), nullptr);

    HWND ok_button =
        CreateWindowExW(0, L"BUTTON", L"Join", WS_CHILD | WS_VISIBLE, 230, 195, 80, 30, dlg,
                         reinterpret_cast<HMENU>(1), GetModuleHandle(nullptr), nullptr);
    HWND cancel_button =
        CreateWindowExW(0, L"BUTTON", L"Cancel", WS_CHILD | WS_VISIBLE, 320, 195, 80, 30, dlg,
                         reinterpret_cast<HMENU>(2), GetModuleHandle(nullptr), nullptr);

    ShowWindow(dlg, SW_SHOW);

    // Simple nested modal loop -- acceptable for a single blocking dialog
    // in an otherwise single-window app; a larger app should use a real
    // DialogBox for proper modal semantics (disabling the parent, tab
    // order, Esc-to-cancel, etc., all of which a full .rc-based dialog
    // gets for free).
    MSG msg;
    bool done = false;
    while (!done && GetMessage(&msg, nullptr, 0, 0)) {
        if (msg.hwnd == dlg || IsChild(dlg, msg.hwnd)) {
            if (msg.message == WM_COMMAND) {
                WORD id = LOWORD(msg.wParam);
                if (id == 1) {  // Join
                    int len = GetWindowTextLengthW(edit);
                    std::wstring buffer(static_cast<size_t>(len) + 1, L'\0');
                    GetWindowTextW(edit, buffer.data(), len + 1);
                    buffer.resize(static_cast<size_t>(len));
                    out_token_json = to_utf8(buffer);
                    s_confirmed = true;
                    done = true;
                } else if (id == 2) {  // Cancel
                    done = true;
                }
            } else if (msg.message == WM_CLOSE || msg.message == WM_DESTROY) {
                done = true;
            }
        }
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    DestroyWindow(dlg);
    return s_confirmed && !out_token_json.empty();
}

LRESULT CALLBACK Win32Shell::qr_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    Win32Shell* self = g_shell_instance;

    switch (msg) {
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            if (self && self->qr_bitmap_) {
                HDC mem_dc = CreateCompatibleDC(hdc);
                HBITMAP old = static_cast<HBITMAP>(SelectObject(mem_dc, self->qr_bitmap_));
                BITMAP bmp_info;
                GetObject(self->qr_bitmap_, sizeof(bmp_info), &bmp_info);
                BitBlt(hdc, 20, 10, bmp_info.bmWidth, bmp_info.bmHeight, mem_dc, 0, 0, SRCCOPY);
                SelectObject(mem_dc, old);
                DeleteDC(mem_dc);
            }
            EndPaint(hwnd, &ps);
            return 0;
        }
        case WM_CLOSE:
            DestroyWindow(hwnd);
            if (self) self->qr_hwnd_ = nullptr;
            return 0;
        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

LRESULT CALLBACK Win32Shell::main_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    Win32Shell* self = g_shell_instance;
    if (self) return self->handle_main_message(hwnd, msg, wparam, lparam);
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

LRESULT Win32Shell::handle_main_message(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    switch (msg) {
        case WM_TIMER:
            if (wparam == poll_timer_id_) poll_engine_events();
            return 0;

        case WM_COMMAND: {
            UINT id = LOWORD(wparam);
            if (id == kIdAddDeviceButton) {
                on_add_device_clicked();
            } else if (id == kIdRemoveDeviceButton) {
                on_remove_device_clicked();
            }
            return 0;
        }

        case WM_DESTROY:
            engine_.stop();
            PostQuitMessage(0);
            return 0;

        default:
            return DefWindowProcW(hwnd, msg, wparam, lparam);
    }
}

INT_PTR CALLBACK Win32Shell::chooser_dlg_proc(HWND, UINT, WPARAM, LPARAM) {
    // Reserved for a future proper dialog-resource-based chooser;
    // run_first_launch_chooser() currently uses MessageBoxW instead. Kept
    // as a declared-but-unused hook so the header's shape doesn't need
    // to change when this gets built out.
    return FALSE;
}

INT_PTR CALLBACK Win32Shell::join_paste_dlg_proc(HWND, UINT, WPARAM, LPARAM) { return FALSE; }

}  // namespace rin

#endif  // _WIN32
