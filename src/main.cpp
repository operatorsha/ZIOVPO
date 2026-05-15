#include <windows.h>
#include <shellapi.h>

#include "resource.h"

namespace {

constexpr wchar_t kWindowClassName[] = L"ZIOVPOPracticeTrayWindow";
constexpr wchar_t kWindowTitle[] = L"ZIOVPO Practice 1";
constexpr wchar_t kMutexName[] = L"Local\\ZIOVPOPractice1TrayAppMutex";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kMenuOpen = 50001;
constexpr UINT kMenuExit = 50002;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
UINT g_taskbar_created_message = 0;
bool g_tray_icon_added = false;

void ShowMainWindow() {
    if (!g_main_window) {
        return;
    }

    ShowWindow(g_main_window, SW_SHOWNORMAL);
    SetForegroundWindow(g_main_window);
}

void RemoveTrayIcon() {
    if (!g_main_window || !g_tray_icon_added) {
        return;
    }

    NOTIFYICONDATA nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_main_window;
    nid.uID = kTrayIconId;
    Shell_NotifyIcon(NIM_DELETE, &nid);
    g_tray_icon_added = false;
}

bool AddTrayIcon() {
    if (!g_main_window) {
        return false;
    }

    NOTIFYICONDATA nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = g_main_window;
    nid.uID = kTrayIconId;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = kTrayMessage;
    nid.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wcscpy_s(nid.szTip, L"ZIOVPO Practice 1");

    if (g_tray_icon_added) {
        if (!Shell_NotifyIcon(NIM_MODIFY, &nid) && !Shell_NotifyIcon(NIM_ADD, &nid)) {
            return false;
        }
    } else if (!Shell_NotifyIcon(NIM_ADD, &nid)) {
        return false;
    }

    nid.uVersion = NOTIFYICON_VERSION_4;
    Shell_NotifyIcon(NIM_SETVERSION, &nid);
    g_tray_icon_added = true;
    return true;
}

void ExitApplication() {
    RemoveTrayIcon();
    DestroyWindow(g_main_window);
    PostQuitMessage(0);
}

void ShowTrayMenu(HWND hwnd) {
    POINT cursor{};
    GetCursorPos(&cursor);

    HMENU menu = CreatePopupMenu();
    if (!menu) {
        return;
    }

    AppendMenu(menu, MF_STRING, kMenuOpen, L"Открыть");
    AppendMenu(menu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(menu, MF_STRING, kMenuExit, L"Выход");

    SetForegroundWindow(hwnd);
    TrackPopupMenu(menu, TPM_RIGHTBUTTON, cursor.x, cursor.y, 0, hwnd, nullptr);
    DestroyMenu(menu);
}

void AddMainWindowControls(HWND hwnd) {
    CreateWindowEx(
        0,
        L"STATIC",
        L"Приложение запущено. При закрытии окна оно продолжит работу в фоне.",
        WS_CHILD | WS_VISIBLE,
        20,
        20,
        520,
        24,
        hwnd,
        nullptr,
        g_instance,
        nullptr
    );

    CreateWindowEx(
        0,
        L"STATIC",
        L"Используйте иконку в трее или меню Файл -> Выход для завершения.",
        WS_CHILD | WS_VISIBLE,
        20,
        52,
        520,
        24,
        hwnd,
        nullptr,
        g_instance,
        nullptr
    );
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == g_taskbar_created_message) {
        AddTrayIcon();
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        AddMainWindowControls(hwnd);
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDM_FILE_EXIT:
        case kMenuExit:
            ExitApplication();
            return 0;
        case kMenuOpen:
            ShowMainWindow();
            return 0;
        default:
            return 0;
        }

    case kTrayMessage:
        switch (LOWORD(lparam)) {
        case WM_LBUTTONUP:
            ShowMainWindow();
            return 0;
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowTrayMenu(hwnd);
            return 0;
        default:
            return 0;
        }

    case WM_CLOSE:
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        return 0;

    default:
        return DefWindowProc(hwnd, message, wparam, lparam);
    }
}

bool IsBackgroundMode(LPWSTR command_line) {
    int argc = 0;
    LPWSTR* argv = CommandLineToArgvW(command_line, &argc);
    if (!argv) {
        return false;
    }

    bool background = false;
    for (int i = 1; i < argc; ++i) {
        if (lstrcmpi(argv[i], L"--background") == 0 ||
            lstrcmpi(argv[i], L"--hidden") == 0 ||
            lstrcmpi(argv[i], L"/background") == 0 ||
            lstrcmpi(argv[i], L"/hidden") == 0) {
            background = true;
            break;
        }
    }

    LocalFree(argv);
    return background;
}

bool RegisterMainWindowClass() {
    WNDCLASS wc{};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = g_instance;
    wc.lpszClassName = kWindowClassName;
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
    wc.lpszMenuName = MAKEINTRESOURCE(IDR_MAIN_MENU);

    return RegisterClass(&wc) != 0;
}

HWND CreateMainWindow() {
    return CreateWindowEx(
        0,
        kWindowClassName,
        kWindowTitle,
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        620,
        220,
        nullptr,
        nullptr,
        g_instance,
        nullptr
    );
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR command_line, int show_command) {
    HANDLE single_instance_mutex = CreateMutex(nullptr, TRUE, kMutexName);
    if (!single_instance_mutex) {
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(single_instance_mutex);
        return 0;
    }

    g_instance = instance;
    g_taskbar_created_message = RegisterWindowMessage(L"TaskbarCreated");

    if (!RegisterMainWindowClass()) {
        CloseHandle(single_instance_mutex);
        return 1;
    }

    g_main_window = CreateMainWindow();
    if (!g_main_window) {
        CloseHandle(single_instance_mutex);
        return 1;
    }

    AddTrayIcon();

    if (!IsBackgroundMode(command_line)) {
        ShowWindow(g_main_window, show_command);
        UpdateWindow(g_main_window);
    }

    MSG message{};
    while (GetMessage(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }

    CloseHandle(single_instance_mutex);
    return static_cast<int>(message.wParam);
}
