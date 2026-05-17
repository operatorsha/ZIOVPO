#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <winsvc.h>

#include <string>

#include "resource.h"
#include "shared.h"

bool SendStopServiceRequest();
long RpcGetCurrentUser(bool& authenticated, std::wstring& login);
long RpcLogin(const std::wstring& login, const std::wstring& password, std::wstring& error);
long RpcLogout();
long RpcGetLicenseStatus(bool& hasLicense, std::wstring& expiresAt, std::wstring& error);
long RpcActivateProduct(const std::wstring& code, std::wstring& error);
long RpcAntivirusPing(std::wstring& error);

namespace {

constexpr wchar_t kWindowClassName[] = L"ZIOVPOPracticeTrayWindow";
constexpr wchar_t kWindowTitle[] = L"ZIOVPO Practice 1";
constexpr wchar_t kMutexName[] = L"Local\\ZIOVPOPractice1TrayAppMutex";
constexpr UINT kTrayIconId = 1;
constexpr UINT kTrayMessage = WM_APP + 1;
constexpr UINT kMenuOpen = 50001;
constexpr UINT kMenuExit = 50002;
constexpr UINT kTimerRefreshState = 1;
constexpr int kLoginEditId = 60001;
constexpr int kPasswordEditId = 60002;
constexpr int kLoginButtonId = 60003;
constexpr int kLogoutButtonId = 60004;
constexpr int kActivationEditId = 60005;
constexpr int kActivationButtonId = 60006;
constexpr int kAvPingButtonId = 60007;

HINSTANCE g_instance = nullptr;
HWND g_main_window = nullptr;
UINT g_taskbar_created_message = 0;
bool g_tray_icon_added = false;
HWND g_status_label = nullptr;
HWND g_login_label = nullptr;
HWND g_login_edit = nullptr;
HWND g_password_label = nullptr;
HWND g_password_edit = nullptr;
HWND g_login_button = nullptr;
HWND g_logout_button = nullptr;
HWND g_license_label = nullptr;
HWND g_activation_label = nullptr;
HWND g_activation_edit = nullptr;
HWND g_activation_button = nullptr;
HWND g_av_status_label = nullptr;
HWND g_av_ping_button = nullptr;
bool g_authenticated = false;
bool g_has_license = false;

std::wstring GetExecutableDirectory() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);

    std::wstring module_path(path);
    const size_t slash = module_path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L".";
    }
    return module_path.substr(0, slash);
}

void PlayWindowOpenSound() {
    const std::wstring sound_path = GetExecutableDirectory() + L"\\open.mp3";
    if (GetFileAttributesW(sound_path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return;
    }

    mciSendStringW(L"close ziovpo_open_sound", nullptr, 0, nullptr);

    const std::wstring open_command =
        L"open \"" + sound_path + L"\" type mpegvideo alias ziovpo_open_sound";
    if (mciSendStringW(open_command.c_str(), nullptr, 0, nullptr) != 0) {
        return;
    }

    mciSendStringW(L"play ziovpo_open_sound from 0", nullptr, 0, nullptr);
}

std::wstring GetWindowTextValue(HWND hwnd) {
    int length = GetWindowTextLengthW(hwnd);
    std::wstring value(static_cast<size_t>(length) + 1, L'\0');
    GetWindowTextW(hwnd, value.data(), length + 1);
    value.resize(static_cast<size_t>(length));
    return value;
}

void SetVisible(HWND hwnd, bool visible) {
    if (hwnd) {
        ShowWindow(hwnd, visible ? SW_SHOW : SW_HIDE);
    }
}

void SetText(HWND hwnd, const std::wstring& text) {
    if (hwnd) {
        SetWindowTextW(hwnd, text.c_str());
    }
}

void RefreshApplicationState() {
    bool authenticated = false;
    std::wstring login;
    long userResult = RpcGetCurrentUser(authenticated, login);

    bool hasLicense = false;
    std::wstring expiresAt;
    std::wstring licenseError;
    long licenseResult = authenticated
        ? RpcGetLicenseStatus(hasLicense, expiresAt, licenseError)
        : ERROR_NOT_LOGGED_ON;

    g_authenticated = authenticated && userResult == 0;
    g_has_license = g_authenticated && hasLicense && licenseResult == 0;

    if (!g_authenticated) {
        SetText(g_status_label, L"Пользователь не аутентифицирован");
        SetText(g_license_label, L"Лицензия недоступна");
        SetText(g_av_status_label, L"Функциональность антивируса заблокирована");
    } else {
        SetText(g_status_label, L"Пользователь: " + login);
        if (g_has_license) {
            SetText(g_license_label, L"Лицензия активна до: " + (expiresAt.empty() ? L"не указано" : expiresAt));
            SetText(g_av_status_label, L"Функциональность антивируса разблокирована");
        } else {
            SetText(g_license_label, L"Лицензия отсутствует" + (licenseError.empty() ? L"" : L": " + licenseError));
            SetText(g_av_status_label, L"Функциональность антивируса заблокирована");
        }
    }

    SetVisible(g_login_label, !g_authenticated);
    SetVisible(g_login_edit, !g_authenticated);
    SetVisible(g_password_label, !g_authenticated);
    SetVisible(g_password_edit, !g_authenticated);
    SetVisible(g_login_button, !g_authenticated);
    SetVisible(g_logout_button, g_authenticated);
    SetVisible(g_license_label, g_authenticated);
    SetVisible(g_activation_label, g_authenticated && !g_has_license);
    SetVisible(g_activation_edit, g_authenticated && !g_has_license);
    SetVisible(g_activation_button, g_authenticated && !g_has_license);
    SetVisible(g_av_status_label, g_authenticated);
    SetVisible(g_av_ping_button, g_authenticated && g_has_license);
}

void HandleLogin() {
    std::wstring error;
    long result = RpcLogin(GetWindowTextValue(g_login_edit), GetWindowTextValue(g_password_edit), error);
    if (result != 0) {
        SetText(g_status_label, L"Ошибка входа: " + (error.empty() ? std::to_wstring(result) : error));
        return;
    }
    SetWindowTextW(g_password_edit, L"");
    RefreshApplicationState();
}

void HandleLogout() {
    RpcLogout();
    g_authenticated = false;
    g_has_license = false;
    RefreshApplicationState();
}

void HandleActivation() {
    std::wstring error;
    long result = RpcActivateProduct(GetWindowTextValue(g_activation_edit), error);
    if (result != 0) {
        SetText(g_license_label, L"Ошибка активации: " + (error.empty() ? std::to_wstring(result) : error));
        return;
    }
    SetWindowTextW(g_activation_edit, L"");
    RefreshApplicationState();
}

void HandleAvPing() {
    std::wstring error;
    long result = RpcAntivirusPing(error);
    if (result == 0) {
        SetText(g_av_status_label, L"Проверка антивирусной функциональности успешна");
    } else {
        SetText(g_av_status_label, L"Антивирус заблокирован: " + (error.empty() ? std::to_wstring(result) : error));
    }
}

DWORD GetParentProcessId() {
    const DWORD current_pid = GetCurrentProcessId();
    DWORD parent_pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == current_pid) {
                parent_pid = entry.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return parent_pid;
}

bool QueryServiceStatus(SC_HANDLE service, SERVICE_STATUS_PROCESS& status) {
    DWORD bytes_needed = 0;
    return QueryServiceStatusEx(
        service,
        SC_STATUS_PROCESS_INFO,
        reinterpret_cast<LPBYTE>(&status),
        sizeof(status),
        &bytes_needed
    ) != FALSE;
}

bool WaitForServiceRunning(SC_HANDLE service) {
    SERVICE_STATUS_PROCESS status{};
    for (int i = 0; i < 60; ++i) {
        if (!QueryServiceStatus(service, status)) {
            return false;
        }
        if (status.dwCurrentState == SERVICE_RUNNING) {
            return true;
        }
        if (status.dwCurrentState == SERVICE_STOPPED) {
            return false;
        }
        Sleep(500);
    }
    return false;
}

bool EnsureServiceContextOrStartAndExit() {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager) {
        return false;
    }

    SC_HANDLE service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(manager);
        return false;
    }

    SERVICE_STATUS_PROCESS status{};
    if (!QueryServiceStatus(service, status)) {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    if (status.dwCurrentState == SERVICE_STOPPED) {
        CloseServiceHandle(service);
        service = OpenServiceW(manager, kServiceName, SERVICE_QUERY_STATUS | SERVICE_START);
        if (service) {
            StartServiceW(service, 0, nullptr);
            WaitForServiceRunning(service);
        }
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    if (status.dwCurrentState != SERVICE_RUNNING) {
        WaitForServiceRunning(service);
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
        return false;
    }

    const DWORD service_pid = status.dwProcessId;
    const DWORD parent_pid = GetParentProcessId();

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    return service_pid != 0 && parent_pid == service_pid;
}

void ShowMainWindow() {
    if (!g_main_window) {
        return;
    }

    ShowWindow(g_main_window, SW_SHOWNORMAL);
    SetForegroundWindow(g_main_window);
    PlayWindowOpenSound();
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
    SendStopServiceRequest();
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
    CreateWindowExW(
        0,
        L"STATIC",
        L"Состояние",
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

    g_status_label = CreateWindowExW(
        0,
        L"STATIC",
        L"Загрузка состояния...",
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

    g_login_label = CreateWindowExW(0, L"STATIC", L"Логин", WS_CHILD | WS_VISIBLE, 20, 90, 80, 24, hwnd, nullptr, g_instance, nullptr);
    g_login_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 110, 88, 220, 26, hwnd, reinterpret_cast<HMENU>(kLoginEditId), g_instance, nullptr);
    g_password_label = CreateWindowExW(0, L"STATIC", L"Пароль", WS_CHILD | WS_VISIBLE, 20, 124, 80, 24, hwnd, nullptr, g_instance, nullptr);
    g_password_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD, 110, 122, 220, 26, hwnd, reinterpret_cast<HMENU>(kPasswordEditId), g_instance, nullptr);
    g_login_button = CreateWindowExW(0, L"BUTTON", L"Войти", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 350, 104, 110, 30, hwnd, reinterpret_cast<HMENU>(kLoginButtonId), g_instance, nullptr);

    g_logout_button = CreateWindowExW(0, L"BUTTON", L"Выйти из аккаунта", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 20, 88, 170, 30, hwnd, reinterpret_cast<HMENU>(kLogoutButtonId), g_instance, nullptr);
    g_license_label = CreateWindowExW(0, L"STATIC", L"Лицензия", WS_CHILD | WS_VISIBLE, 20, 140, 560, 24, hwnd, nullptr, g_instance, nullptr);
    g_activation_label = CreateWindowExW(0, L"STATIC", L"Код активации", WS_CHILD | WS_VISIBLE, 20, 174, 120, 24, hwnd, nullptr, g_instance, nullptr);
    g_activation_edit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_CHILD | WS_VISIBLE | WS_TABSTOP | ES_AUTOHSCROLL, 150, 172, 260, 26, hwnd, reinterpret_cast<HMENU>(kActivationEditId), g_instance, nullptr);
    g_activation_button = CreateWindowExW(0, L"BUTTON", L"Активировать", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 430, 170, 130, 30, hwnd, reinterpret_cast<HMENU>(kActivationButtonId), g_instance, nullptr);

    g_av_status_label = CreateWindowExW(0, L"STATIC", L"Антивирус", WS_CHILD | WS_VISIBLE, 20, 218, 560, 24, hwnd, nullptr, g_instance, nullptr);
    g_av_ping_button = CreateWindowExW(0, L"BUTTON", L"Проверить AV", WS_CHILD | WS_VISIBLE | WS_TABSTOP, 20, 250, 140, 30, hwnd, reinterpret_cast<HMENU>(kAvPingButtonId), g_instance, nullptr);
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT message, WPARAM wparam, LPARAM lparam) {
    if (message == g_taskbar_created_message) {
        AddTrayIcon();
        return 0;
    }

    switch (message) {
    case WM_CREATE:
        AddMainWindowControls(hwnd);
        SetTimer(hwnd, kTimerRefreshState, 15000, nullptr);
        RefreshApplicationState();
        return 0;

    case WM_TIMER:
        if (wparam == kTimerRefreshState) {
            RefreshApplicationState();
        }
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
        case kLoginButtonId:
            HandleLogin();
            return 0;
        case kLogoutButtonId:
            HandleLogout();
            return 0;
        case kActivationButtonId:
            HandleActivation();
            return 0;
        case kAvPingButtonId:
            HandleAvPing();
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
        KillTimer(hwnd, kTimerRefreshState);
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
        360,
        nullptr,
        nullptr,
        g_instance,
        nullptr
    );
}

} // namespace

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, LPWSTR command_line, int show_command) {
    if (!EnsureServiceContextOrStartAndExit()) {
        return 0;
    }

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
        PlayWindowOpenSound();
    }

    MSG message{};
    while (GetMessage(&message, nullptr, 0, 0) > 0) {
        TranslateMessage(&message);
        DispatchMessage(&message);
    }

    CloseHandle(single_instance_mutex);
    return static_cast<int>(message.wParam);
}
