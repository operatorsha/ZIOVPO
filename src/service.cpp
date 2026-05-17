#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <winhttp.h>
#include <wtsapi32.h>
#include <rpc.h>

#include <algorithm>
#include <malloc.h>
#include <fstream>
#include <chrono>
#include <cwctype>
#include <string>
#include <thread>
#include <vector>

#include "shared.h"

extern "C" {
#include "tray_rpc_h.h"
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size);
extern "C" void __RPC_USER midl_user_free(void* pointer);

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
CRITICAL_SECTION g_process_lock;
CRITICAL_SECTION g_auth_lock;
std::vector<PROCESS_INFORMATION> g_tray_processes;
HANDLE g_refresh_thread = nullptr;

struct AuthState {
    bool authenticated = false;
    std::wstring login;
    std::wstring accessToken;
    std::wstring refreshToken;
    ULONGLONG nextTokenRefreshTick = 0;

    bool hasLicense = false;
    std::wstring licenseTicket;
    std::wstring licenseExpiresAt;
    ULONGLONG nextLicenseRefreshTick = 0;
};

AuthState g_auth;

std::wstring GetCurrentDirectoryForModule();

constexpr wchar_t kDemoLogin[] = L"test";
constexpr wchar_t kDemoPassword[] = L"test";
constexpr wchar_t kDemoActivationCode[] = L"DEMO-KEY";
constexpr wchar_t kDemoExpiredActivationCode[] = L"EXPIRED-KEY";
constexpr wchar_t kDemoBlockedActivationCode[] = L"BLOCKED-KEY";
constexpr wchar_t kDemoAccessToken[] = L"demo-access-token";
constexpr wchar_t kDemoRefreshToken[] = L"demo-refresh-token";
constexpr wchar_t kDemoLicenseTicket[] = L"demo-license-ticket";
constexpr wchar_t kDemoLicenseExpiresAt[] = L"2026-12-31T23:59:59Z";

PSECURITY_DESCRIPTOR CreateProtectedProcessSecurityDescriptor() {
    PSECURITY_DESCRIPTOR security_descriptor = nullptr;
    constexpr wchar_t kProtectedProcessSddl[] =
        L"D:P"
        L"(A;;GA;;;SY)"
        L"(A;;GA;;;BA)"
        L"(A;;GR;;;IU)"
        L"(A;;GR;;;BU)";

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            kProtectedProcessSddl,
            SDDL_REVISION_1,
            &security_descriptor,
            nullptr)) {
        return nullptr;
    }

    return security_descriptor;
}

void ApplyProtectedDaclToCurrentProcess() {
    PSECURITY_DESCRIPTOR security_descriptor = CreateProtectedProcessSecurityDescriptor();
    if (!security_descriptor) {
        return;
    }

    PACL dacl = nullptr;
    BOOL dacl_present = FALSE;
    BOOL dacl_defaulted = FALSE;
    if (GetSecurityDescriptorDacl(security_descriptor, &dacl_present, &dacl, &dacl_defaulted) &&
        dacl_present) {
        SetSecurityInfo(
            GetCurrentProcess(),
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            nullptr,
            nullptr,
            dacl,
            nullptr
        );
    }

    LocalFree(security_descriptor);
}

void WriteLog(const std::wstring& message) {
    const std::wstring log_path = GetCurrentDirectoryForModule() + L"\\ZIOVPOService.log";
    std::wofstream log(log_path.c_str(), std::ios::app);
    if (!log) {
        return;
    }

    SYSTEMTIME now{};
    GetLocalTime(&now);
    log << L"["
        << now.wYear << L"-" << now.wMonth << L"-" << now.wDay << L" "
        << now.wHour << L":" << now.wMinute << L":" << now.wSecond << L"] "
        << message << L"\n";
}

void WriteLastErrorLog(const std::wstring& operation) {
    WriteLog(operation + L" failed, error=" + std::to_wstring(GetLastError()));
}

std::wstring GetEnvOrDefault(const wchar_t* name, const wchar_t* fallback) {
    wchar_t buffer[2048]{};
    DWORD length = GetEnvironmentVariableW(name, buffer, static_cast<DWORD>(_countof(buffer)));
    if (length == 0 || length >= _countof(buffer)) {
        return fallback;
    }
    return buffer;
}

std::string ToUtf8(const std::wstring& value) {
    if (value.empty()) {
        return {};
    }
    int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string result(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, result.data(), size, nullptr, nullptr);
    return result;
}

std::wstring FromUtf8(const std::string& value) {
    if (value.empty()) {
        return {};
    }
    int size = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0);
    std::wstring result(static_cast<size_t>(size), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), result.data(), size);
    return result;
}

std::wstring JsonEscape(const std::wstring& value) {
    std::wstring escaped;
    for (wchar_t ch : value) {
        switch (ch) {
        case L'\\':
            escaped += L"\\\\";
            break;
        case L'"':
            escaped += L"\\\"";
            break;
        case L'\n':
            escaped += L"\\n";
            break;
        case L'\r':
            escaped += L"\\r";
            break;
        case L'\t':
            escaped += L"\\t";
            break;
        default:
            escaped += ch;
            break;
        }
    }
    return escaped;
}

std::wstring ExtractJsonString(const std::wstring& json, const std::wstring& key) {
    const std::wstring marker = L"\"" + key + L"\"";
    size_t pos = json.find(marker);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) {
        return {};
    }
    pos = json.find(L'"', pos);
    if (pos == std::wstring::npos) {
        return {};
    }
    ++pos;

    std::wstring result;
    bool escape = false;
    for (; pos < json.size(); ++pos) {
        wchar_t ch = json[pos];
        if (escape) {
            result += ch;
            escape = false;
            continue;
        }
        if (ch == L'\\') {
            escape = true;
            continue;
        }
        if (ch == L'"') {
            break;
        }
        result += ch;
    }
    return result;
}

long ExtractJsonLong(const std::wstring& json, const std::wstring& key, long fallback) {
    const std::wstring marker = L"\"" + key + L"\"";
    size_t pos = json.find(marker);
    if (pos == std::wstring::npos) {
        return fallback;
    }
    pos = json.find(L':', pos);
    if (pos == std::wstring::npos) {
        return fallback;
    }
    ++pos;
    while (pos < json.size() && iswspace(json[pos])) {
        ++pos;
    }
    wchar_t* end = nullptr;
    long value = wcstol(json.c_str() + pos, &end, 10);
    return end == json.c_str() + pos ? fallback : value;
}

ULONGLONG DelayFromSeconds(long seconds, long fallbackSeconds) {
    long effective = seconds > 30 ? seconds - 30 : fallbackSeconds;
    return GetTickCount64() + static_cast<ULONGLONG>(effective) * 1000ULL;
}

bool HttpRequestJson(
    const std::wstring& method,
    const std::wstring& path,
    const std::wstring& body,
    const std::wstring& bearerToken,
    DWORD& statusCode,
    std::wstring& response) {
    response.clear();
    statusCode = 0;

    const std::wstring baseUrl = GetEnvOrDefault(L"ZIOVPO_API_BASE_URL", L"https://localhost:8443");
    const std::wstring fullUrl = baseUrl + path;

    URL_COMPONENTSW url{};
    wchar_t host[256]{};
    wchar_t urlPath[2048]{};
    url.dwStructSize = sizeof(url);
    url.lpszHostName = host;
    url.dwHostNameLength = static_cast<DWORD>(_countof(host));
    url.lpszUrlPath = urlPath;
    url.dwUrlPathLength = static_cast<DWORD>(_countof(urlPath));

    if (!WinHttpCrackUrl(fullUrl.c_str(), 0, 0, &url)) {
        WriteLastErrorLog(L"WinHttpCrackUrl");
        return false;
    }

    HINTERNET session = WinHttpOpen(
        L"ZIOVPOService/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );
    if (!session) {
        WriteLastErrorLog(L"WinHttpOpen");
        return false;
    }

    HINTERNET connection = WinHttpConnect(session, std::wstring(host, url.dwHostNameLength).c_str(), url.nPort, 0);
    if (!connection) {
        WriteLastErrorLog(L"WinHttpConnect");
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD flags = url.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET request = WinHttpOpenRequest(
        connection,
        method.c_str(),
        std::wstring(urlPath, url.dwUrlPathLength).c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags
    );
    if (!request) {
        WriteLastErrorLog(L"WinHttpOpenRequest");
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    std::wstring headers = L"Content-Type: application/json\r\nAccept: application/json\r\n";
    if (!bearerToken.empty()) {
        headers += L"Authorization: Bearer " + bearerToken + L"\r\n";
    }

    std::string utf8Body = ToUtf8(body);
    BOOL sent = WinHttpSendRequest(
        request,
        headers.c_str(),
        static_cast<DWORD>(headers.size()),
        utf8Body.empty() ? WINHTTP_NO_REQUEST_DATA : utf8Body.data(),
        static_cast<DWORD>(utf8Body.size()),
        static_cast<DWORD>(utf8Body.size()),
        0
    );
    if (!sent || !WinHttpReceiveResponse(request, nullptr)) {
        WriteLastErrorLog(L"WinHTTP request");
        WinHttpCloseHandle(request);
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return false;
    }

    DWORD statusSize = sizeof(statusCode);
    WinHttpQueryHeaders(
        request,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &statusSize,
        WINHTTP_NO_HEADER_INDEX
    );

    std::string responseBytes;
    DWORD available = 0;
    while (WinHttpQueryDataAvailable(request, &available) && available > 0) {
        std::string buffer(available, '\0');
        DWORD read = 0;
        if (!WinHttpReadData(request, buffer.data(), available, &read)) {
            break;
        }
        buffer.resize(read);
        responseBytes += buffer;
    }

    response = FromUtf8(responseBytes);
    WinHttpCloseHandle(request);
    WinHttpCloseHandle(connection);
    WinHttpCloseHandle(session);
    return true;
}

void ClearAuthState() {
    EnterCriticalSection(&g_auth_lock);
    g_auth = AuthState{};
    LeaveCriticalSection(&g_auth_lock);
}

bool IsDemoAccessToken(const std::wstring& accessToken) {
    return accessToken == kDemoAccessToken;
}

bool IsDemoRefreshToken(const std::wstring& refreshToken) {
    return refreshToken == kDemoRefreshToken;
}

void SetDemoAuthenticatedUser() {
    EnterCriticalSection(&g_auth_lock);
    g_auth.authenticated = true;
    g_auth.login = kDemoLogin;
    g_auth.accessToken = kDemoAccessToken;
    g_auth.refreshToken = kDemoRefreshToken;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(120, 120);
    g_auth.hasLicense = false;
    g_auth.licenseTicket.clear();
    g_auth.licenseExpiresAt.clear();
    g_auth.nextLicenseRefreshTick = 0;
    LeaveCriticalSection(&g_auth_lock);
}

long TryDemoAuthenticate(const std::wstring& login, const std::wstring& password, std::wstring& error) {
    if (login != kDemoLogin || password != kDemoPassword) {
        error = L"Invalid login or password";
        return ERROR_LOGON_FAILURE;
    }

    SetDemoAuthenticatedUser();
    error.clear();
    return 0;
}

long AuthenticateUser(const std::wstring& login, const std::wstring& password, std::wstring& error) {
    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_LOGIN_PATH", L"/api/auth/login");
    const std::wstring body =
        L"{\"login\":\"" + JsonEscape(login) + L"\",\"password\":\"" + JsonEscape(password) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, L"", status, response) || status < 200 || status >= 300) {
        long demoResult = TryDemoAuthenticate(login, password, error);
        if (demoResult == 0) {
            WriteLog(L"Using built-in demo authentication fallback");
            return 0;
        }

        error = !response.empty() ? response : error;
        return status ? static_cast<long>(status) : demoResult;
    }

    std::wstring access = ExtractJsonString(response, L"accessToken");
    std::wstring refresh = ExtractJsonString(response, L"refreshToken");
    std::wstring displayLogin = ExtractJsonString(response, L"login");
    if (displayLogin.empty()) {
        displayLogin = ExtractJsonString(response, L"email");
    }
    if (displayLogin.empty()) {
        displayLogin = login;
    }
    if (access.empty() || refresh.empty()) {
        error = L"Authentication response does not contain JWT tokens";
        return ERROR_INVALID_DATA;
    }

    EnterCriticalSection(&g_auth_lock);
    g_auth.authenticated = true;
    g_auth.login = displayLogin;
    g_auth.accessToken = access;
    g_auth.refreshToken = refresh;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"accessExpiresIn", 600), 600);
    g_auth.hasLicense = false;
    g_auth.licenseTicket.clear();
    g_auth.licenseExpiresAt.clear();
    g_auth.nextLicenseRefreshTick = 0;
    LeaveCriticalSection(&g_auth_lock);

    error.clear();
    return 0;
}

long RefreshTokens() {
    std::wstring refreshToken;
    EnterCriticalSection(&g_auth_lock);
    refreshToken = g_auth.refreshToken;
    LeaveCriticalSection(&g_auth_lock);
    if (refreshToken.empty()) {
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoRefreshToken(refreshToken)) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.accessToken = kDemoAccessToken;
        g_auth.refreshToken = kDemoRefreshToken;
        g_auth.nextTokenRefreshTick = DelayFromSeconds(120, 120);
        LeaveCriticalSection(&g_auth_lock);
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_REFRESH_PATH", L"/api/auth/refresh");
    const std::wstring body = L"{\"refreshToken\":\"" + JsonEscape(refreshToken) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, L"", status, response) || status < 200 || status >= 300) {
        ClearAuthState();
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring access = ExtractJsonString(response, L"accessToken");
    std::wstring refresh = ExtractJsonString(response, L"refreshToken");
    if (access.empty() || refresh.empty()) {
        ClearAuthState();
        return ERROR_INVALID_DATA;
    }

    EnterCriticalSection(&g_auth_lock);
    g_auth.accessToken = access;
    g_auth.refreshToken = refresh;
    g_auth.nextTokenRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"accessExpiresIn", 600), 600);
    LeaveCriticalSection(&g_auth_lock);
    return 0;
}

long QueryLicenseStatus(std::wstring& error) {
    std::wstring accessToken;
    EnterCriticalSection(&g_auth_lock);
    accessToken = g_auth.accessToken;
    LeaveCriticalSection(&g_auth_lock);
    if (accessToken.empty()) {
        error = L"User is not authenticated";
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoAccessToken(accessToken)) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.nextLicenseRefreshTick = g_auth.hasLicense ? DelayFromSeconds(120, 120) : 0;
        LeaveCriticalSection(&g_auth_lock);
        error.clear();
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_LICENSE_STATUS_PATH", L"/api/license/status");
    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"GET", path, L"", accessToken, status, response) || status < 200 || status >= 300) {
        error = !response.empty() ? response : L"License status request failed";
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring ticket = ExtractJsonString(response, L"ticket");
    std::wstring expiresAt = ExtractJsonString(response, L"expiresAt");
    bool hasLicense = !ticket.empty() || ExtractJsonLong(response, L"hasLicense", 0) != 0;

    EnterCriticalSection(&g_auth_lock);
    g_auth.hasLicense = hasLicense;
    g_auth.licenseTicket = ticket;
    g_auth.licenseExpiresAt = expiresAt;
    g_auth.nextLicenseRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"licenseExpiresIn", 300), 300);
    LeaveCriticalSection(&g_auth_lock);

    error.clear();
    return 0;
}

long ActivateLicense(const std::wstring& code, std::wstring& error) {
    std::wstring accessToken;
    EnterCriticalSection(&g_auth_lock);
    accessToken = g_auth.accessToken;
    LeaveCriticalSection(&g_auth_lock);
    if (accessToken.empty()) {
        error = L"User is not authenticated";
        return ERROR_NOT_LOGGED_ON;
    }
    if (IsDemoAccessToken(accessToken)) {
        if (code == kDemoExpiredActivationCode || code == kDemoBlockedActivationCode) {
            EnterCriticalSection(&g_auth_lock);
            g_auth.hasLicense = false;
            g_auth.licenseTicket.clear();
            g_auth.licenseExpiresAt.clear();
            g_auth.nextLicenseRefreshTick = 0;
            LeaveCriticalSection(&g_auth_lock);
            error = code == kDemoExpiredActivationCode
                ? L"License expired on server"
                : L"License blocked on server";
            return ERROR_NOT_READY;
        }

        if (code != kDemoActivationCode) {
            error = L"Invalid activation code";
            return ERROR_INVALID_DATA;
        }

        EnterCriticalSection(&g_auth_lock);
        g_auth.hasLicense = true;
        g_auth.licenseTicket = kDemoLicenseTicket;
        g_auth.licenseExpiresAt = kDemoLicenseExpiresAt;
        g_auth.nextLicenseRefreshTick = DelayFromSeconds(120, 120);
        LeaveCriticalSection(&g_auth_lock);
        error.clear();
        return 0;
    }

    const std::wstring path = GetEnvOrDefault(L"ZIOVPO_ACTIVATE_PATH", L"/api/license/activate");
    const std::wstring body = L"{\"activationCode\":\"" + JsonEscape(code) + L"\"}";

    DWORD status = 0;
    std::wstring response;
    if (!HttpRequestJson(L"POST", path, body, accessToken, status, response) || status < 200 || status >= 300) {
        error = !response.empty() ? response : L"Activation request failed";
        return static_cast<long>(status ? status : ERROR_NOT_CONNECTED);
    }

    std::wstring ticket = ExtractJsonString(response, L"ticket");
    std::wstring expiresAt = ExtractJsonString(response, L"expiresAt");
    if (!ticket.empty()) {
        EnterCriticalSection(&g_auth_lock);
        g_auth.hasLicense = true;
        g_auth.licenseTicket = ticket;
        g_auth.licenseExpiresAt = expiresAt;
        g_auth.nextLicenseRefreshTick = DelayFromSeconds(ExtractJsonLong(response, L"licenseExpiresIn", 300), 300);
        LeaveCriticalSection(&g_auth_lock);
        error.clear();
        return 0;
    }

    return QueryLicenseStatus(error);
}

DWORD WINAPI RefreshThreadProc(void*) {
    while (WaitForSingleObject(g_stop_event, 1000) == WAIT_TIMEOUT) {
        ULONGLONG now = GetTickCount64();
        bool refreshTokens = false;
        bool refreshLicense = false;

        EnterCriticalSection(&g_auth_lock);
        refreshTokens = g_auth.authenticated &&
            g_auth.nextTokenRefreshTick != 0 &&
            now >= g_auth.nextTokenRefreshTick;
        refreshLicense = g_auth.authenticated &&
            g_auth.hasLicense &&
            g_auth.nextLicenseRefreshTick != 0 &&
            now >= g_auth.nextLicenseRefreshTick;
        LeaveCriticalSection(&g_auth_lock);

        if (refreshTokens) {
            RefreshTokens();
        }
        if (refreshLicense) {
            std::wstring ignored;
            QueryLicenseStatus(ignored);
        }
    }
    return 0;
}

wchar_t* RpcCopyString(const std::wstring& value) {
    size_t bytes = (value.size() + 1) * sizeof(wchar_t);
    wchar_t* copy = static_cast<wchar_t*>(midl_user_allocate(bytes));
    if (!copy) {
        return nullptr;
    }
    wcscpy_s(copy, value.size() + 1, value.c_str());
    return copy;
}

void SetServiceState(DWORD state, DWORD win32_exit_code = NO_ERROR, DWORD wait_hint = 0) {
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = win32_exit_code;
    g_status.dwWaitHint = wait_hint;
    g_status.dwControlsAccepted = state == SERVICE_RUNNING ? SERVICE_ACCEPT_SESSIONCHANGE : 0;
    SetServiceStatus(g_status_handle, &g_status);
}

std::wstring GetCurrentDirectoryForModule() {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring module_path(path);
    const size_t slash = module_path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) {
        return L".";
    }
    return module_path.substr(0, slash);
}

std::wstring Quote(const std::wstring& value) {
    return L"\"" + value + L"\"";
}

bool IsProcessRunning(const PROCESS_INFORMATION& process) {
    return WaitForSingleObject(process.hProcess, 0) == WAIT_TIMEOUT;
}

void CloseProcessInfo(PROCESS_INFORMATION& process) {
    if (process.hThread) {
        CloseHandle(process.hThread);
        process.hThread = nullptr;
    }
    if (process.hProcess) {
        CloseHandle(process.hProcess);
        process.hProcess = nullptr;
    }
}

bool HasTrayProcessInSession(DWORD session_id) {
    EnterCriticalSection(&g_process_lock);

    bool found = false;
    for (auto& process : g_tray_processes) {
        DWORD process_session = 0;
        if (process.dwProcessId != 0 &&
            ProcessIdToSessionId(process.dwProcessId, &process_session) &&
            process_session == session_id &&
            IsProcessRunning(process)) {
            found = true;
            break;
        }
    }

    LeaveCriticalSection(&g_process_lock);
    return found;
}

void RememberTrayProcess(const PROCESS_INFORMATION& process) {
    EnterCriticalSection(&g_process_lock);
    g_tray_processes.push_back(process);
    LeaveCriticalSection(&g_process_lock);
}

void CleanupStoppedTrayProcesses() {
    EnterCriticalSection(&g_process_lock);

    auto it = g_tray_processes.begin();
    while (it != g_tray_processes.end()) {
        if (IsProcessRunning(*it)) {
            ++it;
            continue;
        }

        CloseProcessInfo(*it);
        it = g_tray_processes.erase(it);
    }

    LeaveCriticalSection(&g_process_lock);
}

void TerminateTrayProcesses() {
    EnterCriticalSection(&g_process_lock);

    for (auto& process : g_tray_processes) {
        if (process.hProcess && IsProcessRunning(process)) {
            TerminateProcess(process.hProcess, 0);
            WaitForSingleObject(process.hProcess, 3000);
        }
        CloseProcessInfo(process);
    }
    g_tray_processes.clear();

    LeaveCriticalSection(&g_process_lock);
}

void LaunchTrayForSession(DWORD session_id) {
    WriteLog(L"Trying to launch tray for session " + std::to_wstring(session_id));

    if (session_id == 0 || HasTrayProcessInSession(session_id)) {
        WriteLog(L"Skipping session " + std::to_wstring(session_id));
        return;
    }

    HANDLE user_token = nullptr;
    if (!WTSQueryUserToken(session_id, &user_token)) {
        WriteLastErrorLog(L"WTSQueryUserToken for session " + std::to_wstring(session_id));
        return;
    }

    HANDLE primary_token = nullptr;
    if (!DuplicateTokenEx(
            user_token,
            TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
            nullptr,
            SecurityImpersonation,
            TokenPrimary,
            &primary_token)) {
        WriteLastErrorLog(L"DuplicateTokenEx");
        CloseHandle(user_token);
        return;
    }
    CloseHandle(user_token);

    void* environment = nullptr;
    CreateEnvironmentBlock(&environment, primary_token, FALSE);

    const std::wstring app_path = GetCurrentDirectoryForModule() + L"\\" + kTrayAppExecutableName;
    std::wstring command_line = Quote(app_path) + L" " + kBackgroundArgument;
    WriteLog(L"Tray path: " + app_path);

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.lpDesktop = const_cast<LPWSTR>(L"winsta0\\default");

    PSECURITY_DESCRIPTOR process_security_descriptor = CreateProtectedProcessSecurityDescriptor();
    SECURITY_ATTRIBUTES process_security{};
    process_security.nLength = sizeof(process_security);
    process_security.lpSecurityDescriptor = process_security_descriptor;
    process_security.bInheritHandle = FALSE;

    PROCESS_INFORMATION process{};
    const BOOL created = CreateProcessAsUserW(
        primary_token,
        app_path.c_str(),
        command_line.data(),
        process_security_descriptor ? &process_security : nullptr,
        nullptr,
        FALSE,
        CREATE_UNICODE_ENVIRONMENT,
        environment,
        GetCurrentDirectoryForModule().c_str(),
        &startup,
        &process
    );

    if (process_security_descriptor) {
        LocalFree(process_security_descriptor);
    }
    if (environment) {
        DestroyEnvironmentBlock(environment);
    }
    CloseHandle(primary_token);

    if (created) {
        WriteLog(L"Tray process started, pid=" + std::to_wstring(process.dwProcessId));
        RememberTrayProcess(process);
    } else {
        WriteLastErrorLog(L"CreateProcessAsUserW");
    }
}

void LaunchTrayForLoggedOnSessions() {
    WriteLog(L"Enumerating terminal sessions");
    CleanupStoppedTrayProcesses();

    WTS_SESSION_INFOW* sessions = nullptr;
    DWORD count = 0;
    if (!WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &count)) {
        WriteLastErrorLog(L"WTSEnumerateSessionsW");
        return;
    }

    for (DWORD i = 0; i < count; ++i) {
        WriteLog(
            L"Session " + std::to_wstring(sessions[i].SessionId) +
            L", state=" + std::to_wstring(static_cast<int>(sessions[i].State))
        );
        if (sessions[i].SessionId != 0 &&
            (sessions[i].State == WTSActive || sessions[i].State == WTSConnected)) {
            LaunchTrayForSession(sessions[i].SessionId);
        }
    }

    WTSFreeMemory(sessions);
}

DWORD WINAPI RpcThreadProc(void*) {
    WriteLog(L"Starting RPC server");
    RPC_STATUS status = RpcServerUseProtseqEpW(
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr
    );
    if (status != RPC_S_OK) {
        WriteLog(L"RpcServerUseProtseqEpW failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    status = RpcServerRegisterIf(ZIOVPOControl_v1_0_s_ifspec, nullptr, nullptr);
    if (status != RPC_S_OK) {
        WriteLog(L"RpcServerRegisterIf failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    status = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, TRUE);
    if (status != RPC_S_OK && status != RPC_S_ALREADY_LISTENING) {
        WriteLog(L"RpcServerListen failed, status=" + std::to_wstring(status));
        SetEvent(g_stop_event);
        return status;
    }

    WriteLog(L"RPC server started");

    return ERROR_SUCCESS;
}

DWORD WINAPI ServiceControlHandlerEx(DWORD control, DWORD event_type, void*, void*) {
    if (control == SERVICE_CONTROL_INTERROGATE) {
        SetServiceStatus(g_status_handle, &g_status);
        return NO_ERROR;
    }

    if (control == SERVICE_CONTROL_SESSIONCHANGE) {
        if (event_type == WTS_SESSION_LOGON ||
            event_type == WTS_SESSION_UNLOCK ||
            event_type == WTS_CONSOLE_CONNECT ||
            event_type == WTS_REMOTE_CONNECT) {
            LaunchTrayForLoggedOnSessions();
        }
        return NO_ERROR;
    }

    return ERROR_CALL_NOT_IMPLEMENTED;
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
    g_status_handle = RegisterServiceCtrlHandlerExW(kServiceName, ServiceControlHandlerEx, nullptr);
    if (!g_status_handle) {
        return;
    }

    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_status.dwServiceSpecificExitCode = 0;
    SetServiceState(SERVICE_START_PENDING, NO_ERROR, 3000);
    ApplyProtectedDaclToCurrentProcess();

    InitializeCriticalSection(&g_process_lock);
    InitializeCriticalSection(&g_auth_lock);
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_auth_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    HANDLE rpc_thread = CreateThread(nullptr, 0, RpcThreadProc, nullptr, 0, nullptr);
    if (!rpc_thread) {
        CloseHandle(g_stop_event);
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_auth_lock);
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    g_refresh_thread = CreateThread(nullptr, 0, RefreshThreadProc, nullptr, 0, nullptr);

    SetServiceState(SERVICE_RUNNING);
    WriteLog(L"Service is running");
    LaunchTrayForLoggedOnSessions();

    WaitForSingleObject(g_stop_event, INFINITE);

    SetServiceState(SERVICE_STOP_PENDING, NO_ERROR, 3000);
    WriteLog(L"Service is stopping");
    RpcMgmtStopServerListening(nullptr);
    WaitForSingleObject(rpc_thread, 3000);
    RpcServerUnregisterIf(ZIOVPOControl_v1_0_s_ifspec, nullptr, FALSE);
    CloseHandle(rpc_thread);
    if (g_refresh_thread) {
        WaitForSingleObject(g_refresh_thread, 3000);
        CloseHandle(g_refresh_thread);
        g_refresh_thread = nullptr;
    }

    TerminateTrayProcesses();
    CloseHandle(g_stop_event);
    DeleteCriticalSection(&g_auth_lock);
    DeleteCriticalSection(&g_process_lock);

    SetServiceState(SERVICE_STOPPED);
}

int wmain() {
    SERVICE_TABLE_ENTRYW service_table[] = {
        {const_cast<LPWSTR>(kServiceName), ServiceMain},
        {nullptr, nullptr}
    };

    if (!StartServiceCtrlDispatcherW(service_table)) {
        return static_cast<int>(GetLastError());
    }

    return 0;
}

extern "C" void StopService() {
    if (g_stop_event) {
        SetEvent(g_stop_event);
    }
}

extern "C" long GetCurrentUser(long* authenticated, wchar_t** login) {
    if (!authenticated || !login) {
        return ERROR_INVALID_PARAMETER;
    }

    EnterCriticalSection(&g_auth_lock);
    *authenticated = g_auth.authenticated ? 1 : 0;
    *login = RpcCopyString(g_auth.authenticated ? g_auth.login : L"");
    LeaveCriticalSection(&g_auth_lock);
    return *login ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" long Login(const wchar_t* login, const wchar_t* password, wchar_t** errorMessage) {
    if (!login || !password || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = AuthenticateUser(login, password, error);
    *errorMessage = RpcCopyString(error);
    return result;
}

extern "C" long Logout() {
    ClearAuthState();
    return 0;
}

extern "C" long GetLicenseStatus(long* hasLicense, wchar_t** expiresAt, wchar_t** errorMessage) {
    if (!hasLicense || !expiresAt || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = QueryLicenseStatus(error);

    EnterCriticalSection(&g_auth_lock);
    *hasLicense = g_auth.hasLicense ? 1 : 0;
    *expiresAt = RpcCopyString(g_auth.licenseExpiresAt);
    LeaveCriticalSection(&g_auth_lock);
    *errorMessage = RpcCopyString(error);

    if (!*expiresAt || !*errorMessage) {
        return ERROR_OUTOFMEMORY;
    }
    return result;
}

extern "C" long ActivateProduct(const wchar_t* activationCode, wchar_t** errorMessage) {
    if (!activationCode || !errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    std::wstring error;
    long result = ActivateLicense(activationCode, error);
    *errorMessage = RpcCopyString(error);
    return *errorMessage ? result : ERROR_OUTOFMEMORY;
}

extern "C" long AntivirusPing(wchar_t** errorMessage) {
    if (!errorMessage) {
        return ERROR_INVALID_PARAMETER;
    }

    bool hasLicense = false;
    EnterCriticalSection(&g_auth_lock);
    hasLicense = g_auth.hasLicense;
    LeaveCriticalSection(&g_auth_lock);

    if (!hasLicense) {
        *errorMessage = RpcCopyString(L"License ticket is missing");
        return ERROR_NOT_READY;
    }

    *errorMessage = RpcCopyString(L"");
    return *errorMessage ? 0 : ERROR_OUTOFMEMORY;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    free(pointer);
}
