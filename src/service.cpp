#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <userenv.h>
#include <wtsapi32.h>
#include <rpc.h>

#include <algorithm>
#include <malloc.h>
#include <fstream>
#include <string>
#include <vector>

#include "shared.h"

extern "C" {
#include "tray_rpc_h.h"
}

SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
HANDLE g_stop_event = nullptr;
CRITICAL_SECTION g_process_lock;
std::vector<PROCESS_INFORMATION> g_tray_processes;

std::wstring GetCurrentDirectoryForModule();

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
    g_stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!g_stop_event) {
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_process_lock);
        return;
    }

    HANDLE rpc_thread = CreateThread(nullptr, 0, RpcThreadProc, nullptr, 0, nullptr);
    if (!rpc_thread) {
        CloseHandle(g_stop_event);
        SetServiceState(SERVICE_STOPPED, GetLastError());
        DeleteCriticalSection(&g_process_lock);
        return;
    }

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

    TerminateTrayProcesses();
    CloseHandle(g_stop_event);
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

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    free(pointer);
}
