#include <windows.h>
#include <rpc.h>

#include <malloc.h>
#include <string>

#include "shared.h"

extern "C" {
#include "tray_rpc_h.h"
}

bool EnsureBinding() {
    if (hZIOVPOControlBinding) {
        return true;
    }

    RPC_WSTR string_binding = nullptr;

    RPC_STATUS status = RpcStringBindingComposeW(
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(L"ncalrpc")),
        nullptr,
        reinterpret_cast<RPC_WSTR>(const_cast<wchar_t*>(kRpcEndpoint)),
        nullptr,
        &string_binding
    );
    if (status != RPC_S_OK) {
        return false;
    }

    status = RpcBindingFromStringBindingW(string_binding, &hZIOVPOControlBinding);
    RpcStringFreeW(&string_binding);
    return status == RPC_S_OK;
}

void DropBinding() {
    if (hZIOVPOControlBinding) {
        RpcBindingFree(&hZIOVPOControlBinding);
    }
}

bool SendStopServiceRequest() {
    if (!EnsureBinding()) {
        return false;
    }

    bool sent = true;
    RpcTryExcept {
        StopService();
    }
    RpcExcept(1) {
        sent = false;
    }
    RpcEndExcept

    DropBinding();
    return sent;
}

long RpcGetCurrentUser(bool& authenticated, std::wstring& login) {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    long auth = 0;
    wchar_t* loginBuffer = nullptr;
    long result = 0;
    RpcTryExcept {
        result = GetCurrentUser(&auth, &loginBuffer);
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept

    authenticated = auth != 0;
    login = loginBuffer ? loginBuffer : L"";
    if (loginBuffer) {
        midl_user_free(loginBuffer);
    }
    return result;
}

long RpcLogin(const std::wstring& login, const std::wstring& password, std::wstring& error) {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    wchar_t* errorBuffer = nullptr;
    long result = 0;
    RpcTryExcept {
        result = Login(login.c_str(), password.c_str(), &errorBuffer);
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept

    error = errorBuffer ? errorBuffer : L"";
    if (errorBuffer) {
        midl_user_free(errorBuffer);
    }
    return result;
}

long RpcLogout() {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    long result = 0;
    RpcTryExcept {
        result = Logout();
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept
    return result;
}

long RpcGetLicenseStatus(bool& hasLicense, std::wstring& expiresAt, std::wstring& error) {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    long licensed = 0;
    wchar_t* expiresBuffer = nullptr;
    wchar_t* errorBuffer = nullptr;
    long result = 0;
    RpcTryExcept {
        result = GetLicenseStatus(&licensed, &expiresBuffer, &errorBuffer);
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept

    hasLicense = licensed != 0;
    expiresAt = expiresBuffer ? expiresBuffer : L"";
    error = errorBuffer ? errorBuffer : L"";
    if (expiresBuffer) {
        midl_user_free(expiresBuffer);
    }
    if (errorBuffer) {
        midl_user_free(errorBuffer);
    }
    return result;
}

long RpcActivateProduct(const std::wstring& code, std::wstring& error) {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    wchar_t* errorBuffer = nullptr;
    long result = 0;
    RpcTryExcept {
        result = ActivateProduct(code.c_str(), &errorBuffer);
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept

    error = errorBuffer ? errorBuffer : L"";
    if (errorBuffer) {
        midl_user_free(errorBuffer);
    }
    return result;
}

long RpcAntivirusPing(std::wstring& error) {
    if (!EnsureBinding()) {
        return RPC_S_SERVER_UNAVAILABLE;
    }

    wchar_t* errorBuffer = nullptr;
    long result = 0;
    RpcTryExcept {
        result = AntivirusPing(&errorBuffer);
    }
    RpcExcept(1) {
        result = static_cast<long>(RpcExceptionCode());
        DropBinding();
    }
    RpcEndExcept

    error = errorBuffer ? errorBuffer : L"";
    if (errorBuffer) {
        midl_user_free(errorBuffer);
    }
    return result;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    free(pointer);
}
