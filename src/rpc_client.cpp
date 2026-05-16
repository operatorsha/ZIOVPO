#include <windows.h>
#include <rpc.h>

#include <malloc.h>

#include "shared.h"

extern "C" {
#include "tray_rpc_h.h"
}

bool SendStopServiceRequest() {
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
    if (status != RPC_S_OK) {
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

    RpcBindingFree(&hZIOVPOControlBinding);
    return sent;
}

extern "C" void* __RPC_USER midl_user_allocate(size_t size) {
    return malloc(size);
}

extern "C" void __RPC_USER midl_user_free(void* pointer) {
    free(pointer);
}
