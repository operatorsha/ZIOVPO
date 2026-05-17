cmake_minimum_required(VERSION 3.20)

project(ZIOVPOTrayApp LANGUAGES C CXX)

find_program(MIDL_COMPILER midl)
if(NOT MIDL_COMPILER)
    file(GLOB SDK_BIN_DIRS
        "C:/Program Files (x86)/Windows Kits/10/bin/10.*/x64"
        "C:/Program Files (x86)/Windows Kits/10/bin/x64"
    )
    find_program(MIDL_COMPILER midl PATHS ${SDK_BIN_DIRS})
endif()
if(NOT MIDL_COMPILER)
    message(FATAL_ERROR "MIDL compiler not found. Install the Windows SDK.")
endif()

set(RPC_IDL "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/tray_rpc.idl")
set(RPC_ACF "${CMAKE_CURRENT_SOURCE_DIR}/src/rpc/tray_rpc.acf")
set(RPC_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/rpc_gen")
file(MAKE_DIRECTORY "${RPC_GEN_DIR}")

set(RPC_HEADER "${RPC_GEN_DIR}/tray_rpc_h.h")
set(RPC_CLIENT "${RPC_GEN_DIR}/tray_rpc_c.c")
set(RPC_SERVER "${RPC_GEN_DIR}/tray_rpc_s.c")

add_custom_command(
    OUTPUT ${RPC_HEADER} ${RPC_CLIENT} ${RPC_SERVER}
    COMMAND "${MIDL_COMPILER}"
            /acf "${RPC_ACF}"
            /header tray_rpc_h.h
            /cstub tray_rpc_c.c
            /sstub tray_rpc_s.c
            /env x64
            ${RPC_IDL}
    DEPENDS ${RPC_IDL} ${RPC_ACF}
    WORKING_DIRECTORY "${RPC_GEN_DIR}"
    COMMENT "Running MIDL compiler on tray_rpc.idl"
    VERBATIM
)

add_custom_target(GenerateRpc DEPENDS ${RPC_HEADER} ${RPC_CLIENT} ${RPC_SERVER})

add_executable(ZIOVPOTrayApp WIN32
    src/main.cpp
    src/rpc_client.cpp
    resources/app.rc
    ${RPC_CLIENT}
)

add_executable(ZIOVPOService
    src/service.cpp
    ${RPC_SERVER}
)

add_executable(ZIOVPOMockLicenseServer
    src/mock_license_server.cpp
)

add_dependencies(ZIOVPOTrayApp GenerateRpc)
add_dependencies(ZIOVPOService GenerateRpc)

target_compile_features(ZIOVPOTrayApp PRIVATE cxx_std_17)
target_compile_features(ZIOVPOService PRIVATE cxx_std_17)
target_compile_features(ZIOVPOMockLicenseServer PRIVATE cxx_std_17)
target_compile_definitions(ZIOVPOTrayApp PRIVATE UNICODE _UNICODE)
target_compile_definitions(ZIOVPOService PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(ZIOVPOTrayApp PRIVATE /utf-8)
    target_compile_options(ZIOVPOService PRIVATE /utf-8)
    target_compile_options(ZIOVPOMockLicenseServer PRIVATE /utf-8)
endif()

target_include_directories(ZIOVPOTrayApp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${RPC_GEN_DIR}
)

target_include_directories(ZIOVPOService PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${RPC_GEN_DIR}
)

target_link_libraries(ZIOVPOTrayApp PRIVATE
    user32
    shell32
    gdi32
    advapi32
    rpcrt4
    winmm
)

target_link_libraries(ZIOVPOService PRIVATE
    advapi32
    rpcrt4
    userenv
    winhttp
    wtsapi32
)

target_link_libraries(ZIOVPOMockLicenseServer PRIVATE
    ws2_32
)
