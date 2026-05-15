cmake_minimum_required(VERSION 3.20)

project(ZIOVPOTrayApp LANGUAGES CXX)

add_executable(ZIOVPOTrayApp WIN32
    src/main.cpp
    resources/app.rc
)

target_compile_features(ZIOVPOTrayApp PRIVATE cxx_std_17)
target_compile_definitions(ZIOVPOTrayApp PRIVATE UNICODE _UNICODE)

if(MSVC)
    target_compile_options(ZIOVPOTrayApp PRIVATE /utf-8)
endif()

target_include_directories(ZIOVPOTrayApp PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(ZIOVPOTrayApp PRIVATE
    user32
    shell32
    gdi32
)
