cmake_minimum_required(VERSION 3.16)
project(rin_windows_core CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Dependencies -----------------------------------------------------

# Standalone Asio (header-only, no Boost). Vendored under third_party/
# per the doc's tech stack choice (§08). If you'd rather use a system
# package or vcpkg/Conan on the real Windows box, point ASIO_INCLUDE_DIR
# at it instead of relying on the vendored copy.
set(ASIO_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/third_party/asio/asio/include"
    CACHE PATH "Path to standalone Asio's include/ directory")

find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.9 REQUIRED)

# QR generation. libqrencode ships without a CMake config on most distros
# (including this build environment), so it's located manually rather than
# via find_package(). On Windows via vcpkg this also works fine since
# vcpkg's libqrencode port installs a plain .lib + header, same shape.
find_path(QRENCODE_INCLUDE_DIR qrencode.h)
find_library(QRENCODE_LIBRARY NAMES qrencode)
if(NOT QRENCODE_INCLUDE_DIR OR NOT QRENCODE_LIBRARY)
    message(FATAL_ERROR "libqrencode not found. Install libqrencode-dev (Linux) "
                         "or 'vcpkg install libqrencode' (Windows).")
endif()

# --- Core library -------------------------------------------------------
# Kept separate from main.cpp so a future Win32 GUI shell (or unit tests)
# can link against it without dragging in the console entry point.

add_library(rin_core STATIC
    src/base64.cpp
    src/crypto.cpp
    src/protocol.cpp
    src/transport.cpp
    src/mesh_engine.cpp
    src/qr_code.cpp
)

target_include_directories(rin_core PUBLIC
    include
    ${ASIO_INCLUDE_DIR}
    ${QRENCODE_INCLUDE_DIR}
)

target_compile_definitions(rin_core PUBLIC
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

target_link_libraries(rin_core PUBLIC
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${QRENCODE_LIBRARY}
)

if(WIN32)
    target_link_libraries(rin_core PUBLIC ws2_32 wsock32)
endif()

if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(rin_core PUBLIC Threads::Threads)
endif()

# --- Console milestone executable ---------------------------------------

add_executable(rin_console src/main.cpp)
target_link_libraries(rin_console PRIVATE rin_core)

# --- Win32 GUI shell (Windows-only) --------------------------------------
# Not built on Linux/macOS -- win32_shell.cpp/.hpp and main_gui.cpp are
# fully #ifdef _WIN32-guarded, but there's no reason to even attempt the
# compile on platforms that will never provide <windows.h>.
if(WIN32)
    add_executable(rin_gui WIN32 src/main_gui.cpp src/win32_shell.cpp)
    target_link_libraries(rin_gui PRIVATE rin_core comctl32)
endif()

# --- Tests ----------------------------------------------------------
option(RIN_BUILD_TESTS "Build the crypto/protocol wire-compatibility tests" ON)
if(RIN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
