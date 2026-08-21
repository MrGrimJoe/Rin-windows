cmake_minimum_required(VERSION 3.16)
project(rin_windows_core CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Dependencies -----------------------------------------------------
#
# asio and nlohmann_json are both header-only, so instead of vendoring
# full source trees in third_party/ (which is what was blowing past
# GitHub's web-upload size limit -- the vendored asio checkout alone was
# ~7MB of autotools/docs/tests we never touch), CMake downloads pinned
# versions at configure time and caches them under build/_deps. Nothing
# dependency-related lives in git anymore.
#
# First configure needs network access; after that CMake reuses the
# build/_deps cache, so offline rebuilds work fine.

include(FetchContent)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)

# asio has no CMakeLists.txt for the standalone header-only library (only
# for its own tests/examples), so don't add_subdirectory it -- just pull
# the source down and point an interface target at its include/ dir.
FetchContent_GetProperties(asio)
if(NOT asio_POPULATED)
    FetchContent_Populate(asio)
endif()
add_library(asio_headers INTERFACE)
target_include_directories(asio_headers INTERFACE "${asio_SOURCE_DIR}/asio/include")

# nlohmann_json ships a proper CMakeLists.txt and defines the
# nlohmann_json::nlohmann_json target itself once fetched.
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

find_package(OpenSSL REQUIRED)

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
    ${QRENCODE_INCLUDE_DIR}
)

target_compile_definitions(rin_core PUBLIC
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

target_link_libraries(rin_core PUBLIC
    asio_headers
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
