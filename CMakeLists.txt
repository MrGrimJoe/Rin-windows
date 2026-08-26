cmake_minimum_required(VERSION 3.20)
project(RinWindows VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# --- asio (header-only, standalone) ------------------------------------
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-30-2
    GIT_SHALLOW    TRUE
)
FetchContent_GetProperties(asio)
if(NOT asio_POPULATED)
    FetchContent_Populate(asio)
endif()
add_library(asio_headers INTERFACE)
target_include_directories(asio_headers INTERFACE "${asio_SOURCE_DIR}/asio/include")

# --- nlohmann/json -----------------------------------------------------
FetchContent_Declare(
    nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG        v3.11.3
    GIT_SHALLOW    TRUE
)
set(JSON_BuildTests OFF CACHE INTERNAL "")
FetchContent_MakeAvailable(nlohmann_json)

# --- OpenSSL -----------------------------------------------------------
find_package(OpenSSL REQUIRED)

# --- SQLite: system lib on Linux/macOS, amalgamation on Windows --------
find_path(SQLITE3_SYSTEM_INCLUDE_DIR sqlite3.h)
find_library(SQLITE3_SYSTEM_LIBRARY NAMES sqlite3)

if(SQLITE3_SYSTEM_INCLUDE_DIR AND SQLITE3_SYSTEM_LIBRARY AND NOT WIN32)
    add_library(sqlite3_lib INTERFACE)
    target_include_directories(sqlite3_lib INTERFACE ${SQLITE3_SYSTEM_INCLUDE_DIR})
    target_link_libraries(sqlite3_lib INTERFACE ${SQLITE3_SYSTEM_LIBRARY})
    message(STATUS "Using system SQLite3: ${SQLITE3_SYSTEM_LIBRARY}")
else()
    FetchContent_Declare(
        sqlite3
        URL https://www.sqlite.org/2024/sqlite-amalgamation-3450100.zip
    )
    FetchContent_GetProperties(sqlite3)
    if(NOT sqlite3_POPULATED)
        FetchContent_Populate(sqlite3)
    endif()
    add_library(sqlite3_lib STATIC "${sqlite3_SOURCE_DIR}/sqlite3.c")
    target_include_directories(sqlite3_lib PUBLIC "${sqlite3_SOURCE_DIR}")
    if(UNIX)
        target_link_libraries(sqlite3_lib PUBLIC ${CMAKE_DL_LIBS})
    endif()
    message(STATUS "Using fetched SQLite3 amalgamation")
endif()

# --- libqrencode -------------------------------------------------------
find_path(QRENCODE_INCLUDE_DIR qrencode.h)
find_library(QRENCODE_LIBRARY NAMES qrencode)
if(NOT QRENCODE_INCLUDE_DIR OR NOT QRENCODE_LIBRARY)
    message(FATAL_ERROR "libqrencode not found.\n"
        "  Linux:   apt install libqrencode-dev\n"
        "  Windows: vcpkg install libqrencode")
endif()

# --- ZXing (decode only, used in tests + camera scanner on Windows) ---
# ZXing is required at runtime only on Windows (camera QR scanner).
# On Linux/macOS it is used only in the test suite. Either way we link
# it the same way -- a single find_library call works for both.
find_path(ZXING_INCLUDE_DIR ZXing/ReadBarcode.h)
find_library(ZXING_LIBRARY NAMES ZXing)
if(ZXING_INCLUDE_DIR AND ZXING_LIBRARY)
    message(STATUS "Found ZXing: ${ZXING_LIBRARY}")
    set(HAVE_ZXING TRUE)
else()
    message(STATUS "ZXing not found -- camera QR scanner disabled; "
                   "install libzxing-dev to enable it.")
    set(HAVE_ZXING FALSE)
endif()

# --- rin_core (static library, cross-platform) -------------------------
add_library(rin_core STATIC
    src/base64.cpp
    src/crypto.cpp
    src/protocol.cpp
    src/transport.cpp
    src/mesh_engine.cpp
    src/qr_code.cpp
    src/audit_logger.cpp
    src/persistence.cpp
    src/file_transfer.cpp
    src/camera_qr_scanner.cpp   # #ifdef _WIN32 inside; compiles as stub elsewhere
)

target_include_directories(rin_core PUBLIC
    include
    ${QRENCODE_INCLUDE_DIR}
)

target_compile_definitions(rin_core PUBLIC
    ASIO_STANDALONE
    ASIO_NO_DEPRECATED
)

if(HAVE_ZXING)
    target_include_directories(rin_core PUBLIC ${ZXING_INCLUDE_DIR})
    target_link_libraries(rin_core PUBLIC ${ZXING_LIBRARY})
    target_compile_definitions(rin_core PUBLIC RIN_HAVE_ZXING)
endif()

target_link_libraries(rin_core PUBLIC
    asio_headers
    OpenSSL::SSL
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
    ${QRENCODE_LIBRARY}
    sqlite3_lib
)

if(WIN32)
    target_link_libraries(rin_core PUBLIC
        ws2_32 wsock32 shell32 ole32
        # WinRT for camera scanner (Windows.Media.Capture.Frames)
        windowsapp
    )
    # C++/WinRT coroutines
    target_compile_options(rin_core PUBLIC /await)
endif()

if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(rin_core PUBLIC Threads::Threads)
endif()

# --- Console shell (cross-platform) ------------------------------------
add_executable(rin_console src/main.cpp)
set_target_properties(rin_console PROPERTIES OUTPUT_NAME "rin-console")
target_link_libraries(rin_console PRIVATE rin_core)

# --- Rin Windows GUI (Windows-only) ------------------------------------
if(WIN32)
    # The manifest file enables Common Controls v6 (themed ListView etc.)
    # and declares PerMonitorV2 DPI awareness. Without it the app looks
    # like Windows 95 on any modern display.
    set(MANIFEST_FILE "${CMAKE_CURRENT_SOURCE_DIR}/src/rin_windows.manifest")

    add_executable(RinWindows WIN32
        src/main_gui.cpp
        src/win32_shell.cpp
        ${MANIFEST_FILE}
    )
    target_link_libraries(RinWindows PRIVATE rin_core comctl32)

    # Embed the manifest. CMake handles this automatically when the manifest
    # file is listed as a source with a .manifest extension.
    set_target_properties(RinWindows PROPERTIES
        OUTPUT_NAME "RinWindows"
        VS_WINDOWS_TARGET_PLATFORM_MIN_VERSION "10.0.17763.0"
    )
endif()

# --- Tests -------------------------------------------------------------
option(RIN_BUILD_TESTS "Build the test suite" ON)
if(RIN_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
