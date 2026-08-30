cmake_minimum_required(VERSION 3.20)
project(RinWindows VERSION 1.0.0 LANGUAGES CXX C)

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

    # ${sqlite3_SOURCE_DIR}/sqlite3.c assumed the amalgamation zip extracts
    # flat -- it doesn't. sqlite.org's zip has its own top-level folder
    # (e.g. sqlite-amalgamation-3450100/sqlite3.c), and FetchContent_Populate
    # doesn't strip that the way some other archive tools do. That mismatch
    # left sqlite3_lib with zero real source files, which is why CMake
    # couldn't even determine a linker language for it. Glob for the real
    # path instead of assuming a fixed layout, so this survives sqlite.org
    # changing how a future amalgamation zip is laid out too.
    file(GLOB_RECURSE _sqlite3_c_candidates "${sqlite3_SOURCE_DIR}/sqlite3.c")
    list(LENGTH _sqlite3_c_candidates _sqlite3_c_count)
    if(_sqlite3_c_count EQUAL 0)
        message(FATAL_ERROR "sqlite3.c not found anywhere under ${sqlite3_SOURCE_DIR} -- "
            "the amalgamation zip's layout may have changed.")
    endif()
    list(GET _sqlite3_c_candidates 0 _sqlite3_c_file)
    get_filename_component(_sqlite3_dir "${_sqlite3_c_file}" DIRECTORY)

    add_library(sqlite3_lib STATIC "${_sqlite3_c_file}")
    # ROOT CAUSE (finally): project() at the top of this file only declared
    # LANGUAGES CXX, never C. sqlite3.c is a C file. Without C enabled at
    # the project() level, the Visual Studio generator has no C toolset
    # registered at all, so it silently produces a malformed/incomplete
    # sqlite3_lib.vcxproj -- not excluded, not misordered, just never a
    # real, buildable project. That's why it never appeared ANYWHERE in a
    # full build log (no "Building Custom Rule", no compile line, nothing)
    # regardless of add_dependencies() or EXCLUDE_FROM_ALL, which both
    # assume the target is otherwise valid and just needs sequencing/
    # inclusion -- neither can fix a generator-level toolset gap. The real
    # fix is `project(RinWindows VERSION 1.0.0 LANGUAGES CXX C)` above.
    # LINKER_LANGUAGE C and EXCLUDE_FROM_ALL FALSE below are now likely
    # redundant given that fix, but left in place as harmless belt-and-
    # suspenders rather than risk removing something and reopening a gap.
    set_target_properties(sqlite3_lib PROPERTIES LINKER_LANGUAGE C)
    # add_dependencies(<consumer> sqlite3_lib) on rin_console/rin_tests/
    # RinWindows was NOT enough on its own -- confirmed by grepping a full
    # build log and finding sqlite3_lib.vcxproj is never invoked at all, on
    # any target, despite those add_dependencies() calls being present.
    # add_dependencies() only orders builds among targets MSBuild already
    # scheduled; it doesn't force a target that CMake left out of the
    # default ALL_BUILD project into the build in the first place. Targets
    # created via FetchContent_Populate() (rather than
    # FetchContent_MakeAvailable(), which we can't use here because of the
    # amalgamation zip's non-flat layout -- see the glob comment above) are
    # not automatically added to ALL_BUILD on the Visual Studio generator.
    # Explicitly un-excluding it is the actual fix.
    set_target_properties(sqlite3_lib PROPERTIES EXCLUDE_FROM_ALL FALSE)
    target_include_directories(sqlite3_lib PUBLIC "${_sqlite3_dir}")
    if(UNIX)
        target_link_libraries(sqlite3_lib PUBLIC ${CMAKE_DL_LIBS})
    endif()
    message(STATUS "Using fetched SQLite3 amalgamation: ${_sqlite3_c_file}")
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
)

# camera_qr_scanner.cpp's #ifdef _WIN32 block #includes <ZXing/ReadBarcode.h>
# unconditionally, with no RIN_HAVE_ZXING guard around the include itself
# (only the surrounding logic was meant to be conditional, per the
# ZXing-not-found message above already promising "camera QR scanner
# disabled" -- the source list just never actually enforced that). Nothing
# else in the codebase references CameraQrScanner, confirmed, so leaving it
# out entirely when ZXing isn't available can't cause a link error --
# it's simply not compiled in, matching what CMake already claims happens.
if(HAVE_ZXING AND WIN32)
    target_sources(rin_core PRIVATE src/camera_qr_scanner.cpp)
    # C++/WinRT coroutines -- camera_qr_scanner.cpp is the only WinRT
    # coroutine consumer in the codebase (confirmed, nothing else uses
    # WinRT), so this only applies to that one file rather than forcing
    # the deprecated-coroutine machinery onto the whole target. The newer
    # MSVC toolset on GitHub's windows-latest runner hard-rejects
    # <experimental/coroutine> with a static_assert (C2338/STL1011) unless
    # the silence define is set -- Microsoft's own documented escape
    # hatch, not a real fix. A full migration to std::coroutine (C++20)
    # would be the real fix, but that's an actual code change to the
    # WinRT async logic, not something to improvise here.
    set_source_files_properties(src/camera_qr_scanner.cpp PROPERTIES
        COMPILE_OPTIONS "/await"
        COMPILE_DEFINITIONS "_SILENCE_EXPERIMENTAL_COROUTINE_DEPRECATION_WARNINGS"
    )
endif()

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
endif()

if(UNIX)
    find_package(Threads REQUIRED)
    target_link_libraries(rin_core PUBLIC Threads::Threads)
endif()

# --- Console shell (cross-platform) ------------------------------------
add_executable(rin_console src/main.cpp)
set_target_properties(rin_console PROPERTIES OUTPUT_NAME "rin-console")
target_link_libraries(rin_console PRIVATE rin_core)
# target_link_libraries above already declares the link requirement
# correctly, but on the Windows/Visual Studio generator sqlite3_lib.vcxproj
# (a FetchContent-populated single-source target) never actually got
# invoked as a build step at all -- confirmed by grepping a full build log
# for it, found zero occurrences, while rin_core's OTHER real dependencies
# built fine. add_dependencies() forces the explicit build-order edge that
# target_link_libraries alone wasn't producing for this specific target.
add_dependencies(rin_console sqlite3_lib)

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
    # Same MSBuild/CMake gap as rin_console and rin_tests -- on the Windows
    # Visual Studio generator, sqlite3_lib.vcxproj never gets invoked as a
    # build step without an explicit add_dependencies() edge.
    add_dependencies(RinWindows sqlite3_lib)
    # win32_shell.cpp already uses LVITEMW and to_wstring()/wide strings
    # throughout -- clearly Unicode-only by design -- but without this,
    # generic Win32 macros like ListView_SetItemText resolve to their ANSI
    # (...A, LPSTR-based) variant instead of the intended Wide one, which
    # is exactly the "cannot convert wchar_t* to LPSTR" errors this caused.
    target_compile_definitions(RinWindows PRIVATE UNICODE _UNICODE)

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
