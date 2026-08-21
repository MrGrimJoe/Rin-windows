add_executable(rin_tests
    test_crypto.cpp
    test_protocol.cpp
    test_qr.cpp
)
target_link_libraries(rin_tests PRIVATE rin_core)

# ZXing is used ONLY in tests, as an independent decoder to verify our QR
# encoder actually produces scannable codes -- it is not a runtime
# dependency of rin_core/rin_console/rin_gui. Optional: if not found,
# skip the ZXing-based round-trip test rather than failing the whole
# build, since it's a verification nicety, not core functionality.
find_path(ZXING_INCLUDE_DIR ZXing/ReadBarcode.h)
find_library(ZXING_LIBRARY NAMES ZXing)
if(ZXING_INCLUDE_DIR AND ZXING_LIBRARY)
    target_include_directories(rin_tests PRIVATE ${ZXING_INCLUDE_DIR})
    target_link_libraries(rin_tests PRIVATE ${ZXING_LIBRARY})
    target_compile_definitions(rin_tests PRIVATE RIN_HAVE_ZXING)
else()
    message(STATUS "ZXing not found -- QR round-trip decode test will be skipped. "
                    "Install libzxing-dev (Linux) to enable it.")
endif()

add_test(NAME rin_tests COMMAND rin_tests)
