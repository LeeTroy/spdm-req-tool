cmake_minimum_required(VERSION 3.16)
project(spdm-req-tool VERSION 1.0.0 LANGUAGES C)

include(ExternalProject)

set(LIBSPDM_DIR ${CMAKE_CURRENT_SOURCE_DIR}/libspdm)
if(NOT EXISTS ${LIBSPDM_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "libspdm submodule missing: run 'git submodule update --init --recursive'")
endif()

option(SPDM_STATIC "Link spdm-req-tool statically (recommended for the BMC)" ON)
option(SPDM_TEST_RESPONDER "Build spdm-test-responder (libspdm sample keys, testing only)" ON)
set(LIBSPDM_TARGET Release CACHE STRING "libspdm build type: Release or Debug")

# ---------------------------------------------------------------------------
# libspdm (built as its own CMake project, static libraries, OpenSSL crypto)
# ---------------------------------------------------------------------------
if(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(LIBSPDM_ARCH aarch64)
    set(LIBSPDM_TOOLCHAIN AARCH64_GCC)
    set(LIBSPDM_LTO ON)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(LIBSPDM_ARCH x64)
    set(LIBSPDM_TOOLCHAIN GCC)
    set(LIBSPDM_LTO OFF)
else()
    message(FATAL_ERROR "Unsupported processor ${CMAKE_SYSTEM_PROCESSOR}")
endif()

set(LIBSPDM_BUILD_DIR ${CMAKE_BINARY_DIR}/libspdm)
set(LIBSPDM_LIB_DIR ${LIBSPDM_BUILD_DIR}/lib)

# Link order matters for static libraries.
set(LIBSPDM_LIBS
    spdm_requester_lib
    spdm_common_lib
    spdm_secured_message_lib
    spdm_transport_mctp_lib
    spdm_crypt_lib
    spdm_crypt_ext_lib
    spdm_device_secret_lib_null
    cryptlib_openssl
    rnglib
    memlib
    malloclib
    debuglib
    platform_lib
)
set(LIBSPDM_LIB_FILES "")
foreach(lib ${LIBSPDM_LIBS})
    list(APPEND LIBSPDM_LIB_FILES ${LIBSPDM_LIB_DIR}/lib${lib}.a)
endforeach()

# libspdm builds OpenSSL (the bundled 3.5.x, which has ML-DSA) and installs both the shared and
# the static libcrypto; link the static one.
set(OPENSSL_INSTALL_DIR ${LIBSPDM_BUILD_DIR}/os_stub/openssllib/openssl-install)
set(OPENSSL_CRYPTO_LIB ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
list(APPEND LIBSPDM_LIB_FILES ${OPENSSL_CRYPTO_LIB})

# Extra libraries for the test responder.
set(LIBSPDM_RSP_LIBS spdm_responder_lib spdm_device_secret_lib_sample)
set(LIBSPDM_RSP_LIB_FILES "")
foreach(lib ${LIBSPDM_RSP_LIBS})
    list(APPEND LIBSPDM_RSP_LIB_FILES ${LIBSPDM_LIB_DIR}/lib${lib}.a)
endforeach()

set(LIBSPDM_CMAKE_ARGS
    -DARCH=${LIBSPDM_ARCH}
    -DTOOLCHAIN=${LIBSPDM_TOOLCHAIN}
    -DTARGET=${LIBSPDM_TARGET}
    -DCRYPTO=openssl
    -DDISABLE_TESTS=1
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
)
if(CMAKE_TOOLCHAIN_FILE)
    list(APPEND LIBSPDM_CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE})
endif()

ExternalProject_Add(libspdm_ext
    SOURCE_DIR ${LIBSPDM_DIR}
    BINARY_DIR ${LIBSPDM_BUILD_DIR}
    CMAKE_ARGS ${LIBSPDM_CMAKE_ARGS}
    BUILD_COMMAND ${CMAKE_COMMAND} --build . --parallel
        --target ${LIBSPDM_LIBS} ${LIBSPDM_RSP_LIBS}
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBSPDM_LIB_FILES} ${LIBSPDM_RSP_LIB_FILES}
    BUILD_ALWAYS OFF
)

# Must match the definitions libspdm applies to its own targets when CRYPTO=openssl,
# otherwise config-derived sizes (e.g. LIBSPDM_MAX_CERT_CHAIN_SIZE) would differ.
set(LIBSPDM_APP_DEFS
    LIBSPDM_SM2_KEY_EXCHANGE_P256_SUPPORT=0
    LIBSPDM_AEAD_SM4_128_GCM_SUPPORT=0
)
if(LIBSPDM_TARGET STREQUAL "Release")
    list(APPEND LIBSPDM_APP_DEFS LIBSPDM_DEBUG_ENABLE=0)
endif()

# ---------------------------------------------------------------------------
# spdm-req-tool
# ---------------------------------------------------------------------------
add_executable(spdm-req-tool
    src/main.c
    src/mctp_io.c
    src/spdm_glue.c
    src/decode.c
    src/node.c
    src/output.c
    src/cert.c
    src/cbor.c
    src/util.c
)
add_dependencies(spdm-req-tool libspdm_ext)

target_include_directories(spdm-req-tool PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${LIBSPDM_DIR}/include
    ${LIBSPDM_DIR}/include/hal
    ${LIBSPDM_DIR}/os_stub/include
    ${LIBSPDM_DIR}/os_stub
    ${OPENSSL_INSTALL_DIR}/include
)
target_compile_definitions(spdm-req-tool PRIVATE
    ${LIBSPDM_APP_DEFS}
    SPDM_REQ_TOOL_VERSION="${PROJECT_VERSION}"
    _GNU_SOURCE
)
target_compile_options(spdm-req-tool PRIVATE -std=gnu11 -Wall -Wextra -Wno-unused-parameter
    -Wno-missing-field-initializers -O2)

target_link_libraries(spdm-req-tool PRIVATE
    -Wl,--start-group ${LIBSPDM_LIB_FILES} -Wl,--end-group)
target_link_options(spdm-req-tool PRIVATE -Wl,--gc-sections)
if(LIBSPDM_LTO)
    target_compile_options(spdm-req-tool PRIVATE -flto=auto)
    target_link_options(spdm-req-tool PRIVATE -flto=auto)
endif()
if(SPDM_STATIC)
    target_link_options(spdm-req-tool PRIVATE -static)
endif()

# ---------------------------------------------------------------------------
# spdm-test-responder (testing only: libspdm sample keys)
# ---------------------------------------------------------------------------
if(SPDM_TEST_RESPONDER)
    add_executable(spdm-test-responder test/mctp_responder.c)
    add_dependencies(spdm-test-responder libspdm_ext)
    get_target_property(_inc spdm-req-tool INCLUDE_DIRECTORIES)
    target_include_directories(spdm-test-responder PRIVATE ${_inc})
    target_compile_definitions(spdm-test-responder PRIVATE ${LIBSPDM_APP_DEFS} _GNU_SOURCE)
    target_compile_options(spdm-test-responder PRIVATE -std=gnu11 -Wall -O2)
    target_link_libraries(spdm-test-responder PRIVATE
        -Wl,--start-group ${LIBSPDM_RSP_LIB_FILES} ${LIBSPDM_LIB_FILES} -Wl,--end-group)
    target_link_options(spdm-test-responder PRIVATE -Wl,--gc-sections)
    if(LIBSPDM_LTO)
        target_compile_options(spdm-test-responder PRIVATE -flto=auto)
        target_link_options(spdm-test-responder PRIVATE -flto=auto)
    endif()
    if(SPDM_STATIC)
        target_link_options(spdm-test-responder PRIVATE -static)
    endif()
endif()

install(TARGETS spdm-req-tool RUNTIME DESTINATION bin)
install(PROGRAMS demo/spdm-demo.py DESTINATION bin RENAME spdm-demo)
