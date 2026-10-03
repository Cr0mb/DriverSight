cmake_minimum_required(VERSION 3.20)
project(DriverSight VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCES
    src/main.cpp
    src/driver_enumerator.cpp
    src/device_scanner.cpp
    src/ioctl_fuzzer.cpp
    src/memory_verifier.cpp
    src/report_generator.cpp
    src/nt_helpers.cpp
    src/registry_scanner.cpp
    src/setupapi_scanner.cpp
    src/vuln_patterns.cpp
)

# Windows application icon
if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/assets/icon.ico")
    set(SOURCES ${SOURCES} "${CMAKE_SOURCE_DIR}/assets/app.rc")
endif()

add_executable(DriverSight ${SOURCES})

target_include_directories(DriverSight PRIVATE ${CMAKE_SOURCE_DIR}/include)

target_link_libraries(DriverSight PRIVATE
    ntdll
    setupapi
    psapi
    cfgmgr32
)

target_compile_definitions(DriverSight PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(DriverSight PRIVATE /W4 /EHa)
else()
    target_compile_options(DriverSight PRIVATE -Wall -Wextra)
endif()
