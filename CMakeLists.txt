cmake_minimum_required(VERSION 3.25)

project(KVMLib VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(KVMLIB_BUILD_TESTS "Build KVMLib tests" ${PROJECT_IS_TOP_LEVEL})
option(KVMLIB_BUILD_EXAMPLES "Build KVMLib examples" ${PROJECT_IS_TOP_LEVEL})

add_library(kvmlib
    src/cr3_trace.cpp
    src/cpu.cpp
    src/input.cpp
    src/memory.cpp
    src/privilege.cpp
)

add_library(kvmlib::kvmlib ALIAS kvmlib)

target_compile_features(kvmlib PUBLIC cxx_std_23)

target_include_directories(kvmlib
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_options(kvmlib PRIVATE -Wall -Wextra -Wpedantic)

option(KVMLIB_ENABLE_MEMPROCFS "Build the MemProcFS backend" OFF)
set(MEMPROCFS_ROOT "" CACHE PATH "MemProcFS checkout root")
set(MEMPROCFS_LIBRARY_DIR "" CACHE PATH "Directory containing vmm.so")

if(KVMLIB_ENABLE_MEMPROCFS)
    if(NOT EXISTS "${MEMPROCFS_ROOT}/includes/vmmdll.h")
        message(FATAL_ERROR "MEMPROCFS_ROOT must contain includes/vmmdll.h")
    endif()
    if(NOT EXISTS "${MEMPROCFS_LIBRARY_DIR}/vmm.so")
        message(FATAL_ERROR "MEMPROCFS_LIBRARY_DIR must contain vmm.so")
    endif()
    target_sources(kvmlib PRIVATE
        src/memprocfs_core.cpp
        src/memprocfs_memory.cpp
    )
    target_include_directories(kvmlib SYSTEM PRIVATE "${MEMPROCFS_ROOT}/includes")
    target_compile_definitions(kvmlib PRIVATE LINUX)
    if(NOT TARGET KVMLib::MemProcFS)
        add_library(KVMLib::MemProcFS SHARED IMPORTED GLOBAL)
        set_target_properties(KVMLib::MemProcFS PROPERTIES IMPORTED_LOCATION "${MEMPROCFS_LIBRARY_DIR}/vmm.so")
    endif()
    target_link_libraries(kvmlib PUBLIC KVMLib::MemProcFS)
else()
    target_sources(kvmlib PRIVATE src/memprocfs_stub.cpp)
endif()

if(KVMLIB_BUILD_EXAMPLES)
    add_executable(kvmlib-overview examples/overview.cpp)
    target_link_libraries(kvmlib-overview PRIVATE kvmlib::kvmlib)
endif()

if(BUILD_TESTING AND KVMLIB_BUILD_TESTS)
    add_executable(kvmlib-tests tests/tests.cpp src/memory.cpp src/cpu.cpp)
    target_include_directories(kvmlib-tests PRIVATE include)
    target_compile_features(kvmlib-tests PRIVATE cxx_std_23)
    target_compile_options(kvmlib-tests PRIVATE -Wall -Wextra -Wpedantic)
    target_link_options(kvmlib-tests PRIVATE "LINKER:--wrap=pread")
    add_test(NAME kvmlib-tests COMMAND kvmlib-tests)

    add_executable(kvmlib-host-tests tests/host_tests.cpp src/input.cpp src/cr3_trace.cpp)
    target_include_directories(kvmlib-host-tests PRIVATE include)
    target_compile_features(kvmlib-host-tests PRIVATE cxx_std_23)
    target_compile_options(kvmlib-host-tests PRIVATE -Wall -Wextra -Wpedantic)
    foreach(symbol IN ITEMS open close read write ioctl flock)
        target_link_options(kvmlib-host-tests PRIVATE "LINKER:--wrap=${symbol}")
    endforeach()
    add_test(NAME kvmlib-host-tests COMMAND kvmlib-host-tests)

    if(KVMLIB_ENABLE_MEMPROCFS)
        add_executable(kvmlib-memprocfs-tests
            tests/memprocfs_tests.cpp
            src/memprocfs_core.cpp
            src/memprocfs_memory.cpp
        )
        target_link_libraries(kvmlib-memprocfs-tests PRIVATE KVMLib::MemProcFS)
        target_include_directories(kvmlib-memprocfs-tests PRIVATE include)
        target_compile_features(kvmlib-memprocfs-tests PRIVATE cxx_std_23)
        target_compile_options(kvmlib-memprocfs-tests PRIVATE -Wall -Wextra -Wpedantic)
        target_include_directories(kvmlib-memprocfs-tests SYSTEM PRIVATE "${MEMPROCFS_ROOT}/includes")
        target_compile_definitions(kvmlib-memprocfs-tests PRIVATE LINUX)
        foreach(symbol IN ITEMS
            VMMDLL_Initialize VMMDLL_Close VMMDLL_ConfigSet VMMDLL_MemFree
            VMMDLL_ProcessGetInformationAll VMMDLL_ProcessGetInformation
            VMMDLL_PidGetFromName VMMDLL_Map_GetModuleU VMMDLL_Map_GetEATU
            VMMDLL_Map_GetHeap VMMDLL_Map_GetHeapAlloc VMMDLL_Map_GetVadU
            VMMDLL_ProcessGetModuleBaseU VMMDLL_MemReadEx VMMDLL_MemWrite
            VMMDLL_MemWriteScatter VMMDLL_Scatter_Initialize
            VMMDLL_Scatter_PrepareEx VMMDLL_Scatter_ExecuteRead
            VMMDLL_Scatter_Clear VMMDLL_Scatter_CloseHandle)
            target_link_options(kvmlib-memprocfs-tests PRIVATE "LINKER:--wrap=${symbol}")
        endforeach()
        add_test(NAME kvmlib-memprocfs-tests COMMAND kvmlib-memprocfs-tests)
    endif()

    add_test(NAME kvmlib-package-consumer
        COMMAND ${CMAKE_COMMAND}
            "-DKVMLIB_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DKVMLIB_INSTALL_LIBDIR=${CMAKE_INSTALL_LIBDIR}"
            "-DMEMPROCFS_LIBRARY_DIR=${MEMPROCFS_LIBRARY_DIR}"
            "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
            "-DCMAKE_CTEST_COMMAND=${CMAKE_CTEST_COMMAND}"
            "-DKVMLIB_CONFIG=$<CONFIG>"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/package_consumer.cmake")
    add_test(NAME kvmlib-documentation
        COMMAND ${CMAKE_COMMAND}
            "-DKVMLIB_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}"
            "-DKVMLIB_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}"
            "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/tests/documentation.cmake")
endif()

install(TARGETS kvmlib EXPORT KVMLibTargets)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT KVMLibTargets
    FILE KVMLibTargets.cmake
    NAMESPACE kvmlib::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/KVMLib
)

configure_package_config_file(cmake/KVMLibConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/KVMLibConfig.cmake"
    INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/KVMLib")
write_basic_package_version_file("${CMAKE_CURRENT_BINARY_DIR}/KVMLibConfigVersion.cmake"
    COMPATIBILITY SameMajorVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/KVMLibConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/KVMLibConfigVersion.cmake"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/KVMLib")
