set(prefix "${KVMLIB_BINARY_DIR}/package-test/prefix")
set(source "${KVMLIB_BINARY_DIR}/package-test/source")
set(build "${KVMLIB_BINARY_DIR}/package-test/build")

execute_process(COMMAND "${CMAKE_COMMAND}" --install "${KVMLIB_BINARY_DIR}"
    --prefix "${prefix}" --config "${KVMLIB_CONFIG}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Package installation failed: ${output}${error}")
endif()

file(MAKE_DIRECTORY "${source}")
file(WRITE "${source}/CMakeLists.txt" [=[
cmake_minimum_required(VERSION 3.25)
project(KVMLibConsumer LANGUAGES CXX)
find_package(KVMLib 0.1 CONFIG REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE kvmlib::kvmlib)
enable_testing()
add_test(NAME consumer COMMAND consumer)
]=])
file(WRITE "${source}/main.cpp" [=[
#include <kvmlib/kvmlib.hpp>

int main() {
    const kvmlib::MemProcFs backend;
    const auto result = backend.refresh();
    const auto expected = kvmlib::MemProcFs::available()
        ? kvmlib::Error::invalid_argument : kvmlib::Error::unsupported;
    if (result || result.error() != expected) {
        return 1;
    }
    const auto batch = backend.read_batch(1);
    if (batch || batch.error() != expected) {
        return 1;
    }
    if (!kvmlib::MemProcFs::available()) {
        const auto opened = kvmlib::MemProcFs::open({});
        return opened || opened.error() != kvmlib::Error::unsupported;
    }
    return 0;
}
]=])

execute_process(COMMAND "${CMAKE_COMMAND}" -S "${source}" -B "${build}"
    "-DKVMLib_DIR=${prefix}/${KVMLIB_INSTALL_LIBDIR}/cmake/KVMLib"
    "-DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}"
    "-DCMAKE_BUILD_TYPE=${KVMLIB_CONFIG}"
    "-DMEMPROCFS_LIBRARY_DIR=${MEMPROCFS_LIBRARY_DIR}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Consumer configuration failed: ${output}${error}")
endif()
execute_process(COMMAND "${CMAKE_COMMAND}" --build "${build}" --config "${KVMLIB_CONFIG}"
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Consumer build failed: ${output}${error}")
endif()
execute_process(COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${build}"
    --build-config "${KVMLIB_CONFIG}" --output-on-failure
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error)
if(NOT result EQUAL 0)
    message(FATAL_ERROR "Consumer execution failed: ${output}${error}")
endif()
