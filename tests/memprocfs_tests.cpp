#include "kvmlib/memprocfs.hpp"
#include "kvmlib/privilege.hpp"

extern "C" {
#include "vmmdll.h"
}

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <sys/wait.h>
#include <signal.h>
#include <thread>
#include <chrono>
#include <utility>
#include <vector>
#include <unistd.h>

namespace {

struct State {
    std::array<VMMDLL_PROCESS_INFORMATION, 8> processes{};
    DWORD process_count{};
    std::size_t mem_free_count{};
    std::size_t close_count{};
    std::size_t refresh_count{};
    std::size_t read_count{};
    ULONG64 last_read_flags{};
    DWORD last_scatter_flags{};
    std::size_t read_fail_after{ std::numeric_limits<std::size_t>::max() };
    std::size_t write_count{};
    std::size_t scatter_initialize_count{};
    std::size_t scatter_prepare_count{};
    std::size_t scatter_execute_count{};
    std::size_t scatter_clear_count{};
    std::size_t scatter_close_count{};
    std::size_t scatter_write_count{};
    std::size_t scatter_write_page_count{};
    std::size_t scatter_write_success_pages{};
    bool scatter_write_partial{};
    bool scatter_write_fail{};
    bool scatter_initialize_fail{};
    bool scatter_prepare_fail{};
    std::string last_device;
    std::vector<QWORD> prepared_addresses;
    std::vector<DWORD> prepared_sizes;
    std::vector<PDWORD> prepared_counts;
    std::vector<PBYTE> prepared_buffers;
};

State state;
std::byte handle_token{};

template <typename T>
void check(T&& condition, const std::string_view message) {
    if (static_cast<bool>(condition)) return;
    std::cerr << message << '\n';
    std::exit(1);
}

void reset_state() {
    state = {};
    state.read_fail_after = std::numeric_limits<std::size_t>::max();
}

void set_processes(const std::initializer_list<std::pair<DWORD, std::string_view>> values) {
    state.process_count = 0;
    for (const auto& [pid, name] : values) {
        auto& process = state.processes[state.process_count++];
        process = {};
        process.dwPID = pid;
        std::strncpy(process.szNameLong, name.data(), sizeof(process.szNameLong) - 1);
    }
}

std::filesystem::path test_directory() {
    return std::filesystem::temp_directory_path() / ("kvmlib-memprocfs-tests-" + std::to_string(static_cast<unsigned long long>(::getpid())));
}

struct QemuChild {
    pid_t pid{ -1 };
    bool ready{};

    explicit QemuChild(pid_t value) noexcept : pid(value) {
    }

    ~QemuChild() {
        stop();
    }

    QemuChild(const QemuChild&) = delete;
    QemuChild& operator=(const QemuChild&) = delete;
    QemuChild(QemuChild&& other) noexcept
        : pid(std::exchange(other.pid, -1)), ready(other.ready) {
    }
    QemuChild& operator=(QemuChild&&) = delete;

    void stop() noexcept {
        const auto child = std::exchange(pid, -1);
        if (child <= 0) return;
        static_cast<void>(::kill(child, SIGTERM));
        while (::waitpid(child, nullptr, 0) < 0 && errno == EINTR) {
        }
    }
};

QemuChild spawn_qemu(const std::filesystem::path& executable, const std::string_view guest, const bool duplicate_name = false) {
    const auto name = std::string("guest=") + std::string(guest);
    const auto duplicate = std::string("guest=") + std::string(guest) + "-other";
    const auto child = ::fork();
    if (child == 0) {
        static_cast<void>(std::freopen("/dev/null", "w", stdout));
        static_cast<void>(std::freopen("/dev/null", "w", stderr));
        if (duplicate_name) {
            ::execl(executable.c_str(), "qemu-system-x86_64", "-f", "/dev/null", "--", "-name", name.c_str(), "-name", duplicate.c_str(), static_cast<char*>(nullptr));
        } else {
            ::execl(executable.c_str(), "qemu-system-x86_64", "-f", "/dev/null", "--", "-name", name.c_str(), static_cast<char*>(nullptr));
        }
        std::_Exit(127);
    }
    QemuChild result{ child };
    if (child < 0) return result;
    for (unsigned int attempt{}; attempt < 1000; ++attempt) {
        std::ifstream comm(std::filesystem::path{"/proc"} / std::to_string(child) / "comm");
        std::string executable_name;
        if (comm && std::getline(comm, executable_name) && executable_name.starts_with("qemu-system")) {
            std::ifstream command_line(std::filesystem::path{"/proc"} / std::to_string(child) / "cmdline", std::ios::binary);
            const std::string raw(std::istreambuf_iterator<char>(command_line), {});
            if (raw.find(name) != std::string::npos) {
                result.ready = true;
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return result;
}

void stop_qemu(QemuChild& child) {
    child.stop();
}

}

namespace kvmlib {

std::expected<void, Error> require_root() noexcept {
    return {};
}

}

extern "C" VMM_HANDLE __wrap_VMMDLL_Initialize(DWORD count, LPCSTR arguments[]) {
    state.last_device = count >= 3 && arguments[2] ? arguments[2] : "";
    return reinterpret_cast<VMM_HANDLE>(&handle_token);
}

extern "C" void __wrap_VMMDLL_Close(VMM_HANDLE) {
    ++state.close_count;
}

extern "C" BOOL __wrap_VMMDLL_ConfigSet(VMM_HANDLE, ULONG64 option, ULONG64) {
    if (option == VMMDLL_OPT_REFRESH_ALL) ++state.refresh_count;
    return true;
}

extern "C" void __wrap_VMMDLL_MemFree(PVOID pointer) {
    ++state.mem_free_count;
    if (pointer != state.processes.data()) std::free(pointer);
}

extern "C" BOOL __wrap_VMMDLL_ProcessGetInformationAll(VMM_HANDLE, PVMMDLL_PROCESS_INFORMATION* output, PDWORD count) {
    const auto bytes = static_cast<std::size_t>(state.process_count) * sizeof(VMMDLL_PROCESS_INFORMATION);
    auto* copy = static_cast<PVMMDLL_PROCESS_INFORMATION>(std::malloc(bytes ? bytes : sizeof(VMMDLL_PROCESS_INFORMATION)));
    if (!copy) return false;
    std::memcpy(copy, state.processes.data(), bytes);
    *output = copy;
    *count = state.process_count;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_ProcessGetInformation(VMM_HANDLE, DWORD pid, PVMMDLL_PROCESS_INFORMATION output, PSIZE_T size) {
    for (DWORD index{}; index < state.process_count; ++index) {
        if (state.processes[index].dwPID != pid) continue;
        if (!output || *size < sizeof(VMMDLL_PROCESS_INFORMATION)) return false;
        *output = state.processes[index];
        *size = sizeof(VMMDLL_PROCESS_INFORMATION);
        return true;
    }
    return false;
}

extern "C" BOOL __wrap_VMMDLL_PidGetFromName(VMM_HANDLE, LPCSTR, PDWORD) {
    return false;
}

extern "C" BOOL __wrap_VMMDLL_Map_GetModuleU(VMM_HANDLE, DWORD, PVMMDLL_MAP_MODULE* output, DWORD) {
    auto* map = static_cast<PVMMDLL_MAP_MODULE>(std::calloc(1, sizeof(VMMDLL_MAP_MODULE)));
    if (!map) return false;
    map->dwVersion = VMMDLL_MAP_MODULE_VERSION;
    *output = map;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_Map_GetEATU(VMM_HANDLE, DWORD, LPCSTR, PVMMDLL_MAP_EAT* output) {
    auto* map = static_cast<PVMMDLL_MAP_EAT>(std::calloc(1, sizeof(VMMDLL_MAP_EAT)));
    if (!map) return false;
    map->dwVersion = VMMDLL_MAP_EAT_VERSION;
    *output = map;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_Map_GetHeap(VMM_HANDLE, DWORD, PVMMDLL_MAP_HEAP* output) {
    auto* map = static_cast<PVMMDLL_MAP_HEAP>(std::calloc(1, sizeof(VMMDLL_MAP_HEAP)));
    if (!map) return false;
    map->dwVersion = VMMDLL_MAP_HEAP_VERSION;
    *output = map;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_Map_GetHeapAlloc(VMM_HANDLE, DWORD, QWORD, PVMMDLL_MAP_HEAPALLOC* output) {
    auto* map = static_cast<PVMMDLL_MAP_HEAPALLOC>(std::calloc(1, sizeof(VMMDLL_MAP_HEAPALLOC)));
    if (!map) return false;
    map->dwVersion = VMMDLL_MAP_HEAPALLOC_VERSION;
    *output = map;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_Map_GetVadU(VMM_HANDLE, DWORD, BOOL, PVMMDLL_MAP_VAD* output) {
    auto* map = static_cast<PVMMDLL_MAP_VAD>(std::calloc(1, sizeof(VMMDLL_MAP_VAD)));
    if (!map) return false;
    map->dwVersion = VMMDLL_MAP_VAD_VERSION;
    *output = map;
    return true;
}

extern "C" QWORD __wrap_VMMDLL_ProcessGetModuleBaseU(VMM_HANDLE, DWORD, LPCSTR) {
    return 0x400000;
}

extern "C" BOOL __wrap_VMMDLL_MemReadEx(VMM_HANDLE, DWORD, ULONG64, PBYTE output, DWORD count, PDWORD read, ULONG64 flags) {
    ++state.read_count;
    state.last_read_flags = flags;
    if (state.read_count > state.read_fail_after) {
        *read = 0;
        return false;
    }
    std::fill_n(output, count, static_cast<BYTE>(0x5a));
    *read = count;
    return true;
}

extern "C" BOOL __wrap_VMMDLL_MemWrite(VMM_HANDLE, DWORD, ULONG64, PBYTE, DWORD) {
    ++state.write_count;
    return true;
}

extern "C" DWORD __wrap_VMMDLL_MemWriteScatter(VMM_HANDLE, DWORD, PPMEM_SCATTER pages, DWORD count) {
    ++state.scatter_write_count;
    state.scatter_write_page_count = count;
    state.scatter_write_success_pages = 0;
    for (DWORD index{}; index < count; ++index) {
        pages[index]->f = !state.scatter_write_fail && (!state.scatter_write_partial || index == 0);
        if (pages[index]->f) ++state.scatter_write_success_pages;
    }
    return static_cast<DWORD>(state.scatter_write_success_pages);
}

extern "C" VMMDLL_SCATTER_HANDLE __wrap_VMMDLL_Scatter_Initialize(VMM_HANDLE, DWORD, DWORD flags) {
    ++state.scatter_initialize_count;
    state.last_scatter_flags = flags;
    if (state.scatter_initialize_fail) return nullptr;
    return reinterpret_cast<VMMDLL_SCATTER_HANDLE>(&handle_token);
}

extern "C" BOOL __wrap_VMMDLL_Scatter_PrepareEx(VMMDLL_SCATTER_HANDLE, QWORD address, DWORD size, PBYTE, PDWORD count) {
    ++state.scatter_prepare_count;
    state.prepared_addresses.push_back(address);
    state.prepared_sizes.push_back(size);
    state.prepared_counts.push_back(count);
    if (count) *count = 0;
    return !state.scatter_prepare_fail;
}
