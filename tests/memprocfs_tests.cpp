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
    std::size_t config_set_count{};
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
    bool scatter_clear_fail{};
    std::string last_device;
    ULONG64 last_config_option{};
    ULONG64 last_config_value{};
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

extern "C" BOOL __wrap_VMMDLL_ConfigSet(VMM_HANDLE, ULONG64 option, ULONG64 value) {
    ++state.config_set_count;
    state.last_config_option = option;
    state.last_config_value = value;
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

extern "C" BOOL __wrap_VMMDLL_Scatter_ExecuteRead(VMMDLL_SCATTER_HANDLE) {
    ++state.scatter_execute_count;
    for (std::size_t index{}; index < state.prepared_counts.size(); ++index) {
        if (state.prepared_counts[index]) *state.prepared_counts[index] = state.prepared_sizes[index];
    }
    return true;
}

extern "C" BOOL __wrap_VMMDLL_Scatter_Clear(VMMDLL_SCATTER_HANDLE, DWORD, DWORD) {
    ++state.scatter_clear_count;
    if (state.scatter_clear_fail) return false;
    state.prepared_addresses.clear();
    state.prepared_sizes.clear();
    state.prepared_counts.clear();
    return true;
}

extern "C" void __wrap_VMMDLL_Scatter_CloseHandle(VMMDLL_SCATTER_HANDLE) {
    ++state.scatter_close_count;
    state.prepared_addresses.clear();
    state.prepared_sizes.clear();
    state.prepared_counts.clear();
}

int main() {
    reset_state();
    auto backend_result = kvmlib::MemProcFs::open({ .device = "test", .cache_policy = kvmlib::MemoryCachePolicy::cached });
    check(backend_result.has_value(), "backend open failed");
    kvmlib::MemProcFs backend = std::move(backend_result.value());
    check(kvmlib::MemProcFs::available(), "backend should report availability");
    const std::string embedded_device("test\0suffix", 11);
    const auto invalid_device = kvmlib::MemProcFs::open({ .device = embedded_device });
    check(!invalid_device && invalid_device.error() == kvmlib::Error::invalid_argument,
        "embedded-NUL device was accepted");

    const auto qemu_directory = std::filesystem::temp_directory_path() / ("kvmlib-qemu-tests-" + std::to_string(static_cast<unsigned long long>(::getpid())));
    std::error_code qemu_cleanup_error;
    std::filesystem::remove_all(qemu_directory, qemu_cleanup_error);
    std::filesystem::create_directories(qemu_directory);
    const auto qemu_executable = qemu_directory / "qemu-system-x86_64";
    std::filesystem::create_symlink("/usr/bin/tail", qemu_executable);
    const auto exact_guest = "kvmlib-exact-" + std::to_string(static_cast<unsigned long long>(::getpid()));
    auto backup_child = spawn_qemu(qemu_executable, exact_guest + "-backup");
    const auto prefix_miss = kvmlib::MemProcFs::open_qemu(exact_guest);
    stop_qemu(backup_child);
    check(backup_child.ready && !prefix_miss && prefix_miss.error() == kvmlib::Error::not_found, "QEMU guest prefix fixture failed or was accepted");
    auto escaped_child = spawn_qemu(qemu_executable, exact_guest + ",,backup");
    const auto escaped_miss = kvmlib::MemProcFs::open_qemu(exact_guest);
    stop_qemu(escaped_child);
    check(escaped_child.ready && !escaped_miss && escaped_miss.error() == kvmlib::Error::not_found, "escaped QEMU guest fixture failed or was accepted");
    auto duplicate_name_child = spawn_qemu(qemu_executable, exact_guest, true);
    const auto duplicate_name_miss = kvmlib::MemProcFs::open_qemu(exact_guest);
    stop_qemu(duplicate_name_child);
    check(duplicate_name_child.ready && !duplicate_name_miss && duplicate_name_miss.error() == kvmlib::Error::not_found, "duplicate QEMU name fixture failed or was accepted");
    auto exact_child = spawn_qemu(qemu_executable, exact_guest);
    const auto exact_guest_backend = kvmlib::MemProcFs::open_qemu(exact_guest, qemu_directory / "custom-qmp.sock");
    stop_qemu(exact_child);
    check(exact_child.ready && exact_guest_backend.has_value(), "exact QEMU guest fixture failed or lookup failed");
    check(state.last_device.find("qmp=" + (qemu_directory / "custom-qmp.sock").string()) != std::string::npos, "explicit QMP path was not used");
    auto first_ambiguous = spawn_qemu(qemu_executable, exact_guest);
    auto second_ambiguous = spawn_qemu(qemu_executable, exact_guest);
    const auto ambiguous_guest = kvmlib::MemProcFs::open_qemu(exact_guest);
    stop_qemu(first_ambiguous);
    stop_qemu(second_ambiguous);
    check(first_ambiguous.ready && second_ambiguous.ready && !ambiguous_guest && ambiguous_guest.error() == kvmlib::Error::invalid_argument, "ambiguous QEMU guest fixture failed or lookup was accepted");
    std::filesystem::remove_all(qemu_directory, qemu_cleanup_error);

    set_processes({ { 101, "Notepad.EXE" }, { 102, "notepad-helper.exe" } });
    const auto exact = backend.process_id("NOTEPAD.exe");
    check(exact && *exact == 101, "case-insensitive exact process lookup failed");
    check(state.refresh_count == 0, "process lookup unexpectedly refreshed globally");
    std::array<std::byte, 1> cache_probe{};
    check(backend.read(101, 0x1000, cache_probe), "cached read probe failed");
    check(state.last_read_flags == 0, "cached policy still forced NOCACHE");
    auto fresh_backend_result = kvmlib::MemProcFs::open({ .device = "fresh" });
    check(fresh_backend_result.has_value(), "fresh backend open failed");
    auto fresh_backend = std::move(fresh_backend_result.value());
    check(fresh_backend.read(101, 0x1000, cache_probe), "fresh read probe failed");
    check(state.last_read_flags == VMMDLL_FLAG_NOCACHE, "fresh policy did not force NOCACHE");
    const auto missing = backend.process_id("notepad");
    check(!missing && missing.error() == kvmlib::Error::not_found, "substring process lookup was accepted");
    const std::string embedded_name("notepad.exe\0suffix", 18);
    const auto embedded = backend.process_id(embedded_name);
    check(!embedded && embedded.error() == kvmlib::Error::invalid_argument, "embedded-NUL process lookup was accepted");
    set_processes({ { 101, "notepad.exe" }, { 102, "NOTEPAD.EXE" } });
    const auto ambiguous = backend.process_id("Notepad.exe");
    check(!ambiguous && ambiguous.error() == kvmlib::Error::invalid_argument, "ambiguous process lookup was accepted");

    reset_state();
    check(!backend.force_process_dtb(101, 0x100) && state.config_set_count == 0,
        "zero-aligned DTB was submitted to MemProcFS");
    check(backend.force_process_dtb(101, 0x123456), "aligned DTB was rejected");
    check(state.config_set_count == 1
            && state.last_config_option == (VMMDLL_OPT_PROCESS_DTB | 101)
            && state.last_config_value == 0x123000,
        "DTB was not page aligned before submission");

    set_processes({ { 101, "target.exe" } });
    const std::string embedded_module("target.dll\0suffix", 17);
    const auto invalid_exports = backend.exports(101, embedded_module);
    const auto invalid_base = backend.module_base(101, embedded_module);
    check(!invalid_exports && invalid_exports.error() == kvmlib::Error::invalid_argument
            && !invalid_base && invalid_base.error() == kvmlib::Error::invalid_argument,
        "embedded-NUL module name was accepted");
    const auto maps_before = state.mem_free_count;
    check(backend.processes(), "process enumeration failed");
    check(backend.modules(101), "module enumeration failed");
    check(backend.exports(101, "target.exe"), "export enumeration failed");
    check(backend.heaps(101), "heap enumeration failed");
    check(backend.heap_allocations(101, 1), "heap allocation enumeration failed");
    check(backend.memory_ranges(101), "VAD enumeration failed");
    check(state.mem_free_count >= maps_before + 6, "native enumeration allocation was not released");

    reset_state();
    std::array<std::byte, 1> empty_read_bytes{};
    kvmlib::MemoryTransfer empty_read{ .address = 0x4000, .bytes = std::span<std::byte>{ empty_read_bytes }.first(0), .bytes_read = 99 };
    check(backend.scatter_read(101, std::span{ &empty_read, 1 }), "empty scatter read should be a no-op");
    check(empty_read.bytes_read == 0 && state.scatter_initialize_count == 0, "empty scatter read retained stale state or touched backend");
    std::array<std::byte, 0x30> bytes{};
    kvmlib::MemoryTransfer transfer{ .address = 0x1ff0, .bytes = bytes };
    reset_state();
    set_processes({ { 101, "target.exe" } });
    check(backend.scatter_write(101, std::span{ &transfer, 1 }), "full scatter write failed");
    check(state.scatter_write_count == 1 && state.scatter_write_page_count == 2, "scatter write did not split at page boundary");
    check(transfer.bytes_read == bytes.size(), "scatter write byte count was not verified");
    check(state.scatter_write_page_count == state.scatter_write_success_pages, "scatter write page result mismatch");
    state.scatter_write_partial = true;
    transfer.bytes_read = 0;
    const auto partial = backend.scatter_write(101, std::span{ &transfer, 1 });
    check(!partial && partial.error() == kvmlib::Error::partial_write, "partial scatter write was reported as success");
    check(transfer.bytes_read != 0 && transfer.bytes_read < bytes.size(), "partial scatter byte count was not retained");
    state.scatter_write_partial = false;
    state.scatter_write_fail = true;
    const auto failed = backend.scatter_write(101, std::span{ &transfer, 1 });
    check(!failed && failed.error() == kvmlib::Error::io_error, "failed scatter write did not report I/O error");
    reset_state();
    std::array<std::byte, 1> one_byte{};
    kvmlib::MemoryTransfer unaligned{ .address = 0x1235, .bytes = one_byte };
    check(backend.scatter_write(101, std::span{ &unaligned, 1 }), "single-byte unaligned scatter write failed");
    check(state.scatter_write_page_count == 1 && unaligned.bytes_read == 1, "single-byte scatter write was narrowed or miscounted");
    std::array<std::byte, 5> tail_bytes{};
    kvmlib::MemoryTransfer page_tail{ .address = 0x1ffe, .bytes = tail_bytes };
    check(backend.scatter_write(101, std::span{ &page_tail, 1 }), "unaligned page-tail scatter write failed");
    check(state.scatter_write_page_count == 2 && page_tail.bytes_read == tail_bytes.size(), "page-tail scatter write was not split correctly");
    const auto writes_before_invalid = state.scatter_write_count;
    kvmlib::MemoryTransfer invalid{ .address = std::numeric_limits<std::uint64_t>::max(), .bytes = std::span<std::byte>{ bytes }.first(2) };
    check(!backend.scatter_write(101, std::span{ &invalid, 1 }) && state.scatter_write_count == writes_before_invalid, "invalid scatter range reached backend");
    check(backend.scatter_write(101, {}), "empty scatter write should be a no-op");

    reset_state();
    std::array<std::byte, 32> read_buffer{};
    kvmlib::MemoryTransfer read_transfer{ .address = 0x4000, .bytes = read_buffer };
    auto batch_result = backend.read_batch(101);
    check(batch_result.has_value(), "read batch creation failed");
    auto batch = std::move(*batch_result);
    check(batch.execute(std::span{ &read_transfer, 1 }), "first batch read failed");
    check(batch.execute(std::span{ &read_transfer, 1 }), "repeated batch read failed");
    check(state.scatter_initialize_count == 1 && state.scatter_prepare_count == 1 && state.scatter_execute_count == 2, "batch did not reuse prepared request");
    std::array<std::byte, 32> second_buffer{};
    read_transfer.bytes = second_buffer;
    check(batch.execute(std::span{ &read_transfer, 1 }), "rebound buffer batch read failed");
    check(state.scatter_clear_count == 1 && state.scatter_prepare_count == 2, "changed batch storage was not rebound");
    std::array<std::byte, 1> empty_batch_bytes{};
    kvmlib::MemoryTransfer empty_batch{ .address = 0x4000, .bytes = std::span<std::byte>{ empty_batch_bytes }.first(0), .bytes_read = 99 };
    const auto execute_before_empty = state.scatter_execute_count;
    check(batch.execute(std::span{ &empty_batch, 1 }), "nonempty empty-transfer batch should clear and succeed");
    check(empty_batch.bytes_read == 0 && state.scatter_clear_count == 2 && state.scatter_execute_count == execute_before_empty, "empty-transfer batch did not clear bindings without executing");
    check(batch.clear(), "batch clear failed");
    check(state.scatter_clear_count == 3, "batch clear did not release registrations");
    check(batch.execute({}), "empty batch should be a no-op");
    check(batch.rebind(102), "batch process rebind failed");
    check(batch.execute(std::span{ &read_transfer, 1 }), "rebound process batch read failed");
    auto clear_failure_batch_result = backend.read_batch(101);
    check(clear_failure_batch_result.has_value(), "clear-failure batch creation failed");
    auto clear_failure_batch = std::move(*clear_failure_batch_result);
    check(clear_failure_batch.execute(std::span{ &read_transfer, 1 }), "clear-failure batch setup failed");
    const auto close_before_clear_failure = state.scatter_close_count;
    state.scatter_clear_fail = true;
    const auto failed_clear = clear_failure_batch.clear();
    state.scatter_clear_fail = false;
    check(!failed_clear && failed_clear.error() == kvmlib::Error::io_error
            && state.scatter_close_count == close_before_clear_failure + 1,
        "failed scatter clear did not close the handle");
    check(clear_failure_batch.execute(std::span{ &read_transfer, 1 }),
        "batch did not recover after failed scatter clear");
    state.scatter_initialize_fail = true;
    read_transfer.bytes_read = 77;
    auto failed_initialize_batch_result = backend.read_batch(101);
    check(failed_initialize_batch_result.has_value(), "failed-initialize batch creation failed");
    auto failed_initialize_batch = std::move(failed_initialize_batch_result.value());
    const auto failed_initialize = failed_initialize_batch.execute(std::span{ &read_transfer, 1 });
    state.scatter_initialize_fail = false;
    check(!failed_initialize && read_transfer.bytes_read == 0, "failed batch initialization retained stale completion");
    state.scatter_prepare_fail = true;
    read_transfer.bytes_read = 77;
    auto failed_prepare_batch_result = backend.read_batch(101);
    check(failed_prepare_batch_result.has_value(), "failed-prepare batch creation failed");
    auto failed_prepare_batch = std::move(failed_prepare_batch_result.value());
    const auto failed_prepare = failed_prepare_batch.execute(std::span{ &read_transfer, 1 });
    state.scatter_prepare_fail = false;
    check(!failed_prepare && read_transfer.bytes_read == 0, "failed batch preparation retained stale completion");
    const auto close_before_lifetime = state.close_count;
    {
        auto lifetime_result = backend.read_batch(101);
        check(lifetime_result.has_value(), "lifetime batch creation failed");
        auto lifetime_batch = std::move(*lifetime_result);
        auto moved_backend = std::move(backend);
        backend = kvmlib::MemProcFs{};
        check(lifetime_batch.execute(std::span{ &read_transfer, 1 }), "batch lost session after backend move/destruction");
        check(state.close_count == close_before_lifetime, "backend closed a session still owned by a batch");
        backend = std::move(moved_backend);
    }

    const auto directory = test_directory();
    std::error_code cleanup_error;
    std::filesystem::remove_all(directory, cleanup_error);
    std::filesystem::create_directories(directory);
    const auto output = directory / "dump.bin";
    {
        std::ofstream file(output, std::ios::binary);
        file << "preserved";
    }
    reset_state();
    state.read_fail_after = 1;
    const auto failed_dump = backend.dump_physical(0, (1 << 20) + 1, output);
    check(!failed_dump, "failed dump was reported as success");
    std::ifstream preserved(output, std::ios::binary);
    const std::string preserved_contents((std::istreambuf_iterator<char>(preserved)), std::istreambuf_iterator<char>());
    check(preserved_contents == "preserved", "failed dump replaced destination");
    const auto reads_before_special = state.read_count;
    check(!backend.dump_physical(0, 1, "/dev/full") && state.read_count == reads_before_special, "special output was opened");
    const auto invalid_range_dump = backend.dump_physical(std::numeric_limits<std::uint64_t>::max(), 2, output);
    check(!invalid_range_dump && invalid_range_dump.error() == kvmlib::Error::invalid_argument, "overflowing dump range was accepted");
    state.read_fail_after = std::numeric_limits<std::size_t>::max();
    const auto empty_output = directory / "empty.bin";
    check(backend.dump_physical(0, 0, empty_output), "zero-size dump failed");
    check(std::filesystem::file_size(empty_output) == 0, "zero-size dump did not create an empty regular file");
    const auto symlink = directory / "device-link";
    std::filesystem::create_symlink("/dev/full", symlink);
    check(!backend.dump_physical(0, 1, symlink), "symlink output was accepted");
    const auto nonexistent_parent = directory / "missing" / "output.bin";
    check(!backend.dump_physical(0, 0, nonexistent_parent), "missing output parent was accepted");
    std::filesystem::remove_all(directory, cleanup_error);
    return 0;
}
