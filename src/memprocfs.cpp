#include "kvmlib/memprocfs.hpp"
#include "kvmlib/privilege.hpp"

extern "C" {
#include "vmmdll.h"
}

#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iterator>
#include <limits>
#include <memory>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace kvmlib {

struct MemProcFsSession {
    VMM_HANDLE handle{};
    DWORD read_flags{};

    ~MemProcFsSession() {
        if (handle) VMMDLL_Close(handle);
    }
};

}

namespace {

constexpr DWORD physical_memory = static_cast<DWORD>(-1);

kvmlib::Error failure() {
    return kvmlib::Error::io_error;
}

struct VmmDeleter {
    void operator()(void* pointer) const noexcept {
        if (pointer) VMMDLL_Close(static_cast<VMM_HANDLE>(pointer));
    }
};

struct MemFreeDeleter {
    void operator()(void* pointer) const noexcept {
        VMMDLL_MemFree(pointer);
    }
};

struct ScatterDeleter {
    void operator()(void* pointer) const noexcept {
        if (pointer) VMMDLL_Scatter_CloseHandle(static_cast<VMMDLL_SCATTER_HANDLE>(pointer));
    }
};

template <typename T>
using MemFreePtr = std::unique_ptr<T, MemFreeDeleter>;

using VmmPtr = std::unique_ptr<void, VmmDeleter>;
using ScatterPtr = std::unique_ptr<void, ScatterDeleter>;

DWORD read_flags(const kvmlib::MemoryCachePolicy policy) {
    return policy == kvmlib::MemoryCachePolicy::fresh ? VMMDLL_FLAG_NOCACHE : 0;
}

std::string lowercase(const std::string_view value) {
    std::string result(value);
    std::ranges::transform(result, result.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return result;
}

bool valid_range(const std::uint64_t address, const std::uint64_t size) {
    return size == 0 || address <= std::numeric_limits<std::uint64_t>::max() - (size - 1);
}

std::expected<std::uint32_t, kvmlib::Error> parse_pid(const std::string_view value) {
    std::uint32_t pid{};
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), pid);
    if (error != std::errc{} || end != value.data() + value.size() || pid == 0) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    return pid;
}

std::optional<std::string> parse_guest_field(const std::string_view value) {
    if (value.contains(",,") || value.contains("\\,")) return std::nullopt;
    std::optional<std::string> guest_name;
    std::optional<std::string> bare_name;
    std::size_t begin{};
    while (begin <= value.size()) {
        const auto end = value.find(',', begin);
        const auto field = value.substr(begin, end == std::string_view::npos ? value.size() - begin : end - begin);
        if (field.starts_with("guest=")) {
            if (guest_name) return std::nullopt;
            guest_name = std::string(field.substr(6));
        }
        if (begin == 0 && !field.contains('=') && !field.empty()) bare_name = std::string(field);
        if (begin != 0 && !field.contains('=')) return std::nullopt;
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    return guest_name ? guest_name : bare_name;
}

std::optional<std::string> qemu_guest_name(const std::vector<std::string>& arguments) {
    std::optional<std::string> result;
    bool seen_name{};
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::string_view argument = arguments[index];
        if (argument == "-name") {
            if (seen_name || index + 1 >= arguments.size()) return std::nullopt;
            seen_name = true;
            const auto value = parse_guest_field(arguments[++index]);
            if (!value) return std::nullopt;
            result = *value;
            continue;
        }
        if (argument.starts_with("-name=")) {
            if (seen_name) return std::nullopt;
            seen_name = true;
            const auto value = parse_guest_field(argument.substr(6));
            if (!value) return std::nullopt;
            result = *value;
        }
    }
    return result;
}

std::expected<std::vector<std::string>, kvmlib::Error> read_command_line(const std::filesystem::path& path) {
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return std::unexpected(kvmlib::Error::io_error);
    const std::string raw(std::istreambuf_iterator<char>(stream), {});
    if (stream.bad()) return std::unexpected(kvmlib::Error::io_error);
    std::vector<std::string> arguments;
    std::size_t begin{};
    while (begin < raw.size()) {
        const auto end = raw.find('\0', begin);
        arguments.emplace_back(raw.substr(begin, end == std::string::npos ? raw.size() - begin : end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return arguments;
}

std::expected<std::uint32_t, kvmlib::Error> qemu_pid(const std::string_view guest_name) {
    std::error_code error;
    std::filesystem::directory_iterator entries("/proc", error);
    if (error) return std::unexpected(kvmlib::Error::io_error);
    const std::filesystem::directory_iterator end;
    std::optional<std::uint32_t> match;
    for (; entries != end; entries.increment(error)) {
        if (error) break;
        const auto name = entries->path().filename().string();
        if (name.empty() || !std::ranges::all_of(name, [](const char character) {
                return character >= '0' && character <= '9';
            })) {
            continue;
        }
        const auto pid = parse_pid(name);
        if (!pid) continue;
        std::ifstream comm(entries->path() / "comm");
        std::string executable;
        if (!comm || !std::getline(comm, executable) || !executable.starts_with("qemu-system")) continue;
        const auto arguments = read_command_line(entries->path() / "cmdline");
        if (!arguments) continue;
        const auto actual_guest = qemu_guest_name(*arguments);
        if (!actual_guest || *actual_guest != guest_name) continue;
        if (match) return std::unexpected(kvmlib::Error::invalid_argument);
        match = *pid;
    }
    if (error) return std::unexpected(kvmlib::Error::io_error);
    if (match) return *match;
    return std::unexpected(kvmlib::Error::not_found);
}

class TemporaryFile {
public:
    TemporaryFile() = default;

    TemporaryFile(int descriptor, std::filesystem::path path) noexcept
        : descriptor_(descriptor), path_(std::move(path)) {
    }

    ~TemporaryFile() {
        if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
        if (!path_.empty()) static_cast<void>(::unlink(path_.c_str()));
    }

    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;
    TemporaryFile(TemporaryFile&& other) noexcept
        : descriptor_(std::exchange(other.descriptor_, -1)), path_(std::move(other.path_)) {
        other.path_.clear();
    }

    TemporaryFile& operator=(TemporaryFile&& other) noexcept {
        if (this != &other) {
            if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
            if (!path_.empty()) static_cast<void>(::unlink(path_.c_str()));
            descriptor_ = std::exchange(other.descriptor_, -1);
            path_ = std::move(other.path_);
            other.path_.clear();
        }
        return *this;
    }

    static std::expected<TemporaryFile, kvmlib::Error> create(const std::filesystem::path& output) {
        const auto parent = output.parent_path().empty() ? std::filesystem::path{"."} : output.parent_path();
        static std::atomic_uint64_t sequence{};
        const auto process = static_cast<unsigned long long>(::getpid());
        for (unsigned int attempt{}; attempt < 32; ++attempt) {
            const auto suffix = std::to_string(process) + "." + std::to_string(sequence.fetch_add(1, std::memory_order_relaxed)) + "." + std::to_string(attempt);
            auto path = parent / (std::string{".kvmlib-"} + suffix);
            const int descriptor = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            if (descriptor >= 0) return TemporaryFile{ descriptor, std::move(path) };
            if (errno != EEXIST) return std::unexpected(kvmlib::Error::io_error);
        }
        return std::unexpected(kvmlib::Error::io_error);
    }

    std::expected<void, kvmlib::Error> write(const std::span<const std::byte> bytes) {
        const auto* data = bytes.data();
        std::size_t remaining = bytes.size();
        while (remaining) {
            const auto result = ::write(descriptor_, data, remaining);
            if (result < 0 && errno == EINTR) continue;
            if (result <= 0) return std::unexpected(kvmlib::Error::io_error);
            data += result;
            remaining -= static_cast<std::size_t>(result);
        }
        return {};
    }

    std::expected<void, kvmlib::Error> close_checked() {
        if (descriptor_ < 0) return {};
        const int descriptor = std::exchange(descriptor_, -1);
        if (::close(descriptor) != 0) return std::unexpected(kvmlib::Error::io_error);
        return {};
    }

    std::expected<void, kvmlib::Error> commit(const std::filesystem::path& output) {
        const auto closed = close_checked();
        if (!closed) return std::unexpected(closed.error());
        if (::rename(path_.c_str(), output.c_str()) != 0) return std::unexpected(kvmlib::Error::io_error);
        path_.clear();
        return {};
    }

private:
    int descriptor_{ -1 };
    std::filesystem::path path_;
};

std::expected<void, kvmlib::Error> validate_dump_output(const std::filesystem::path& output) {
    if (output.empty() || output.filename().empty()) return std::unexpected(kvmlib::Error::invalid_argument);
    std::error_code error;
    const auto existing = std::filesystem::symlink_status(output, error);
    if (error && error != std::errc::no_such_file_or_directory) return std::unexpected(kvmlib::Error::io_error);
    if (!error) {
        if (std::filesystem::is_symlink(existing) || !std::filesystem::is_regular_file(existing)) {
            return std::unexpected(kvmlib::Error::invalid_argument);
        }
    }
    error.clear();
    const auto parent = output.parent_path().empty() ? std::filesystem::path{"."} : output.parent_path();
    const auto parent_status = std::filesystem::status(parent, error);
    if (error || !std::filesystem::is_directory(parent_status)) return std::unexpected(kvmlib::Error::io_error);
    return {};
}

std::expected<void, kvmlib::Error> dump_memory(const kvmlib::MemProcFs& backend, const std::uint32_t process_id, const std::uint64_t address, const std::uint64_t size, const std::filesystem::path& output, const bool physical) {
    if ((!physical && !process_id) || !valid_range(address, size)) return std::unexpected(kvmlib::Error::invalid_argument);
    const auto output_status = validate_dump_output(output);
    if (!output_status) return std::unexpected(output_status.error());
    auto file = TemporaryFile::create(output);
    if (!file) return std::unexpected(file.error());
    std::vector<std::byte> buffer(1 << 20);
    for (std::uint64_t offset{}; offset < size;) {
        const auto count = static_cast<std::size_t>((std::min)(std::uint64_t{ buffer.size() }, size - offset));
        const auto result = physical
            ? backend.read_physical(address + offset, std::span{ buffer }.first(count))
            : backend.read(process_id, address + offset, std::span{ buffer }.first(count));
        if (!result || *result != count) return std::unexpected(result ? kvmlib::Error::io_error : result.error());
        const auto written = file->write(std::span{ buffer }.first(count));
        if (!written) return std::unexpected(written.error());
        offset += count;
    }
    return file->commit(output);
}

bool valid_transfer(const kvmlib::MemoryTransfer& transfer) {
    return valid_range(transfer.address, transfer.bytes.size());
}

std::uint64_t page_count(const std::uint64_t address, const std::size_t size) {
    if (!size) return 0;
    const auto first = (std::min)(size, std::size_t{ 0x1000 } - static_cast<std::size_t>(address & 0xfff));
    const auto remaining = size - first;
    return 1 + remaining / 0x1000 + (remaining % 0x1000 != 0);
}

}

namespace kvmlib {

MemProcFs::MemProcFs(std::shared_ptr<MemProcFsSession> session) noexcept
    : session_(std::move(session)) {
}

MemProcFs::~MemProcFs() = default;

MemProcFs::MemProcFs(MemProcFs&& other) noexcept
    : session_(std::move(other.session_)) {
}

MemProcFs& MemProcFs::operator=(MemProcFs&& other) noexcept {
    if (this != &other) session_ = std::move(other.session_);
    return *this;
}

bool MemProcFs::available() noexcept {
    return true;
}

std::expected<MemProcFs, Error> MemProcFs::open(const MemProcFsOptions& options) {
    if (const auto privileged = require_root(); !privileged) return std::unexpected(privileged.error());
    if (options.device.empty()) return std::unexpected(Error::invalid_argument);
    std::vector<std::string> arguments{ "", "-device", options.device };
    if (options.disable_python) arguments.emplace_back("-disable-python");
    if (options.wait_initialize) arguments.emplace_back("-waitinitialize");
    if (options.refresh_mode == RefreshMode::manual) arguments.emplace_back("-norefresh");
    std::vector<const char*> values;
    values.reserve(arguments.size());
    for (const auto& argument : arguments) values.push_back(argument.c_str());
    VmmPtr owner(VMMDLL_Initialize(static_cast<DWORD>(values.size()), values.data()));
    if (!owner) return std::unexpected(failure());
    auto session = std::make_shared<MemProcFsSession>();
    session->handle = static_cast<VMM_HANDLE>(owner.release());
    session->read_flags = read_flags(options.cache_policy);
    return MemProcFs{ std::move(session) };
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(const std::string_view guest_name, const RefreshMode refresh_mode) {
    if (guest_name.empty()) return std::unexpected(Error::invalid_argument);
    return open_qemu(guest_name, std::filesystem::path{"/tmp/qmp-" + std::string(guest_name) + ".sock"}, refresh_mode);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(const std::string_view guest_name, const std::filesystem::path& qmp_path, const RefreshMode refresh_mode) {
    const auto qmp_value = qmp_path.string();
    if (guest_name.empty() || guest_name.contains(',') || guest_name.contains('\0') || qmp_path.empty() || qmp_value.contains(',') || qmp_value.contains('\0')) return std::unexpected(Error::invalid_argument);
    const auto process = qemu_pid(guest_name);
    if (!process) return std::unexpected(process.error());
    return open({
        .device = "qemu://hugepage-pid=" + std::to_string(*process) + ",qmp=" + qmp_value,
        .refresh_mode = refresh_mode,
    });
}

std::expected<void, Error> MemProcFs::refresh() const {
    if (!session_ || !session_->handle) return std::unexpected(Error::invalid_argument);
    if (!VMMDLL_ConfigSet(session_->handle, VMMDLL_OPT_REFRESH_ALL, 1)) return std::unexpected(failure());
    return {};
}

std::expected<void, Error> MemProcFs::refresh_tlb_partial() const {
    if (!session_ || !session_->handle) return std::unexpected(Error::invalid_argument);
    if (!VMMDLL_ConfigSet(session_->handle, VMMDLL_OPT_REFRESH_FREQ_TLB_PARTIAL, 1)) return std::unexpected(failure());
    return {};
}

std::expected<std::vector<ProcessInfo>, Error> MemProcFs::processes() const {
    if (!session_ || !session_->handle) return std::unexpected(Error::invalid_argument);
    PVMMDLL_PROCESS_INFORMATION native{};
    DWORD count{};
    if (!VMMDLL_ProcessGetInformationAll(session_->handle, &native, &count) || (count && !native)) return std::unexpected(failure());
    MemFreePtr<VMMDLL_PROCESS_INFORMATION> owner(native);
    std::vector<ProcessInfo> result;
    result.reserve(count);
    for (DWORD index{}; index < count; ++index) {
        const auto& process = native[index];
        result.push_back({
            process.dwPID,
            process.paDTB,
            process.paDTB_UserOpt,
            process.win.vaEPROCESS,
            process.szNameLong[0] ? process.szNameLong : process.szName
        });
    }
    return result;
}

std::expected<std::uint32_t, Error> MemProcFs::process_id(const std::string_view name) const {
    if (!session_ || !session_->handle || name.empty()) return std::unexpected(Error::invalid_argument);
    const auto expected = lowercase(name);
    const auto list = processes();
    if (!list) return std::unexpected(list.error());
    std::optional<std::uint32_t> match;
    for (const auto& process : *list) {
        if (!process.process_id || lowercase(process.name) != expected) continue;
        if (match) return std::unexpected(Error::invalid_argument);
        match = process.process_id;
    }
    if (match) return *match;
    return std::unexpected(Error::not_found);
}

std::expected<void, Error> MemProcFs::force_process_dtb(const std::uint32_t process_id, const std::uint64_t dtb) const {
    if (!session_ || !session_->handle || !process_id || !dtb) return std::unexpected(Error::invalid_argument);
    const auto option = VMMDLL_OPT_PROCESS_DTB | process_id;
    if (!VMMDLL_ConfigSet(session_->handle, option, dtb & ~std::uint64_t{ 0xFFF })) return std::unexpected(failure());
    return {};
}

std::expected<ProcessInfo, Error> MemProcFs::process_info(const std::uint32_t process_id) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    VMMDLL_PROCESS_INFORMATION native{};
    native.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    native.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    SIZE_T size = sizeof(native);
    if (!VMMDLL_ProcessGetInformation(session_->handle, process_id, &native, &size)) return std::unexpected(Error::not_found);
    return ProcessInfo{
        native.dwPID,
        native.paDTB,
        native.paDTB_UserOpt,
        native.win.vaEPROCESS,
        native.szNameLong[0] ? native.szNameLong : native.szName
    };
}

std::expected<std::vector<ModuleInfo>, Error> MemProcFs::modules(const std::uint32_t process_id) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    PVMMDLL_MAP_MODULE native{};
    if (!VMMDLL_Map_GetModuleU(session_->handle, process_id, &native, 0) || !native) return std::unexpected(failure());
    MemFreePtr<VMMDLL_MAP_MODULE> owner(native);
    if (native->dwVersion != VMMDLL_MAP_MODULE_VERSION) return std::unexpected(failure());
    std::vector<ModuleInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& module = native->pMap[index];
        result.push_back({
            module.vaBase,
            module.vaEntry,
            module.cbImageSize,
            module.cbFileSizeRaw,
            module.fWoW64 != 0,
            module.uszText ? module.uszText : "",
            module.uszFullName ? module.uszFullName : ""
        });
    }
    return result;
}

std::expected<std::vector<ExportInfo>, Error> MemProcFs::exports(const std::uint32_t process_id, const std::string_view module) const {
    if (!session_ || !session_->handle || !process_id || module.empty()) return std::unexpected(Error::invalid_argument);
    const std::string value(module);
    PVMMDLL_MAP_EAT native{};
    if (!VMMDLL_Map_GetEATU(session_->handle, process_id, value.c_str(), &native) || !native) return std::unexpected(failure());
    MemFreePtr<VMMDLL_MAP_EAT> owner(native);
    if (native->dwVersion != VMMDLL_MAP_EAT_VERSION) return std::unexpected(failure());
    std::vector<ExportInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& entry = native->pMap[index];
        result.push_back({
            entry.vaFunction,
            entry.dwOrdinal,
            entry.uszFunction ? entry.uszFunction : "",
            entry.uszForwardedFunction ? entry.uszForwardedFunction : ""
        });
    }
    return result;
}

std::expected<std::vector<HeapInfo>, Error> MemProcFs::heaps(const std::uint32_t process_id) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    PVMMDLL_MAP_HEAP native{};
    if (!VMMDLL_Map_GetHeap(session_->handle, process_id, &native) || !native) return std::unexpected(failure());
    MemFreePtr<VMMDLL_MAP_HEAP> owner(native);
    if (native->dwVersion != VMMDLL_MAP_HEAP_VERSION) return std::unexpected(failure());
    std::vector<HeapInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& heap = native->pMap[index];
        result.push_back({ heap.va, static_cast<std::uint32_t>(heap.tp), heap.iHeap, heap.dwHeapNum, heap.f32 != 0 });
    }
    return result;
}

std::expected<std::vector<HeapAllocation>, Error> MemProcFs::heap_allocations(const std::uint32_t process_id, const std::uint64_t heap_number_or_address) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    PVMMDLL_MAP_HEAPALLOC native{};
    if (!VMMDLL_Map_GetHeapAlloc(session_->handle, process_id, heap_number_or_address, &native) || !native) return std::unexpected(failure());
    MemFreePtr<VMMDLL_MAP_HEAPALLOC> owner(native);
    if (native->dwVersion != VMMDLL_MAP_HEAPALLOC_VERSION) return std::unexpected(failure());
    std::vector<HeapAllocation> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& allocation = native->pMap[index];
        result.push_back({ allocation.va, allocation.cb, static_cast<std::uint32_t>(allocation.tp) });
    }
    return result;
}

std::expected<std::vector<MemoryRange>, Error> MemProcFs::memory_ranges(const std::uint32_t process_id) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    PVMMDLL_MAP_VAD native{};
    if (!VMMDLL_Map_GetVadU(session_->handle, process_id, false, &native) || !native) return std::unexpected(failure());
    MemFreePtr<VMMDLL_MAP_VAD> owner(native);
    if (native->dwVersion != VMMDLL_MAP_VAD_VERSION) return std::unexpected(failure());
    std::vector<MemoryRange> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& range = native->pMap[index];
        result.push_back({
            range.vaStart,
            range.vaEnd,
            range.Protection,
            range.HeapNum,
            range.CommitCharge,
            range.MemCommit != 0,
            range.fPrivateMemory != 0,
            range.fHeap != 0,
            range.fStack != 0,
            range.uszText ? range.uszText : ""
        });
    }
    return result;
}

std::expected<std::uint64_t, Error> MemProcFs::module_base(const std::uint32_t process_id, const std::string_view module) const {
    if (!session_ || !session_->handle || !process_id || module.empty()) return std::unexpected(Error::invalid_argument);
    const std::string value(module);
    const auto base = VMMDLL_ProcessGetModuleBaseU(session_->handle, process_id, value.c_str());
    if (!base) return std::unexpected(Error::not_found);
    return base;
}

std::expected<std::size_t, Error> MemProcFs::read(const std::uint32_t process_id, const std::uint64_t address, const std::span<std::byte> bytes) const {
    if (!session_ || !session_->handle || !process_id || bytes.size() > std::numeric_limits<DWORD>::max() || !valid_range(address, bytes.size())) return std::unexpected(Error::invalid_argument);
    if (bytes.empty()) return std::size_t{};
    DWORD count{};
    const auto ok = VMMDLL_MemReadEx(session_->handle, process_id, address, reinterpret_cast<PBYTE>(bytes.data()), static_cast<DWORD>(bytes.size()), &count, session_->read_flags);
    if (!ok && !count) return std::unexpected(failure());
    return count;
}

std::expected<std::size_t, Error> MemProcFs::write(const std::uint32_t process_id, const std::uint64_t address, const std::span<const std::byte> bytes) const {
    if (!session_ || !session_->handle || !process_id || bytes.size() > std::numeric_limits<DWORD>::max() || !valid_range(address, bytes.size())) return std::unexpected(Error::invalid_argument);
    if (bytes.empty()) return std::size_t{};
    if (!VMMDLL_MemWrite(session_->handle, process_id, address, reinterpret_cast<PBYTE>(const_cast<std::byte*>(bytes.data())), static_cast<DWORD>(bytes.size()))) return std::unexpected(failure());
    return bytes.size();
}

std::expected<std::size_t, Error> MemProcFs::read_physical(const std::uint64_t address, const std::span<std::byte> bytes) const {
    if (!session_ || !session_->handle || bytes.size() > std::numeric_limits<DWORD>::max() || !valid_range(address, bytes.size())) return std::unexpected(Error::invalid_argument);
    if (bytes.empty()) return std::size_t{};
    DWORD count{};
    const auto ok = VMMDLL_MemReadEx(session_->handle, physical_memory, address, reinterpret_cast<PBYTE>(bytes.data()), static_cast<DWORD>(bytes.size()), &count, session_->read_flags);
    if (!ok && !count) return std::unexpected(failure());
    return count;
}

std::expected<void, Error> MemProcFs::scatter_read(const std::uint32_t process_id, const std::span<MemoryTransfer> transfers) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    if (transfers.empty()) return {};
    std::vector<DWORD> counts(transfers.size());
    bool has_data{};
    for (const auto& transfer : transfers) {
        if (!valid_transfer(transfer) || transfer.bytes.size() > std::numeric_limits<DWORD>::max()) return std::unexpected(Error::invalid_argument);
        has_data = has_data || !transfer.bytes.empty();
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    if (!has_data) {
        return {};
    }
    ScatterPtr scatter(VMMDLL_Scatter_Initialize(session_->handle, process_id, session_->read_flags));
    if (!scatter) return std::unexpected(failure());
    bool prepared = true;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        const auto& transfer = transfers[index];
        if (!transfer.bytes.empty()) {
            prepared = VMMDLL_Scatter_PrepareEx(static_cast<VMMDLL_SCATTER_HANDLE>(scatter.get()), transfer.address, static_cast<DWORD>(transfer.bytes.size()), reinterpret_cast<PBYTE>(transfer.bytes.data()), &counts[index]) && prepared;
        }
    }
    const bool executed = prepared && VMMDLL_Scatter_ExecuteRead(static_cast<VMMDLL_SCATTER_HANDLE>(scatter.get()));
    bool complete = executed;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        transfers[index].bytes_read = counts[index];
        complete = complete && counts[index] == transfers[index].bytes.size();
    }
    return complete ? std::expected<void, Error>{} : std::unexpected(failure());
}

std::expected<void, Error> MemProcFs::scatter_write(const std::uint32_t process_id, const std::span<MemoryTransfer> transfers) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    std::uint64_t descriptor_count{};
    for (const auto& transfer : transfers) {
        if (!valid_transfer(transfer)) return std::unexpected(Error::invalid_argument);
        if (transfer.bytes.empty()) continue;
        const auto count = page_count(transfer.address, transfer.bytes.size());
        if (count > std::numeric_limits<DWORD>::max() - descriptor_count) return std::unexpected(Error::invalid_argument);
        descriptor_count += count;
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    if (!descriptor_count) return {};
    std::vector<MEM_SCATTER> descriptors(static_cast<std::size_t>(descriptor_count));
    std::vector<PMEM_SCATTER> pointers(static_cast<std::size_t>(descriptor_count));
    std::vector<std::size_t> descriptor_transfers(static_cast<std::size_t>(descriptor_count));
    std::size_t descriptor_index{};
    for (std::size_t transfer_index{}; transfer_index < transfers.size(); ++transfer_index) {
        const auto& transfer = transfers[transfer_index];
        std::size_t offset{};
        while (offset < transfer.bytes.size()) {
            const auto address = transfer.address + offset;
            const auto count = (std::min)(std::size_t{ 0x1000 } - static_cast<std::size_t>(address & 0xfff), transfer.bytes.size() - offset);
            auto& descriptor = descriptors[descriptor_index];
            descriptor.version = MEM_SCATTER_VERSION;
            descriptor.f = false;
            descriptor.qwA = address;
            descriptor.pb = reinterpret_cast<PBYTE>(transfer.bytes.data() + offset);
            descriptor.cb = static_cast<DWORD>(count);
            descriptor.iStack = 0;
            pointers[descriptor_index] = &descriptor;
            descriptor_transfers[descriptor_index] = transfer_index;
            ++descriptor_index;
            offset += count;
        }
    }
    const auto completed = VMMDLL_MemWriteScatter(session_->handle, process_id, pointers.data(), static_cast<DWORD>(pointers.size()));
    std::size_t successful_pages{};
    for (std::size_t index{}; index < descriptors.size(); ++index) {
        if (!descriptors[index].f) continue;
        ++successful_pages;
        transfers[descriptor_transfers[index]].bytes_read += descriptors[index].cb;
    }
    bool complete = completed == successful_pages;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        complete = complete && transfers[index].bytes_read == transfers[index].bytes.size();
    }
    if (complete) return {};
    if (successful_pages) return std::unexpected(Error::partial_write);
    return std::unexpected(Error::io_error);
}

std::expected<MemProcFsReadBatch, Error> MemProcFs::read_batch(const std::uint32_t process_id) const {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    return MemProcFsReadBatch{ session_, process_id };
}

std::expected<void, Error> MemProcFs::dump_process(const std::uint32_t process_id, const std::uint64_t address, const std::uint64_t size, const std::filesystem::path& output) const {
    if (!session_ || !session_->handle) return std::unexpected(Error::invalid_argument);
    return dump_memory(*this, process_id, address, size, output, false);
}

std::expected<void, Error> MemProcFs::dump_physical(const std::uint64_t address, const std::uint64_t size, const std::filesystem::path& output) const {
    if (!session_ || !session_->handle) return std::unexpected(Error::invalid_argument);
    return dump_memory(*this, 0, address, size, output, true);
}

MemProcFsReadBatch::MemProcFsReadBatch(std::shared_ptr<MemProcFsSession> session, const std::uint32_t process_id) noexcept
    : session_(std::move(session)), process_id_(process_id) {
}

MemProcFsReadBatch::~MemProcFsReadBatch() {
    ScatterPtr scatter(scatter_);
    scatter_ = nullptr;
}

MemProcFsReadBatch::MemProcFsReadBatch(MemProcFsReadBatch&& other) noexcept
    : session_(std::move(other.session_)), process_id_(std::exchange(other.process_id_, 0)), scatter_(std::exchange(other.scatter_, nullptr)), counts_(std::move(other.counts_)), prepared_transfers_(std::move(other.prepared_transfers_)), prepared_(std::exchange(other.prepared_, false)) {
}

MemProcFsReadBatch& MemProcFsReadBatch::operator=(MemProcFsReadBatch&& other) noexcept {
    if (this != &other) {
        {
            ScatterPtr scatter(scatter_);
            scatter_ = nullptr;
        }
        scatter_ = std::exchange(other.scatter_, nullptr);
        session_ = std::move(other.session_);
        process_id_ = std::exchange(other.process_id_, 0);
        counts_ = std::move(other.counts_);
        prepared_transfers_ = std::move(other.prepared_transfers_);
        prepared_ = std::exchange(other.prepared_, false);
    }
    return *this;
}

bool MemProcFsReadBatch::valid() const noexcept {
    return session_ && session_->handle && process_id_ != 0;
}

std::expected<void, Error> MemProcFsReadBatch::clear() {
    if (!valid()) return std::unexpected(Error::invalid_argument);
    if (scatter_ && !VMMDLL_Scatter_Clear(static_cast<VMMDLL_SCATTER_HANDLE>(scatter_), process_id_, session_->read_flags)) {
        ScatterPtr scatter(scatter_);
        scatter_ = nullptr;
        prepared_ = false;
        prepared_transfers_.clear();
        counts_.clear();
        return std::unexpected(failure());
    }
    prepared_ = false;
    prepared_transfers_.clear();
    counts_.clear();
    return {};
}

std::expected<void, Error> MemProcFsReadBatch::execute(const std::span<MemoryTransfer> transfers) {
    if (!valid()) return std::unexpected(Error::invalid_argument);
    for (const auto& transfer : transfers) {
        if (!valid_transfer(transfer) || transfer.bytes.size() > std::numeric_limits<DWORD>::max()) return std::unexpected(Error::invalid_argument);
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    const auto has_data = std::ranges::any_of(transfers, [](const auto& transfer) {
        return !transfer.bytes.empty();
    });
    if (!has_data) {
        return clear();
    }
    bool same = prepared_ && prepared_transfers_.size() == transfers.size();
    if (same) {
        for (std::size_t index{}; index < transfers.size(); ++index) {
            const auto& prepared = prepared_transfers_[index];
            if (prepared.address != transfers[index].address || prepared.data != transfers[index].bytes.data() || prepared.size != transfers[index].bytes.size()) {
                same = false;
                break;
            }
        }
    }
    if (!same) {
        if (scatter_ && !VMMDLL_Scatter_Clear(static_cast<VMMDLL_SCATTER_HANDLE>(scatter_), process_id_, session_->read_flags)) {
            ScatterPtr scatter(scatter_);
            scatter_ = nullptr;
            prepared_ = false;
            prepared_transfers_.clear();
            counts_.clear();
            return std::unexpected(failure());
        }
        prepared_ = false;
        prepared_transfers_.clear();
        if (!scatter_) {
            scatter_ = VMMDLL_Scatter_Initialize(session_->handle, process_id_, session_->read_flags);
            if (!scatter_) return std::unexpected(failure());
        }
        counts_.assign(transfers.size(), 0);
        prepared_transfers_.resize(transfers.size());
        bool prepared = true;
        for (std::size_t index{}; index < transfers.size(); ++index) {
            const auto& transfer = transfers[index];
            prepared_transfers_[index] = { transfer.address, transfer.bytes.data(), transfer.bytes.size() };
            if (!transfer.bytes.empty()) {
                prepared = VMMDLL_Scatter_PrepareEx(static_cast<VMMDLL_SCATTER_HANDLE>(scatter_), transfer.address, static_cast<DWORD>(transfer.bytes.size()), reinterpret_cast<PBYTE>(transfer.bytes.data()), reinterpret_cast<PDWORD>(&counts_[index])) && prepared;
            }
        }
        if (!prepared) {
            ScatterPtr scatter(scatter_);
            scatter_ = nullptr;
            prepared_ = false;
            prepared_transfers_.clear();
            counts_.clear();
            return std::unexpected(failure());
        }
        prepared_ = true;
    } else {
        std::fill(counts_.begin(), counts_.end(), 0);
    }
    const bool executed = VMMDLL_Scatter_ExecuteRead(static_cast<VMMDLL_SCATTER_HANDLE>(scatter_));
    bool complete = executed;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        transfers[index].bytes_read = counts_[index];
        complete = complete && counts_[index] == transfers[index].bytes.size();
    }
    return complete ? std::expected<void, Error>{} : std::unexpected(failure());
}

std::expected<void, Error> MemProcFsReadBatch::rebind(const std::uint32_t process_id) {
    if (!session_ || !session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    {
        ScatterPtr scatter(scatter_);
        scatter_ = nullptr;
    }
    process_id_ = process_id;
    counts_.clear();
    prepared_transfers_.clear();
    prepared_ = false;
    return {};
}

std::expected<void, Error> MemProcFsReadBatch::rebind(const MemProcFs& backend, const std::uint32_t process_id) {
    if (!backend.session_ || !backend.session_->handle || !process_id) return std::unexpected(Error::invalid_argument);
    {
        ScatterPtr scatter(scatter_);
        scatter_ = nullptr;
    }
    session_ = backend.session_;
    process_id_ = process_id;
    counts_.clear();
    prepared_transfers_.clear();
    prepared_ = false;
    return {};
}

}
