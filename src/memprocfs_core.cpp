#include "memprocfs_detail.hpp"

#include "detail.hpp"
#include "kvmlib/privilege.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace {

using kvmlib::Error;

struct VmmDeleter {
    void operator()(void* pointer) const noexcept {
        if (pointer) VMMDLL_Close(static_cast<VMM_HANDLE>(pointer));
    }
};
using VmmPtr = std::unique_ptr<void, VmmDeleter>;

bool equal_case_insensitive(const std::string_view left, const std::string_view right) noexcept {
    return left.size() == right.size() && std::ranges::equal(left, right,
        [](const char lhs, const char rhs) {
            return std::tolower(static_cast<unsigned char>(lhs))
                == std::tolower(static_cast<unsigned char>(rhs));
        });
}

std::expected<std::uint32_t, Error> parse_pid(const std::string_view text) {
    std::uint32_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size() || value == 0) {
        return std::unexpected(Error::parse_error);
    }
    return value;
}

std::optional<std::string> guest_field(const std::string_view value) {
    if (value.contains(",,") || value.contains("\\,")) return std::nullopt;
    std::optional<std::string> guest;
    std::optional<std::string> unnamed;
    std::size_t begin{};
    while (begin <= value.size()) {
        const auto end = value.find(',', begin);
        const auto field = value.substr(begin,
            end == std::string_view::npos ? value.size() - begin : end - begin);
        if (field.starts_with("guest=")) {
            if (guest) return std::nullopt;
            guest = field.substr(6);
        } else if (begin == 0 && !field.empty() && !field.contains('=')) {
            unnamed = field;
        } else if (begin != 0 && !field.contains('=')) {
            return std::nullopt;
        }
        if (end == std::string_view::npos) break;
        begin = end + 1;
    }
    return guest ? guest : unnamed;
}

std::optional<std::string> qemu_name(const std::vector<std::string>& arguments) {
    bool seen{};
    std::optional<std::string> result;
    for (std::size_t index = 1; index < arguments.size(); ++index) {
        const std::string_view argument(arguments[index]);
        std::string_view value;
        if (argument == "-name") {
            if (seen || index + 1 >= arguments.size()) return std::nullopt;
            seen = true;
            value = arguments[++index];
        } else if (argument.starts_with("-name=")) {
            if (seen) return std::nullopt;
            seen = true;
            value = argument.substr(6);
        } else {
            continue;
        }
        result = guest_field(value);
        if (!result) return std::nullopt;
    }
    return result;
}

std::expected<std::vector<std::string>, Error> process_arguments(const std::filesystem::path& file) {
    std::ifstream input(file, std::ios::binary);
    if (!input) return std::unexpected(Error::io_error);
    const std::string bytes(std::istreambuf_iterator<char>(input), {});
    if (input.bad()) return std::unexpected(Error::io_error);
    std::vector<std::string> result;
    result.reserve(24);
    for (std::size_t begin{}; begin < bytes.size();) {
        const auto end = bytes.find('\0', begin);
        result.emplace_back(bytes.substr(begin,
            end == std::string::npos ? bytes.size() - begin : end - begin));
        if (end == std::string::npos) break;
        begin = end + 1;
    }
    return result;
}

std::expected<std::uint32_t, Error> find_qemu_pid(const std::string_view expected_name) {
    std::error_code error;
    std::filesystem::directory_iterator current("/proc", error);
    if (error) return std::unexpected(kvmlib::detail::from_error_code(error));
    const std::filesystem::directory_iterator end;
    std::optional<std::uint32_t> match;
    for (; current != end; current.increment(error)) {
        if (error) break;
        const auto directory = current->path();
        const auto name = directory.filename().string();
        if (name.empty() || !std::ranges::all_of(name, [](const char value) {
                return value >= '0' && value <= '9';
            })) {
            continue;
        }
        const auto pid = parse_pid(name);
        if (!pid) continue;
        std::ifstream comm(directory / "comm");
        std::string executable;
        if (!comm || !std::getline(comm, executable) || !executable.starts_with("qemu-system")) {
            continue;
        }
        const auto arguments = process_arguments(directory / "cmdline");
        if (!arguments) continue;
        const auto actual_name = qemu_name(*arguments);
        if (!actual_name || *actual_name != expected_name) continue;
        if (match) return std::unexpected(Error::invalid_argument);
        match = *pid;
    }
    if (error) return std::unexpected(kvmlib::detail::from_error_code(error));
    return match ? std::expected<std::uint32_t, Error>{*match}
                 : std::unexpected(Error::not_found);
}

}

namespace kvmlib {

MemProcFs::MemProcFs(std::shared_ptr<MemProcFsSession> session) noexcept
    : session_(std::move(session)) {}

MemProcFs::~MemProcFs() = default;
MemProcFs::MemProcFs(MemProcFs&& other) noexcept = default;
MemProcFs& MemProcFs::operator=(MemProcFs&& other) noexcept = default;

bool MemProcFs::available() noexcept {
    return true;
}

std::expected<MemProcFs, Error> MemProcFs::open(const MemProcFsOptions& options) {
    if (const auto root = require_root(); !root) return std::unexpected(root.error());
    if (options.device.empty() || options.device.contains('\0')) {
        return std::unexpected(Error::invalid_argument);
    }

    std::vector<std::string> arguments{"", "-device", options.device};
    if (options.disable_python) arguments.emplace_back("-disable-python");
    if (options.wait_initialize) arguments.emplace_back("-waitinitialize");
    if (options.refresh_mode == RefreshMode::manual) arguments.emplace_back("-norefresh");
    std::vector<const char*> argv;
    argv.reserve(arguments.size());
    for (const auto& argument : arguments) argv.push_back(argument.c_str());

    VmmPtr native(VMMDLL_Initialize(static_cast<DWORD>(argv.size()), argv.data()));
    if (!native) return std::unexpected(Error::io_error);
    auto session = std::make_shared<MemProcFsSession>();
    session->handle = static_cast<VMM_HANDLE>(native.release());
    session->read_flags = options.cache_policy == MemoryCachePolicy::fresh
        ? VMMDLL_FLAG_NOCACHE : 0;
    return MemProcFs{std::move(session)};
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(
    const std::string_view guest_name,
    const RefreshMode refresh_mode) {
    if (guest_name.empty()) return std::unexpected(Error::invalid_argument);
    return open_qemu(guest_name,
        std::filesystem::path("/tmp/qmp-" + std::string(guest_name) + ".sock"),
        refresh_mode);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(
    const std::string_view guest_name,
    const std::filesystem::path& qmp_path,
    const RefreshMode refresh_mode) {
    const auto qmp = qmp_path.string();
    if (guest_name.empty() || guest_name.contains(',') || guest_name.contains('\0')
        || qmp_path.empty() || qmp.contains(',') || qmp.contains('\0')) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto pid = find_qemu_pid(guest_name);
    if (!pid) return std::unexpected(pid.error());
    return open({
        .device = "qemu://hugepage-pid=" + std::to_string(*pid) + ",qmp=" + qmp,
        .refresh_mode = refresh_mode
    });
}

std::expected<void, Error> MemProcFs::refresh() const {
    if (!detail::session_ready(session_)) return std::unexpected(Error::invalid_argument);
    return VMMDLL_ConfigSet(session_->handle, VMMDLL_OPT_REFRESH_ALL, 1)
        ? std::expected<void, Error>{} : std::unexpected(Error::io_error);
}

std::expected<void, Error> MemProcFs::refresh_tlb_partial() const {
    if (!detail::session_ready(session_)) return std::unexpected(Error::invalid_argument);
    return VMMDLL_ConfigSet(session_->handle, VMMDLL_OPT_REFRESH_FREQ_TLB_PARTIAL, 1)
        ? std::expected<void, Error>{} : std::unexpected(Error::io_error);
}

std::expected<std::vector<ProcessInfo>, Error> MemProcFs::processes() const {
    if (!detail::session_ready(session_)) return std::unexpected(Error::invalid_argument);
    PVMMDLL_PROCESS_INFORMATION native{};
    DWORD count{};
    if (!VMMDLL_ProcessGetInformationAll(session_->handle, &native, &count)
        || (count != 0 && native == nullptr)) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_PROCESS_INFORMATION> owner(native);
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
    if (!detail::session_ready(session_) || name.empty() || name.contains('\0')) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto list = processes();
    if (!list) return std::unexpected(list.error());
    std::optional<std::uint32_t> match;
    for (const auto& process : *list) {
        if (process.process_id == 0 || !equal_case_insensitive(process.name, name)) continue;
        if (match) return std::unexpected(Error::invalid_argument);
        match = process.process_id;
    }
    return match ? std::expected<std::uint32_t, Error>{*match}
                 : std::unexpected(Error::not_found);
}

std::expected<void, Error> MemProcFs::force_process_dtb(
    const std::uint32_t process_id,
    const std::uint64_t dtb) const {
    const auto aligned = dtb & ~std::uint64_t{0xFFF};
    if (!detail::session_ready(session_) || process_id == 0 || aligned == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto option = VMMDLL_OPT_PROCESS_DTB | process_id;
    return VMMDLL_ConfigSet(session_->handle, option, aligned)
        ? std::expected<void, Error>{} : std::unexpected(Error::io_error);
}

std::expected<ProcessInfo, Error> MemProcFs::process_info(const std::uint32_t process_id) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    VMMDLL_PROCESS_INFORMATION native{};
    native.magic = VMMDLL_PROCESS_INFORMATION_MAGIC;
    native.wVersion = VMMDLL_PROCESS_INFORMATION_VERSION;
    SIZE_T size = sizeof(native);
    if (!VMMDLL_ProcessGetInformation(session_->handle, process_id, &native, &size)) {
        return std::unexpected(Error::not_found);
    }
    return ProcessInfo{
        native.dwPID, native.paDTB, native.paDTB_UserOpt, native.win.vaEPROCESS,
        native.szNameLong[0] ? native.szNameLong : native.szName
    };
}

std::expected<std::vector<ModuleInfo>, Error> MemProcFs::modules(const std::uint32_t process_id) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_MODULE native{};
    if (!VMMDLL_Map_GetModuleU(session_->handle, process_id, &native, 0) || !native) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_MAP_MODULE> owner(native);
    if (native->dwVersion != VMMDLL_MAP_MODULE_VERSION) return std::unexpected(Error::io_error);
    std::vector<ModuleInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& module = native->pMap[index];
        result.push_back({
            module.vaBase, module.vaEntry, module.cbImageSize, module.cbFileSizeRaw,
            module.fWoW64 != 0, module.uszText ? module.uszText : "",
            module.uszFullName ? module.uszFullName : ""
        });
    }
    return result;
}

std::expected<std::vector<ExportInfo>, Error> MemProcFs::exports(
    const std::uint32_t process_id,
    const std::string_view module) const {
    if (!detail::session_ready(session_) || process_id == 0 || module.empty()
        || module.contains('\0')) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string module_name(module);
    PVMMDLL_MAP_EAT native{};
    if (!VMMDLL_Map_GetEATU(session_->handle, process_id, module_name.c_str(), &native)
        || !native) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_MAP_EAT> owner(native);
    if (native->dwVersion != VMMDLL_MAP_EAT_VERSION) return std::unexpected(Error::io_error);
    std::vector<ExportInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& item = native->pMap[index];
        result.push_back({
            item.vaFunction, item.dwOrdinal,
            item.uszFunction ? item.uszFunction : "",
            item.uszForwardedFunction ? item.uszForwardedFunction : ""
        });
    }
    return result;
}

std::expected<std::vector<HeapInfo>, Error> MemProcFs::heaps(const std::uint32_t process_id) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_HEAP native{};
    if (!VMMDLL_Map_GetHeap(session_->handle, process_id, &native) || !native) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_MAP_HEAP> owner(native);
    if (native->dwVersion != VMMDLL_MAP_HEAP_VERSION) return std::unexpected(Error::io_error);
    std::vector<HeapInfo> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& heap = native->pMap[index];
        result.push_back({
            heap.va, static_cast<std::uint32_t>(heap.tp), heap.iHeap,
            heap.dwHeapNum, heap.f32 != 0
        });
    }
    return result;
}

std::expected<std::vector<HeapAllocation>, Error> MemProcFs::heap_allocations(
    const std::uint32_t process_id,
    const std::uint64_t heap_number_or_address) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_HEAPALLOC native{};
    if (!VMMDLL_Map_GetHeapAlloc(session_->handle, process_id, heap_number_or_address, &native)
        || !native) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_MAP_HEAPALLOC> owner(native);
    if (native->dwVersion != VMMDLL_MAP_HEAPALLOC_VERSION) return std::unexpected(Error::io_error);
    std::vector<HeapAllocation> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& allocation = native->pMap[index];
        result.push_back({
            allocation.va, allocation.cb, static_cast<std::uint32_t>(allocation.tp)
        });
    }
    return result;
}

std::expected<std::vector<MemoryRange>, Error> MemProcFs::memory_ranges(
    const std::uint32_t process_id) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    PVMMDLL_MAP_VAD native{};
    if (!VMMDLL_Map_GetVadU(session_->handle, process_id, false, &native) || !native) {
        return std::unexpected(Error::io_error);
    }
    detail::MemFreePtr<VMMDLL_MAP_VAD> owner(native);
    if (native->dwVersion != VMMDLL_MAP_VAD_VERSION) return std::unexpected(Error::io_error);
    std::vector<MemoryRange> result;
    result.reserve(native->cMap);
    for (DWORD index{}; index < native->cMap; ++index) {
        const auto& range = native->pMap[index];
        result.push_back({
            range.vaStart, range.vaEnd, range.Protection, range.HeapNum,
            range.CommitCharge, range.MemCommit != 0, range.fPrivateMemory != 0,
            range.fHeap != 0, range.fStack != 0, range.uszText ? range.uszText : ""
        });
    }
    return result;
}

std::expected<std::uint64_t, Error> MemProcFs::module_base(
    const std::uint32_t process_id,
    const std::string_view module) const {
    if (!detail::session_ready(session_) || process_id == 0 || module.empty()
        || module.contains('\0')) {
        return std::unexpected(Error::invalid_argument);
    }
    const std::string module_name(module);
    const auto base = VMMDLL_ProcessGetModuleBaseU(session_->handle, process_id, module_name.c_str());
    return base ? std::expected<std::uint64_t, Error>{base}
                : std::unexpected(Error::not_found);
}

std::expected<MemProcFsReadBatch, Error> MemProcFs::read_batch(
    const std::uint32_t process_id) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    return MemProcFsReadBatch{session_, process_id};
}

}
