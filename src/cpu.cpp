#include "kvmlib/cpu.hpp"

#include "detail.hpp"

#include <algorithm>
#include <charconv>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>
#include <utility>

namespace {

using kvmlib::Error;

std::string_view trim(std::string_view text) noexcept {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string_view::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

std::expected<std::uint32_t, Error> parse_cpu_id(const std::string_view text) {
    std::uint32_t result{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), result);
    if (text.empty() || error != std::errc{} || end != text.data() + text.size()) {
        return std::unexpected(Error::parse_error);
    }
    return result;
}

std::expected<std::vector<std::uint32_t>, Error> parse_cpu_list(std::string_view text) {
    std::vector<std::uint32_t> cpus;
    while (!text.empty()) {
        const auto comma = text.find(',');
        auto item = trim(text.substr(0, comma));
        if (item.empty()) return std::unexpected(Error::parse_error);

        const auto dash = item.find('-');
        if (dash != std::string_view::npos && item.find('-', dash + 1) != std::string_view::npos) {
            return std::unexpected(Error::parse_error);
        }
        const auto first = parse_cpu_id(dash == std::string_view::npos ? item : item.substr(0, dash));
        const auto last = dash == std::string_view::npos ? first : parse_cpu_id(item.substr(dash + 1));
        if (!first || !last || *first > *last) return std::unexpected(Error::parse_error);

        const auto count = static_cast<std::uint64_t>(*last) - *first + 1;
        if (count > cpus.max_size() - cpus.size()) return std::unexpected(Error::parse_error);
        for (std::uint64_t cpu = *first; cpu <= *last; ++cpu) {
            cpus.push_back(static_cast<std::uint32_t>(cpu));
        }
        if (comma == std::string_view::npos) break;
        if (comma + 1 == text.size()) return std::unexpected(Error::parse_error);
        text.remove_prefix(comma + 1);
    }
    if (text.empty() && !cpus.empty()) return cpus;
    if (cpus.empty()) return std::unexpected(Error::parse_error);
    return cpus;
}

std::expected<std::string, Error> read_single_line(const std::filesystem::path& path) {
    std::ifstream stream(path);
    if (!stream) {
        return std::unexpected(kvmlib::detail::from_errno());
    }
    std::string value;
    if (!std::getline(stream, value)) {
        return std::unexpected(stream.bad() ? Error::io_error : Error::parse_error);
    }
    std::string trailing;
    if (stream >> trailing) return std::unexpected(Error::parse_error);
    if (stream.bad()) return std::unexpected(Error::io_error);
    return value;
}

std::expected<std::uint32_t, Error> read_cpu_id(const std::filesystem::path& path) {
    const auto text = read_single_line(path);
    return text ? parse_cpu_id(*text) : std::unexpected(text.error());
}

std::expected<std::vector<std::uint32_t>, Error> read_cpu_list(const std::filesystem::path& path) {
    const auto text = read_single_line(path);
    return text ? parse_cpu_list(*text) : std::unexpected(text.error());
}

bool has_virtualization_flag() {
    std::ifstream stream("/proc/cpuinfo");
    if (!stream) return false;
    std::string line;
    while (std::getline(stream, line)) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        const auto label = trim(std::string_view(line).substr(0, colon));
        if (label != "flags" && label != "Features") continue;
        std::string_view flags(line);
        flags.remove_prefix(colon + 1);
        while (!flags.empty()) {
            flags = trim(flags);
            if (flags.empty()) break;
            const auto space = flags.find_first_of(" \t");
            const auto flag = flags.substr(0, space);
            if (flag == "vmx" || flag == "svm") return true;
            if (space == std::string_view::npos) break;
            flags.remove_prefix(space + 1);
        }
    }
    return false;
}

}

namespace kvmlib {

std::uint32_t CpuTopology::physical_core_count() const {
    std::vector<std::pair<std::uint32_t, std::uint32_t>> cores;
    cores.reserve(threads.size());
    for (const auto& thread : threads) cores.emplace_back(thread.package_id, thread.core_id);
    std::ranges::sort(cores);
    const auto unique_end = std::ranges::unique(cores).begin();
    return static_cast<std::uint32_t>(std::distance(cores.begin(), unique_end));
}

bool CpuTopology::smt_enabled() const {
    return std::ranges::any_of(threads, [](const CpuThread& thread) {
        return thread.siblings.size() > 1;
    });
}

const CpuThread* CpuTopology::find(const std::uint32_t logical_id) const {
    const auto found = std::ranges::find(threads, logical_id, &CpuThread::logical_id);
    return found == threads.end() ? nullptr : std::addressof(*found);
}

std::expected<CpuTopology, Error> cpu_topology() {
    const std::filesystem::path root{"/sys/devices/system/cpu"};
    std::error_code error;
    const bool exists = std::filesystem::exists(root, error);
    if (error) return std::unexpected(detail::from_error_code(error));
    if (!exists) return std::unexpected(Error::unsupported);
    if (!std::filesystem::is_directory(root, error)) {
        return std::unexpected(error ? detail::from_error_code(error) : Error::unsupported);
    }

    const auto online = read_cpu_list(root / "online");
    if (!online) return std::unexpected(online.error());
    if (online->empty()) return std::unexpected(Error::not_found);

    CpuTopology result;
    result.threads.reserve(online->size());
    for (const auto logical_id : *online) {
        const auto cpu_root = root / ("cpu" + std::to_string(logical_id));
        if (!std::filesystem::is_directory(cpu_root, error)) {
            return std::unexpected(error ? detail::from_error_code(error) : Error::not_found);
        }
        const auto core = read_cpu_id(cpu_root / "topology/core_id");
        const auto package = read_cpu_id(cpu_root / "topology/physical_package_id");
        const auto siblings = read_cpu_list(cpu_root / "topology/thread_siblings_list");
        if (!core) return std::unexpected(core.error());
        if (!package) return std::unexpected(package.error());
        if (!siblings || siblings->empty()) {
            return std::unexpected(siblings ? Error::parse_error : siblings.error());
        }
        result.threads.push_back({logical_id, *package, *core, *siblings});
    }

    const auto online_after = read_cpu_list(root / "online");
    if (!online_after) return std::unexpected(online_after.error());
    if (*online_after != *online) return std::unexpected(Error::io_error);
    std::ranges::sort(result.threads, {}, &CpuThread::logical_id);
    return result;
}

std::expected<KvmStatus, Error> kvm_status() {
    const std::filesystem::path device{"/dev/kvm"};
    std::error_code error;
    const bool present = std::filesystem::exists(device, error);
    if (error) return std::unexpected(detail::from_error_code(error));
    const bool accessible = present && ::access(device.c_str(), R_OK | W_OK) == 0;
    return KvmStatus{present, accessible, has_virtualization_flag()};
}

}
