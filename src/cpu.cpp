#include "kvmlib/cpu.hpp"

#include <algorithm>
#include <charconv>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

namespace {

kvmlib::Error filesystem_error(const std::filesystem::path& path) {
    std::error_code error;
    const auto status = std::filesystem::status(path, error);
    if (error) {
        if (error == std::errc::permission_denied) {
            return kvmlib::Error::permission_denied;
        }
        if (error == std::errc::no_such_file_or_directory) {
            return kvmlib::Error::not_found;
        }
        return kvmlib::Error::io_error;
    }
    return std::filesystem::exists(status) ? kvmlib::Error::io_error : kvmlib::Error::not_found;
}

std::string_view trim(const std::string_view value) {
    std::size_t first{};
    while (first < value.size()
        && std::isspace(static_cast<unsigned char>(value[first])) != 0) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first
        && std::isspace(static_cast<unsigned char>(value[last - 1])) != 0) {
        --last;
    }
    return value.substr(first, last - first);
}

std::expected<std::uint32_t, kvmlib::Error> parse_number(const std::string_view value) {
    const auto text = trim(value);
    if (text.empty()) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    std::uint32_t result{};
    const auto parsed = std::from_chars(text.data(), text.data() + text.size(), result, 10);
    if (parsed.ec != std::errc{} || parsed.ptr != text.data() + text.size()) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    return result;
}

std::expected<std::vector<std::uint32_t>, kvmlib::Error> parse_cpu_list(
    const std::string_view value) {
    std::vector<std::uint32_t> result;
    std::size_t position{};
    while (position <= value.size()) {
        const auto separator = value.find(',', position);
        const auto segment = trim(value.substr(
            position, separator == std::string_view::npos ? std::string_view::npos : separator - position));
        if (segment.empty()) {
            return std::unexpected(kvmlib::Error::parse_error);
        }

        const auto dash = segment.find('-');
        if (dash != std::string_view::npos && segment.find('-', dash + 1) != std::string_view::npos) {
            return std::unexpected(kvmlib::Error::parse_error);
        }
        const auto first = parse_number(dash == std::string_view::npos
            ? segment
            : segment.substr(0, dash));
        const auto last = dash == std::string_view::npos
            ? first
            : parse_number(segment.substr(dash + 1));
        if (!first || !last || *first > *last) {
            return std::unexpected(kvmlib::Error::parse_error);
        }

        const auto count = static_cast<std::uint64_t>(*last)
            - static_cast<std::uint64_t>(*first) + 1;
        if (count > result.max_size() - result.size()) {
            return std::unexpected(kvmlib::Error::parse_error);
        }
        for (std::uint64_t current = *first; current <= *last; ++current) {
            result.push_back(static_cast<std::uint32_t>(current));
        }

        if (separator == std::string_view::npos) {
            break;
        }
        position = separator + 1;
    }
    return result;
}

std::expected<std::string, kvmlib::Error> read_line(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input) {
        return std::unexpected(filesystem_error(path));
    }
    std::string value;
    if (!std::getline(input, value)) {
        return std::unexpected(input.bad() ? kvmlib::Error::io_error : kvmlib::Error::parse_error);
    }
    std::string extra;
    if (input >> extra) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    if (input.bad()) {
        return std::unexpected(kvmlib::Error::io_error);
    }
    return value;
}

std::expected<std::uint32_t, kvmlib::Error> read_number(const std::filesystem::path& path) {
    const auto text = read_line(path);
    if (!text) {
        return std::unexpected(text.error());
    }
    return parse_number(*text);
}

std::expected<std::vector<std::uint32_t>, kvmlib::Error> read_cpu_list(
    const std::filesystem::path& path) {
    const auto text = read_line(path);
    if (!text) {
        return std::unexpected(text.error());
    }
    return parse_cpu_list(*text);
}

bool has_virtualization_flag() {
    std::ifstream input("/proc/cpuinfo");
    std::string line;
    while (std::getline(input, line)) {
        if ((line.starts_with("flags") || line.starts_with("Features"))
            && (line.contains(" vmx") || line.contains(" svm"))) {
            return true;
        }
    }
    return false;
}

}

namespace kvmlib {

std::uint32_t CpuTopology::physical_core_count() const {
    std::set<std::pair<std::uint32_t, std::uint32_t>> cores;
    for (const auto& thread : threads) {
        cores.emplace(thread.package_id, thread.core_id);
    }
    return static_cast<std::uint32_t>(cores.size());
}

bool CpuTopology::smt_enabled() const {
    return std::any_of(threads.begin(), threads.end(), [](const CpuThread& thread) {
        return thread.siblings.size() > 1;
    });
}

const CpuThread* CpuTopology::find(const std::uint32_t logical_id) const {
    const auto found = std::ranges::find(threads, logical_id, &CpuThread::logical_id);
    return found == threads.end() ? nullptr : &*found;
}

std::expected<CpuTopology, Error> cpu_topology() {
    const std::filesystem::path root{ "/sys/devices/system/cpu" };
    std::error_code root_error;
    if (!std::filesystem::exists(root, root_error)) {
        return std::unexpected(root_error ? Error::io_error : Error::unsupported);
    }
    if (!std::filesystem::is_directory(root, root_error)) {
        return std::unexpected(root_error ? Error::io_error : Error::unsupported);
    }

    const auto online = read_cpu_list(root / "online");
    if (!online) {
        return std::unexpected(online.error());
    }
    if (online->empty()) {
        return std::unexpected(Error::not_found);
    }

    CpuTopology topology;
    topology.threads.reserve(online->size());
    for (const auto logical_id : *online) {
        const auto cpu_path = root / ("cpu" + std::to_string(logical_id));
        std::error_code cpu_error;
        if (!std::filesystem::is_directory(cpu_path, cpu_error)) {
            return std::unexpected(cpu_error ? Error::io_error : Error::not_found);
        }

        const auto core = read_number(cpu_path / "topology/core_id");
        const auto package = read_number(cpu_path / "topology/physical_package_id");
        const auto sibling_text = read_line(cpu_path / "topology/thread_siblings_list");
        if (!core) {
            return std::unexpected(core.error());
        }
        if (!package) {
            return std::unexpected(package.error());
        }
        if (!sibling_text) {
            return std::unexpected(sibling_text.error());
        }
        const auto siblings = parse_cpu_list(*sibling_text);
        if (!siblings || siblings->empty()) {
            return std::unexpected(siblings ? Error::parse_error : siblings.error());
        }

        topology.threads.push_back({ logical_id, *package, *core, *siblings });
    }

    const auto current_online = read_cpu_list(root / "online");
    if (!current_online) {
        return std::unexpected(current_online.error());
    }
    if (*current_online != *online) {
        return std::unexpected(Error::io_error);
    }

    std::ranges::sort(topology.threads, {}, &CpuThread::logical_id);
    return topology;
}

std::expected<KvmStatus, Error> kvm_status() {
    const std::filesystem::path device{ "/dev/kvm" };
    std::error_code error;
    const bool present = std::filesystem::exists(device, error);
    if (error) {
        return std::unexpected(Error::io_error);
    }
    const bool accessible = present && ::access(device.c_str(), R_OK | W_OK) == 0;
    return KvmStatus{ present, accessible, has_virtualization_flag() };
}

}
