#include "kvmlib/memory.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <sstream>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>

namespace {

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) {
        return kvmlib::Error::permission_denied;
    }
    if (errno == ENOENT || errno == ESRCH) {
        return kvmlib::Error::not_found;
    }
    return kvmlib::Error::io_error;
}

std::expected<std::uintptr_t, kvmlib::Error> parse_address(const std::string_view text) {
    std::uintptr_t value{};
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size()) {
        return std::unexpected(kvmlib::Error::parse_error);
    }
    return value;
}

bool valid_address_range(const std::uintptr_t address, const std::size_t length) noexcept {
    return length == 0 || length - 1 <= std::numeric_limits<std::uintptr_t>::max() - address;
}

}

namespace kvmlib {

ProcessMemory::ProcessMemory(const std::int32_t process_id, const int descriptor) noexcept
    : process_id_(process_id), descriptor_(descriptor) {
}

ProcessMemory::~ProcessMemory() {
    if (descriptor_ >= 0) {
        ::close(descriptor_);
    }
}

ProcessMemory::ProcessMemory(ProcessMemory&& other) noexcept
    : process_id_(other.process_id_), descriptor_(other.descriptor_) {
    other.process_id_ = 0;
    other.descriptor_ = -1;
}

ProcessMemory& ProcessMemory::operator=(ProcessMemory&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) {
            ::close(descriptor_);
        }
        process_id_ = other.process_id_;
        descriptor_ = other.descriptor_;
        other.process_id_ = 0;
        other.descriptor_ = -1;
    }
    return *this;
}

std::expected<ProcessMemory, Error> ProcessMemory::open(const std::int32_t process_id) {
    if (process_id <= 0) {
        return std::unexpected(Error::invalid_argument);
    }
    const auto path = "/proc/" + std::to_string(process_id) + "/mem";
    const int descriptor = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (descriptor < 0) {
        return std::unexpected(errno_error());
    }
    return ProcessMemory{ process_id, descriptor };
}

std::int32_t ProcessMemory::process_id() const noexcept {
    return process_id_;
}

bool ProcessMemory::is_open() const noexcept {
    return descriptor_ >= 0;
}

std::expected<std::size_t, Error> ProcessMemory::read(
    const std::uintptr_t address,
    const std::span<std::byte> destination) const {
    if (!is_open() || (!destination.empty() && address == 0)) {
        return std::unexpected(Error::invalid_argument);
    }
    if (!valid_address_range(address, destination.size())) {
        return std::unexpected(Error::invalid_argument);
    }
    std::size_t total{};
    while (total < destination.size()) {
        const auto count = ::pread(descriptor_, destination.data() + total,
            destination.size() - total, static_cast<off_t>(address + total));
        if (count < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (total) {
                return total;
            }
            return std::unexpected(errno_error());
        }
        if (count == 0) {
            break;
        }
        total += static_cast<std::size_t>(count);
    }
    return total;
}

std::expected<std::string, Error> ProcessMemory::read_string(
    const std::uintptr_t address,
    const std::size_t maximum_size) const {
    if (maximum_size == 0) {
        return std::string{};
    }
    if (!is_open() || address == 0 || !valid_address_range(address, maximum_size)) {
        return std::unexpected(Error::invalid_argument);
    }

    constexpr std::size_t first_chunk_size = 256;
    constexpr std::size_t large_chunk_size = 64 * 1024;
    std::array<std::byte, first_chunk_size> first_buffer;
    std::string value;

    std::size_t offset{};
    std::size_t chunk_size{ first_chunk_size };
    while (offset < maximum_size) {
        if (offset == 0) {
            const auto request = std::min(first_chunk_size, maximum_size);
            const auto read_result = read(address, std::span{ first_buffer }.first(request));
            if (!read_result) {
                return std::unexpected(read_result.error());
            }
            const auto count = *read_result;
            const auto* begin = reinterpret_cast<const char*>(first_buffer.data());
            const auto* terminator = static_cast<const char*>(std::memchr(begin, 0, count));
            const auto length = terminator ? static_cast<std::size_t>(terminator - begin) : count;
            value.assign(begin, length);
            offset = count;
            if (terminator || count != request) {
                return value;
            }
            if (offset == maximum_size) {
                return value;
            }
            constexpr std::size_t reservation_limit = 1 << 20;
            value.reserve(std::min(maximum_size, reservation_limit));
            chunk_size = std::min(large_chunk_size, maximum_size - offset);
            continue;
        }

        const auto request = std::min(chunk_size, maximum_size - offset);
        value.resize(offset + request);
        const auto read_result = read(address + offset,
            std::as_writable_bytes(std::span{ value.data() + offset, request }));
        if (!read_result) {
            value.resize(offset);
            return value;
        }
        const auto count = *read_result;
        const auto* begin = value.data() + offset;
        const auto* terminator = static_cast<const char*>(std::memchr(begin, 0, count));
        const auto length = terminator ? static_cast<std::size_t>(terminator - begin) : count;
        value.resize(offset + length);
        offset += length;
        if (terminator || count != request) {
            return value;
        }
        if (chunk_size <= std::numeric_limits<std::size_t>::max() / 2) {
            chunk_size = std::min(chunk_size * 2, maximum_size - offset);
        } else {
            chunk_size = maximum_size - offset;
        }
    }
    return value;
}

std::expected<std::vector<MemoryRegion>, Error> ProcessMemory::regions() const {
    if (!is_open()) {
        return std::unexpected(Error::invalid_argument);
    }
    std::ifstream input("/proc/" + std::to_string(process_id_) + "/maps");
    if (!input) {
        return std::unexpected(errno_error());
    }
    std::vector<MemoryRegion> result;
    std::string line;
    while (std::getline(input, line)) {
        std::istringstream fields(line);
        std::string range;
        std::string permissions;
        std::string offset;
        std::string device;
        std::uint64_t inode{};
        if (!(fields >> range >> permissions >> offset >> device >> inode)) {
            return std::unexpected(Error::parse_error);
        }
        const auto dash = range.find('-');
        if (dash == std::string::npos) {
            return std::unexpected(Error::parse_error);
        }
        const auto begin = parse_address(std::string_view{ range }.substr(0, dash));
        const auto end = parse_address(std::string_view{ range }.substr(dash + 1));
        if (!begin || !end || *end <= *begin) {
            return std::unexpected(Error::parse_error);
        }
        if (permissions.size() < 4) {
            return std::unexpected(Error::parse_error);
        }
        std::string name;
        if (std::getline(fields, name)) {
            const auto first = name.find_first_not_of(" \t");
            name = first == std::string::npos ? std::string{} : name.substr(first);
        }
        result.push_back({
            *begin,
            *end,
            permissions[0] == 'r',
            permissions[1] == 'w',
            permissions[2] == 'x',
            permissions[3] == 'p',
            std::move(name)
        });
    }
    if (input.bad()) {
        return std::unexpected(Error::io_error);
    }
    return result;
}

std::expected<MemoryInfo, Error> memory_info() {
    std::ifstream input("/proc/meminfo");
    if (!input) {
        return std::unexpected(errno_error());
    }
    MemoryInfo result;
    std::string line;
    while (std::getline(input, line)) {
        if (line.empty() || line.find_first_not_of(" \t") == std::string::npos) {
            continue;
        }
        std::istringstream fields(line);
        std::string key;
        std::uint64_t value{};
        std::string unit;
        if (!(fields >> key >> value)) {
            return std::unexpected(Error::parse_error);
        }
        if (fields >> unit) {
            std::string extra;
            if (fields >> extra || unit != "kB") {
                return std::unexpected(Error::parse_error);
            }
        }
        const bool tracked = key == "MemTotal:" || key == "MemFree:"
            || key == "MemAvailable:" || key == "Buffers:"
            || key == "Cached:" || key == "SwapTotal:" || key == "SwapFree:";
        if (tracked && unit != "kB") {
            return std::unexpected(Error::parse_error);
        }
        std::uint64_t bytes = value;
        if (unit == "kB") {
            if (value > std::numeric_limits<std::uint64_t>::max() / 1024) {
                return std::unexpected(Error::parse_error);
            }
            bytes *= 1024;
        }
        if (key == "MemTotal:") result.total_bytes = bytes;
        if (key == "MemFree:") result.free_bytes = bytes;
        if (key == "MemAvailable:") result.available_bytes = bytes;
        if (key == "Buffers:") result.buffers_bytes = bytes;
        if (key == "Cached:") result.cached_bytes = bytes;
        if (key == "SwapTotal:") result.swap_total_bytes = bytes;
        if (key == "SwapFree:") result.swap_free_bytes = bytes;
    }
    if (input.bad()) {
        return std::unexpected(Error::io_error);
    }
    return result.total_bytes ? std::expected<MemoryInfo, Error>{ result }
                              : std::unexpected(Error::parse_error);
}

}
