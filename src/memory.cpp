#include "kvmlib/memory.hpp"

#include "detail.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <limits>
#include <string_view>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace {

using kvmlib::Error;

std::expected<std::uintptr_t, Error> parse_hex(const std::string_view text) {
    std::uintptr_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, 16);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::unexpected(Error::parse_error);
    }
    return value;
}

std::string_view trim_left(std::string_view text) noexcept {
    const auto first = text.find_first_not_of(" \t");
    return first == std::string_view::npos ? std::string_view{} : text.substr(first);
}

bool take_field(std::string_view& line, std::string_view& field) noexcept {
    line = trim_left(line);
    if (line.empty()) return false;
    const auto end = line.find_first_of(" \t");
    field = line.substr(0, end);
    line = end == std::string_view::npos ? std::string_view{} : line.substr(end);
    return true;
}

std::expected<std::uint64_t, Error> parse_decimal(const std::string_view text) {
    std::uint64_t value{};
    const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value, 10);
    if (error != std::errc{} || end != text.data() + text.size()) {
        return std::unexpected(Error::parse_error);
    }
    return value;
}

bool is_memory_counter(const std::string_view key) noexcept {
    return key == "MemTotal:" || key == "MemFree:" || key == "MemAvailable:"
        || key == "Buffers:" || key == "Cached:" || key == "SwapTotal:"
        || key == "SwapFree:";
}

}

namespace kvmlib {

ProcessMemory::ProcessMemory(const std::int32_t process_id, const int descriptor) noexcept
    : process_id_(process_id), descriptor_(descriptor) {}

ProcessMemory::~ProcessMemory() {
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
}

ProcessMemory::ProcessMemory(ProcessMemory&& other) noexcept
    : process_id_(std::exchange(other.process_id_, 0)),
      descriptor_(std::exchange(other.descriptor_, -1)) {}

ProcessMemory& ProcessMemory::operator=(ProcessMemory&& other) noexcept {
    if (this == &other) return *this;
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
    process_id_ = std::exchange(other.process_id_, 0);
    descriptor_ = std::exchange(other.descriptor_, -1);
    return *this;
}

std::expected<ProcessMemory, Error> ProcessMemory::open(const std::int32_t process_id) {
    if (process_id <= 0) return std::unexpected(Error::invalid_argument);
    const auto path = "/proc/" + std::to_string(process_id) + "/mem";
    detail::UniqueFd descriptor(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!descriptor) return std::unexpected(detail::from_errno());
    return ProcessMemory{process_id, descriptor.release()};
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
    if (!is_open() || (!destination.empty() && address == 0)
        || !detail::valid_range(address, destination.size())) {
        return std::unexpected(Error::invalid_argument);
    }

    std::size_t completed{};
    while (completed < destination.size()) {
        const auto count = ::pread(descriptor_, destination.data() + completed,
            destination.size() - completed, static_cast<off_t>(address + completed));
        if (count < 0) {
            if (errno == EINTR) continue;
            if (completed != 0) return completed;
            return std::unexpected(detail::from_errno());
        }
        if (count == 0) break;
        completed += static_cast<std::size_t>(count);
    }
    return completed;
}

std::expected<std::string, Error> ProcessMemory::read_string(
    const std::uintptr_t address,
    const std::size_t maximum_size) const {
    if (maximum_size == 0) return std::string{};
    if (!is_open() || address == 0 || !detail::valid_range(address, maximum_size)) {
        return std::unexpected(Error::invalid_argument);
    }

    constexpr std::size_t initial_chunk = 256;
    constexpr std::size_t maximum_chunk = 64 * 1024;
    constexpr std::size_t maximum_reservation = 1 << 20;
    std::array<std::byte, initial_chunk> first{};
    std::string result;
    std::size_t offset{};
    std::size_t chunk_size = initial_chunk;

    while (offset < maximum_size) {
        if (offset == 0) {
            const auto request = std::min(initial_chunk, maximum_size);
            const auto read_result = read(address, std::span{first}.first(request));
            if (!read_result) return std::unexpected(read_result.error());
            const auto count = *read_result;
            const auto* data = reinterpret_cast<const char*>(first.data());
            const auto* zero = static_cast<const char*>(std::memchr(data, 0, count));
            const auto length = zero ? static_cast<std::size_t>(zero - data) : count;
            result.assign(data, length);
            offset = count;
            if (zero || count != request || offset == maximum_size) return result;
            result.reserve(std::min(maximum_size, maximum_reservation));
            chunk_size = std::min(maximum_chunk, maximum_size - offset);
            continue;
        }

        const auto request = std::min(chunk_size, maximum_size - offset);
        result.resize(offset + request);
        const auto output = std::as_writable_bytes(std::span{result.data() + offset, request});
        const auto read_result = read(address + offset, output);
        if (!read_result) {
            result.resize(offset);
            return result;
        }
        const auto count = *read_result;
        const auto* data = result.data() + offset;
        const auto* zero = static_cast<const char*>(std::memchr(data, 0, count));
        const auto length = zero ? static_cast<std::size_t>(zero - data) : count;
        result.resize(offset + length);
        offset += length;
        if (zero || count != request) return result;
        if (chunk_size <= std::numeric_limits<std::size_t>::max() / 2) {
            chunk_size = std::min(chunk_size * 2, maximum_size - offset);
        } else {
            chunk_size = maximum_size - offset;
        }
    }
    return result;
}

std::expected<std::vector<MemoryRegion>, Error> ProcessMemory::regions() const {
    if (!is_open()) return std::unexpected(Error::invalid_argument);
    std::ifstream input("/proc/" + std::to_string(process_id_) + "/maps");
    if (!input) return std::unexpected(detail::from_errno());

    std::vector<MemoryRegion> result;
    std::string line;
    while (std::getline(input, line)) {
        std::string_view fields(line);
        std::string_view range;
        std::string_view permissions;
        std::string_view offset;
        std::string_view device;
        std::string_view inode;
        if (!take_field(fields, range) || !take_field(fields, permissions)
            || !take_field(fields, offset) || !take_field(fields, device)
            || !take_field(fields, inode) || permissions.size() != 4) {
            return std::unexpected(Error::parse_error);
        }
        std::uint64_t inode_number{};
        const auto [inode_end, inode_error] = std::from_chars(inode.data(), inode.data() + inode.size(), inode_number);
        if (inode_error != std::errc{} || inode_end != inode.data() + inode.size()) {
            return std::unexpected(Error::parse_error);
        }
        const auto device_separator = device.find(':');
        if (device_separator == std::string_view::npos
            || !parse_hex(offset)
            || !parse_hex(device.substr(0, device_separator))
            || !parse_hex(device.substr(device_separator + 1))) {
            return std::unexpected(Error::parse_error);
        }

        const auto separator = range.find('-');
        if (separator == std::string_view::npos) return std::unexpected(Error::parse_error);
        const auto begin = parse_hex(range.substr(0, separator));
        const auto end = parse_hex(range.substr(separator + 1));
        if (!begin || !end || *end <= *begin) return std::unexpected(Error::parse_error);

        const auto name = trim_left(fields);
        result.push_back({
            *begin, *end,
            permissions[0] == 'r',
            permissions[1] == 'w',
            permissions[2] == 'x',
            permissions[3] == 'p',
            std::string(name)
        });
    }
    if (input.bad()) return std::unexpected(Error::io_error);
    return result;
}

std::expected<MemoryInfo, Error> memory_info() {
    std::ifstream input("/proc/meminfo");
    if (!input) return std::unexpected(detail::from_errno());

    MemoryInfo result;
    bool found_total{};
    std::string line;
    while (std::getline(input, line)) {
        std::string_view fields(line);
        std::string_view key;
        std::string_view number;
        std::string_view unit;
        std::string_view extra;
        if (!take_field(fields, key)) continue;
        if (!take_field(fields, number)) return std::unexpected(Error::parse_error);
        const bool has_unit = take_field(fields, unit);
        if (has_unit) {
            if (unit != "kB" || take_field(fields, extra)) {
                return std::unexpected(Error::parse_error);
            }
        }

        const auto value = parse_decimal(number);
        if (!value) return std::unexpected(value.error());
        if (!is_memory_counter(key)) continue;
        if (unit != "kB" || *value > std::numeric_limits<std::uint64_t>::max() / 1024) {
            return std::unexpected(Error::parse_error);
        }
        const auto bytes = *value * 1024;
        if (key == "MemTotal:") { result.total_bytes = bytes; found_total = true; }
        else if (key == "MemFree:") result.free_bytes = bytes;
        else if (key == "MemAvailable:") result.available_bytes = bytes;
        else if (key == "Buffers:") result.buffers_bytes = bytes;
        else if (key == "Cached:") result.cached_bytes = bytes;
        else if (key == "SwapTotal:") result.swap_total_bytes = bytes;
        else if (key == "SwapFree:") result.swap_free_bytes = bytes;
    }
    if (input.bad()) return std::unexpected(Error::io_error);
    return found_total && result.total_bytes != 0
        ? std::expected<MemoryInfo, Error>{result}
        : std::unexpected(Error::parse_error);
}

}
