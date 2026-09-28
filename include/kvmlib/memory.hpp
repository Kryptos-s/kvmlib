#pragma once

#include "kvmlib/error.hpp"

#include <concepts>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <type_traits>
#include <vector>

namespace kvmlib {

struct MemoryInfo {
    std::uint64_t total_bytes{};
    std::uint64_t free_bytes{};
    std::uint64_t available_bytes{};
    std::uint64_t buffers_bytes{};
    std::uint64_t cached_bytes{};
    std::uint64_t swap_total_bytes{};
    std::uint64_t swap_free_bytes{};
};

struct MemoryRegion {
    std::uintptr_t begin{};
    std::uintptr_t end{};
    bool readable{};
    bool writable{};
    bool executable{};
    bool private_mapping{};
    std::string name;
};

class ProcessMemory {
public:
    ProcessMemory() = default;
    ~ProcessMemory();

    ProcessMemory(const ProcessMemory&) = delete;
    ProcessMemory& operator=(const ProcessMemory&) = delete;
    ProcessMemory(ProcessMemory&& other) noexcept;
    ProcessMemory& operator=(ProcessMemory&& other) noexcept;

    [[nodiscard]] static std::expected<ProcessMemory, Error> open(std::int32_t process_id);
    [[nodiscard]] std::int32_t process_id() const noexcept;
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] std::expected<std::size_t, Error> read(std::uintptr_t address, std::span<std::byte> destination) const;
    [[nodiscard]] std::expected<std::string, Error> read_string(std::uintptr_t address, std::size_t maximum_size) const;
    [[nodiscard]] std::expected<std::vector<MemoryRegion>, Error> regions() const;

    template <typename T>
        requires std::is_trivially_copyable_v<T>
    [[nodiscard]] std::expected<T, Error> read_object(const std::uintptr_t address) const {
        T value{};
        auto result = read(address, std::as_writable_bytes(std::span{&value, 1}));
        if (!result || *result != sizeof(T)) {
            return std::unexpected(result ? Error::io_error : result.error());
        }
        return value;
    }

private:
    explicit ProcessMemory(std::int32_t process_id, int descriptor) noexcept;

    std::int32_t process_id_{};
    int descriptor_{ -1 };
};

[[nodiscard]] std::expected<MemoryInfo, Error> memory_info();

}
