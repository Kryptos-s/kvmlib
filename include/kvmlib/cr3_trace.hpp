#pragma once

#include "kvmlib/error.hpp"

#include <cstdint>
#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace kvmlib {

struct Cr3Event {
    std::uint64_t timestamp_ns{};
    std::uint32_t virtual_cpu{};
    std::uint64_t previous{};
    std::uint64_t current{};
};

class Cr3Trace {
public:
    Cr3Trace() = default;
    ~Cr3Trace();

    Cr3Trace(const Cr3Trace&) = delete;
    Cr3Trace& operator=(const Cr3Trace&) = delete;
    Cr3Trace(Cr3Trace&& other) noexcept;
    Cr3Trace& operator=(Cr3Trace&& other) noexcept;

    [[nodiscard]] static std::expected<Cr3Trace, Error> open(std::string device = "/dev/kvm_cr3trace");
    [[nodiscard]] bool enabled() const noexcept;
    [[nodiscard]] int native_handle() const noexcept;
    [[nodiscard]] std::expected<void, Error> start();
    [[nodiscard]] std::expected<void, Error> stop();
    [[nodiscard]] std::expected<std::size_t, Error> poll(std::span<Cr3Event> output);
    [[nodiscard]] std::expected<std::vector<Cr3Event>, Error> poll();

private:
    explicit Cr3Trace(int descriptor) noexcept;

    int descriptor_{ -1 };
    bool enabled_{};
};

}
