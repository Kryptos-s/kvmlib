#include "kvmlib/cr3_trace.hpp"

#include "detail.hpp"
#include "kvmlib/privilege.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <fcntl.h>
#include <span>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>

namespace {

struct NativeCr3Event {
    std::uint64_t timestamp_ns;
    std::uint32_t virtual_cpu;
    std::uint32_t padding;
    std::uint64_t previous;
    std::uint64_t current;
};
static_assert(sizeof(NativeCr3Event) == 32);

constexpr unsigned long make_ioctl(const unsigned type, const unsigned number) noexcept {
    return (type << 8) | number;
}
constexpr auto arm_command = make_ioctl(0xC3, 1);
constexpr auto disarm_command = make_ioctl(0xC3, 2);
constexpr auto flush_command = make_ioctl(0xC3, 3);
constexpr std::size_t events_per_read = 128;
constexpr std::size_t default_result_size = 128;
constexpr std::size_t maximum_result_size = 4096;

}

namespace kvmlib {

Cr3Trace::Cr3Trace(const int descriptor) noexcept : descriptor_(descriptor) {}

Cr3Trace::~Cr3Trace() {
    static_cast<void>(stop());
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
}

Cr3Trace::Cr3Trace(Cr3Trace&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)),
      enabled_(std::exchange(other.enabled_, false)) {}

Cr3Trace& Cr3Trace::operator=(Cr3Trace&& other) noexcept {
    if (this == &other) return *this;
    static_cast<void>(stop());
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
    descriptor_ = std::exchange(other.descriptor_, -1);
    enabled_ = std::exchange(other.enabled_, false);
    return *this;
}

std::expected<Cr3Trace, Error> Cr3Trace::open(std::string device) {
    if (const auto root = require_root(); !root) return std::unexpected(root.error());
    detail::UniqueFd descriptor(::open(device.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (!descriptor) return std::unexpected(detail::from_errno());
    if (::flock(descriptor.get(), LOCK_EX | LOCK_NB) < 0) {
        return std::unexpected(detail::from_errno());
    }
    return Cr3Trace{descriptor.release()};
}

bool Cr3Trace::enabled() const noexcept {
    return enabled_;
}

int Cr3Trace::native_handle() const noexcept {
    return descriptor_;
}

std::expected<void, Error> Cr3Trace::start() {
    if (descriptor_ < 0 || enabled_) return std::unexpected(Error::invalid_argument);
    if (::ioctl(descriptor_, flush_command) < 0 || ::ioctl(descriptor_, arm_command) < 0) {
        return std::unexpected(detail::from_errno());
    }
    enabled_ = true;
    return {};
}

std::expected<void, Error> Cr3Trace::stop() {
    if (!enabled_) return {};
    if (descriptor_ < 0) return std::unexpected(Error::invalid_argument);
    if (::ioctl(descriptor_, disarm_command) < 0) {
        return std::unexpected(detail::from_errno());
    }
    enabled_ = false;
    return {};
}

std::expected<std::size_t, Error> Cr3Trace::poll(const std::span<Cr3Event> output) {
    if (descriptor_ < 0) return std::unexpected(Error::invalid_argument);
    const auto limit = std::min(output.size(), maximum_result_size);
    if (limit == 0) return std::size_t{};

    std::array<NativeCr3Event, events_per_read> input{};
    std::size_t total{};
    while (total < limit) {
        const auto requested = std::min(limit - total, input.size());
        const auto byte_count = requested * sizeof(NativeCr3Event);
        const auto bytes = ::read(descriptor_, input.data(), byte_count);
        if (bytes < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
            return total ? std::expected<std::size_t, Error>{total}
                         : std::unexpected(detail::from_errno());
        }
        if (bytes > static_cast<ssize_t>(byte_count)
            || bytes % static_cast<ssize_t>(sizeof(NativeCr3Event)) != 0) {
            return total ? std::expected<std::size_t, Error>{total}
                         : std::unexpected(Error::io_error);
        }

        const auto count = static_cast<std::size_t>(bytes) / sizeof(NativeCr3Event);
        for (std::size_t index{}; index < count; ++index) {
            const auto& event = input[index];
            output[total + index] = {event.timestamp_ns, event.virtual_cpu, event.previous, event.current};
        }
        total += count;
        if (count < requested) break;
    }
    return total;
}

std::expected<std::vector<Cr3Event>, Error> Cr3Trace::poll() {
    std::array<Cr3Event, default_result_size> output{};
    const auto count = poll(output);
    if (!count) return std::unexpected(count.error());
    return std::vector<Cr3Event>(output.begin(), output.begin() + *count);
}

}
