#include "kvmlib/cr3_trace.hpp"
#include "kvmlib/privilege.hpp"

#include <array>
#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#include <span>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace {

struct NativeCr3Event {
    std::uint64_t timestamp_ns;
    std::uint32_t virtual_cpu;
    std::uint32_t padding;
    std::uint64_t previous;
    std::uint64_t current;
};

static_assert(sizeof(NativeCr3Event) == 32);

constexpr unsigned long ioctl_command(const unsigned type, const unsigned number) {
    return (type << 8) | number;
}

constexpr unsigned long arm_command = ioctl_command(0xC3, 1);
constexpr unsigned long disarm_command = ioctl_command(0xC3, 2);
constexpr unsigned long flush_command = ioctl_command(0xC3, 3);
constexpr std::size_t default_poll_events = 128;
constexpr std::size_t poll_batch_events = 128;
constexpr std::size_t max_poll_events = 4096;

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) return kvmlib::Error::permission_denied;
    if (errno == ENOENT) return kvmlib::Error::not_found;
    return kvmlib::Error::io_error;
}

kvmlib::Error flock_error() {
    if (errno == EWOULDBLOCK || errno == EAGAIN) return kvmlib::Error::busy;
    return errno_error();
}

}

namespace kvmlib {

Cr3Trace::Cr3Trace(const int descriptor) noexcept : descriptor_(descriptor) {
}

Cr3Trace::~Cr3Trace() {
    static_cast<void>(stop());
    if (descriptor_ >= 0) ::close(descriptor_);
}

Cr3Trace::Cr3Trace(Cr3Trace&& other) noexcept
    : descriptor_(other.descriptor_), enabled_(other.enabled_) {
    other.descriptor_ = -1;
    other.enabled_ = false;
}

Cr3Trace& Cr3Trace::operator=(Cr3Trace&& other) noexcept {
    if (this != &other) {
        static_cast<void>(stop());
        if (descriptor_ >= 0) ::close(descriptor_);
        descriptor_ = -1;
        enabled_ = false;
        descriptor_ = other.descriptor_;
        enabled_ = other.enabled_;
        other.descriptor_ = -1;
        other.enabled_ = false;
    }
    return *this;
}

std::expected<Cr3Trace, Error> Cr3Trace::open(std::string device) {
    if (const auto privileged = require_root(); !privileged) return std::unexpected(privileged.error());
    const int descriptor = ::open(device.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0) return std::unexpected(errno_error());
    if (::flock(descriptor, LOCK_EX | LOCK_NB) < 0) {
        const int lock_errno = errno;
        ::close(descriptor);
        errno = lock_errno;
        return std::unexpected(flock_error());
    }
    return Cr3Trace{ descriptor };
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
        return std::unexpected(errno_error());
    }
    enabled_ = true;
    return {};
}

std::expected<void, Error> Cr3Trace::stop() {
    if (!enabled_) return {};
    if (descriptor_ < 0) return std::unexpected(Error::invalid_argument);
    if (::ioctl(descriptor_, disarm_command) < 0) {
        return std::unexpected(errno_error());
    }
    enabled_ = false;
    return {};
}

std::expected<std::size_t, Error> Cr3Trace::poll(std::span<Cr3Event> output) {
    if (descriptor_ < 0) return std::unexpected(Error::invalid_argument);
    if (output.empty()) return std::size_t{ 0 };
    const auto limit = std::min(output.size(), max_poll_events);
    std::array<NativeCr3Event, poll_batch_events> events;
    std::size_t total = 0;
    while (total < limit) {
        const auto requested = std::min(limit - total, poll_batch_events);
        const auto bytes = ::read(descriptor_, events.data(), requested * sizeof(NativeCr3Event));
        if (bytes < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
            if (total > 0) return total;
            return std::unexpected(errno_error());
        }
        if (bytes > static_cast<ssize_t>(requested * sizeof(NativeCr3Event))
            || bytes % static_cast<ssize_t>(sizeof(NativeCr3Event)) != 0) {
            if (total > 0) return total;
            return std::unexpected(Error::io_error);
        }
        const auto event_count = static_cast<std::size_t>(bytes) / sizeof(NativeCr3Event);
        for (std::size_t index = 0; index < event_count; ++index) {
            const auto& event = events[index];
            output[total + index] = { event.timestamp_ns, event.virtual_cpu, event.previous, event.current };
        }
        total += event_count;
        if (event_count < requested) return total;
    }
    return total;
}

std::expected<std::vector<Cr3Event>, Error> Cr3Trace::poll() {
    std::array<Cr3Event, default_poll_events> events;
    auto count = poll(std::span<Cr3Event>(events));
    if (!count) return std::unexpected(count.error());
    if (*count == 0) return std::vector<Cr3Event>{};
    return std::vector<Cr3Event>(events.begin(), events.begin() + *count);
}

}
