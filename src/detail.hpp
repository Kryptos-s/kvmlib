#pragma once

#include "kvmlib/error.hpp"

#include <cerrno>
#include <concepts>
#include <cstdint>
#include <limits>
#include <system_error>
#include <utility>
#include <unistd.h>

namespace kvmlib::detail {

inline Error from_errno(const int value = errno) noexcept {
    switch (value) {
    case EACCES:
    case EPERM:
        return Error::permission_denied;
    case ENOENT:
    case ESRCH:
        return Error::not_found;
    case EBUSY:
        return Error::busy;
    default:
        return Error::io_error;
    }
}

inline Error from_error_code(const std::error_code value) noexcept {
    if (value == std::errc::permission_denied) return Error::permission_denied;
    if (value == std::errc::no_such_file_or_directory) return Error::not_found;
    if (value == std::errc::device_or_resource_busy || value == std::errc::resource_unavailable_try_again) return Error::busy;
    return Error::io_error;
}

class UniqueFd {
public:
    UniqueFd() noexcept = default;
    explicit UniqueFd(const int descriptor) noexcept : descriptor_(descriptor) {}
    ~UniqueFd() { reset(); }

    UniqueFd(const UniqueFd&) = delete;
    UniqueFd& operator=(const UniqueFd&) = delete;

    UniqueFd(UniqueFd&& other) noexcept : descriptor_(std::exchange(other.descriptor_, -1)) {}
    UniqueFd& operator=(UniqueFd&& other) noexcept {
        if (this != &other) reset(std::exchange(other.descriptor_, -1));
        return *this;
    }

    [[nodiscard]] int get() const noexcept { return descriptor_; }
    [[nodiscard]] explicit operator bool() const noexcept { return descriptor_ >= 0; }
    [[nodiscard]] int release() noexcept { return std::exchange(descriptor_, -1); }

    void reset(const int descriptor = -1) noexcept {
        const int previous = std::exchange(descriptor_, descriptor);
        if (previous >= 0) static_cast<void>(::close(previous));
    }

private:
    int descriptor_{-1};
};

template <std::unsigned_integral Address, std::unsigned_integral Size>
[[nodiscard]] constexpr bool valid_range(const Address address, const Size size) noexcept {
    if (size == 0) return true;
    return size - 1 <= std::numeric_limits<Address>::max() - address;
}

}
