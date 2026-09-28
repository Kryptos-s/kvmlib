#pragma once

#include <string_view>

namespace kvmlib {

enum class Error {
    none,
    invalid_argument,
    not_found,
    permission_denied,
    io_error,
    parse_error,
    unsupported,
    busy,
    partial_write
};

constexpr std::string_view error_message(const Error error) noexcept {
    switch (error) {
    case Error::none: return "no error";
    case Error::invalid_argument: return "invalid argument";
    case Error::not_found: return "not found";
    case Error::permission_denied: return "permission denied";
    case Error::io_error: return "I/O error";
    case Error::parse_error: return "parse error";
    case Error::unsupported: return "unsupported operation or backend";
    case Error::busy: return "resource is busy";
    case Error::partial_write: return "write partially completed";
    }
    return "unknown error";
}

}
