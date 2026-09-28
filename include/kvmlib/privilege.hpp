#pragma once

#include "kvmlib/error.hpp"

#include <expected>

namespace kvmlib {

[[nodiscard]] bool running_as_root() noexcept;
[[nodiscard]] std::expected<void, Error> require_root() noexcept;

}
