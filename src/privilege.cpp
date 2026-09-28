#include "kvmlib/privilege.hpp"

#include <unistd.h>

namespace kvmlib {

bool running_as_root() noexcept {
    return ::geteuid() == 0;
}

std::expected<void, Error> require_root() noexcept {
    if (!running_as_root()) return std::unexpected(Error::permission_denied);
    return {};
}

}
