#include "kvmlib/input.hpp"
#include "kvmlib/privilege.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <filesystem>
#include <fcntl.h>
#include <linux/input.h>
#include <optional>
#include <span>
#include <string_view>
#include <sys/ioctl.h>
#include <system_error>
#include <unistd.h>

namespace {

kvmlib::Error errno_error() {
    if (errno == EACCES || errno == EPERM) return kvmlib::Error::permission_denied;
    if (errno == ENOENT) return kvmlib::Error::not_found;
    return kvmlib::Error::io_error;
}

kvmlib::Error filesystem_error(const std::error_code error) {
    if (error == std::errc::permission_denied) return kvmlib::Error::permission_denied;
    if (error == std::errc::no_such_file_or_directory) return kvmlib::Error::not_found;
    return kvmlib::Error::io_error;
}

constexpr std::size_t default_poll_events = 128;
constexpr std::size_t poll_batch_events = 128;
constexpr std::size_t max_poll_events = 4096;

std::expected<void, kvmlib::Error> write_all(
    const int descriptor,
    const std::span<const input_event> events) {
    const auto* bytes = reinterpret_cast<const std::byte*>(events.data());
    const auto total = events.size_bytes();
    std::size_t offset = 0;
    while (offset < total) {
        const auto written = ::write(descriptor, bytes + offset, total - offset);
        if (written > 0) {
            const auto count = static_cast<std::size_t>(written);
            if (count > total - offset) {
                return std::unexpected(offset == 0 ? kvmlib::Error::io_error : kvmlib::Error::partial_write);
            }
            if (count % sizeof(input_event) != 0) {
                return std::unexpected(kvmlib::Error::partial_write);
            }
            offset += count;
            continue;
        }
        if (written == 0) {
            return std::unexpected(offset == 0 ? kvmlib::Error::io_error : kvmlib::Error::partial_write);
        }
        if (errno == EINTR) continue;
        return std::unexpected(offset == 0 ? errno_error() : kvmlib::Error::partial_write);
    }
    return {};
}

void retain_candidate_error(std::optional<kvmlib::Error>& current, const kvmlib::Error candidate) {
    if (!current || *current == kvmlib::Error::not_found || candidate == kvmlib::Error::permission_denied) {
        current = candidate;
    }
}

std::expected<kvmlib::EvdevInput, kvmlib::Error> open_kind(const std::string_view kind, const bool host_only) {
    const std::filesystem::path directory{ "/dev/input/by-id" };
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(error ? filesystem_error(error) : kvmlib::Error::not_found);
    }
    std::vector<std::filesystem::path> candidates;
    std::filesystem::directory_iterator iterator(directory, error);
    const std::filesystem::directory_iterator end;
    if (error) return std::unexpected(filesystem_error(error));
    for (; iterator != end; iterator.increment(error)) {
        if (error) break;
        const auto& entry = *iterator;
        const auto name = entry.path().filename().string();
        if (host_only && name.starts_with("baykus-")) continue;
        if (name.contains(kind) && name.contains("event")) candidates.push_back(entry.path());
    }
    const auto iteration_error = error;
    std::ranges::sort(candidates, [](const auto& left, const auto& right) {
        return left.filename().string().starts_with("baykus-") > right.filename().string().starts_with("baykus-");
    });
    std::optional<kvmlib::Error> candidate_error;
    for (const auto& candidate : candidates) {
        auto input = kvmlib::EvdevInput::open(candidate.string());
        if (input) return input;
        retain_candidate_error(candidate_error, input.error());
    }
    if (candidate_error && *candidate_error != kvmlib::Error::not_found) {
        return std::unexpected(*candidate_error);
    }
    if (iteration_error) return std::unexpected(filesystem_error(iteration_error));
    if (candidate_error) return std::unexpected(*candidate_error);
    return std::unexpected(kvmlib::Error::not_found);
}

}

namespace kvmlib {

EvdevInput::EvdevInput(const int descriptor) noexcept : descriptor_(descriptor) {
}

EvdevInput::~EvdevInput() {
    if (descriptor_ >= 0) ::close(descriptor_);
}

EvdevInput::EvdevInput(EvdevInput&& other) noexcept : descriptor_(other.descriptor_) {
    other.descriptor_ = -1;
}

EvdevInput& EvdevInput::operator=(EvdevInput&& other) noexcept {
    if (this != &other) {
        if (descriptor_ >= 0) ::close(descriptor_);
        descriptor_ = other.descriptor_;
        other.descriptor_ = -1;
    }
    return *this;
}

std::expected<EvdevInput, Error> EvdevInput::open(std::string path) {
    if (const auto privileged = require_root(); !privileged) return std::unexpected(privileged.error());
    const int descriptor = ::open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC);
    if (descriptor < 0) return std::unexpected(errno_error());
    return EvdevInput{ descriptor };
}

std::expected<EvdevInput, Error> EvdevInput::open_mouse() {
    return open_kind("mouse", false);
}

std::expected<EvdevInput, Error> EvdevInput::open_keyboard() {
    auto input = open_kind("kbd", false);
    if (input) return input;
    const auto first_error = input.error();
    auto fallback = open_kind("keyboard", false);
    if (fallback) return fallback;
    std::optional<Error> candidate_error{ first_error };
    retain_candidate_error(candidate_error, fallback.error());
    return std::unexpected(*candidate_error);
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_mouse() {
    return open("/dev/input/by-id/baykus-vmouse-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_keyboard() {
    return open("/dev/input/by-id/baykus-vkbd-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_host_keyboard() {
    auto input = open_kind("kbd", true);
    if (input) return input;
    const auto first_error = input.error();
    auto fallback = open_kind("keyboard", true);
    if (fallback) return fallback;
    std::optional<Error> candidate_error{ first_error };
    retain_candidate_error(candidate_error, fallback.error());
    return std::unexpected(*candidate_error);
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_keyboards() {
    const std::filesystem::path directory{ "/dev/input/by-id" };
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(error ? filesystem_error(error) : Error::not_found);
    }
    std::vector<std::filesystem::path> candidates;
    std::filesystem::directory_iterator iterator(directory, error);
    const std::filesystem::directory_iterator end;
    if (error) return std::unexpected(filesystem_error(error));
    for (; iterator != end; iterator.increment(error)) {
        if (error) break;
        const auto& entry = *iterator;
        const auto name = entry.path().filename().string();
        if (name.starts_with("baykus-") || !name.contains("event") || (!name.contains("kbd") && !name.contains("keyboard"))) continue;
        candidates.push_back(entry.path());
    }
    const auto iteration_error = error;
    std::ranges::sort(candidates);
    std::vector<EvdevInput> inputs;
    std::optional<Error> candidate_error;
    for (const auto& candidate : candidates) {
        auto input = open(candidate.string());
        if (input) {
            inputs.push_back(std::move(*input));
        } else {
            retain_candidate_error(candidate_error, input.error());
        }
    }
    if (iteration_error) return std::unexpected(filesystem_error(iteration_error));
    if (inputs.empty()) {
        if (candidate_error && *candidate_error != Error::not_found) return std::unexpected(*candidate_error);
        if (candidate_error) return std::unexpected(*candidate_error);
        return std::unexpected(Error::not_found);
    }
    return inputs;
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_mice() {
    const std::filesystem::path directory{ "/dev/input/by-id" };
    std::error_code error;
    if (!std::filesystem::exists(directory, error)) {
        return std::unexpected(error ? filesystem_error(error) : Error::not_found);
    }
    std::vector<std::filesystem::path> candidates;
    std::filesystem::directory_iterator iterator(directory, error);
    const std::filesystem::directory_iterator end;
    if (error) return std::unexpected(filesystem_error(error));
    for (; iterator != end; iterator.increment(error)) {
        if (error) break;
        const auto& entry = *iterator;
        const auto name = entry.path().filename().string();
        if (name.starts_with("baykus-") || !name.contains("event") || !name.contains("mouse")) continue;
        candidates.push_back(entry.path());
    }
    const auto iteration_error = error;
    std::ranges::sort(candidates);
    std::vector<EvdevInput> inputs;
    std::optional<Error> candidate_error;
    for (const auto& candidate : candidates) {
        auto input = open(candidate.string());
        if (input) {
            inputs.push_back(std::move(*input));
        } else {
            retain_candidate_error(candidate_error, input.error());
        }
    }
    if (iteration_error) return std::unexpected(filesystem_error(iteration_error));
    if (inputs.empty()) {
        if (candidate_error && *candidate_error != Error::not_found) return std::unexpected(*candidate_error);
        if (candidate_error) return std::unexpected(*candidate_error);
        return std::unexpected(Error::not_found);
    }
    return inputs;
}

bool EvdevInput::is_open() const noexcept {
    return descriptor_ >= 0;
}

int EvdevInput::native_handle() const noexcept {
    return descriptor_;
}

std::expected<bool, Error> EvdevInput::key_down(const std::uint16_t key_code) const {
    if (!is_open() || key_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    std::array<std::uint8_t, KEY_MAX / 8 + 1> bits{};
    if (::ioctl(descriptor_, EVIOCGKEY(bits.size()), bits.data()) < 0) {
        return std::unexpected(errno_error());
    }
    return (bits[key_code / 8] & (1U << (key_code % 8))) != 0;
}

std::expected<bool, Error> EvdevInput::mouse_button_down(const std::uint16_t button_code) const {
    return key_down(button_code);
}

std::expected<std::size_t, Error> EvdevInput::poll(std::span<InputEvent> output) {
    if (!is_open()) return std::unexpected(Error::invalid_argument);
    if (output.empty()) return std::size_t{ 0 };
    const auto limit = std::min(output.size(), max_poll_events);
    std::array<input_event, poll_batch_events> native_events;
    std::size_t total = 0;
    while (total < limit) {
        const auto requested = std::min(limit - total, poll_batch_events);
        const auto bytes = ::read(descriptor_, native_events.data(), requested * sizeof(input_event));
        if (bytes < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
            if (total > 0) return total;
            return std::unexpected(errno_error());
        }
        if (bytes > static_cast<ssize_t>(requested * sizeof(input_event))
            || bytes % static_cast<ssize_t>(sizeof(input_event)) != 0) {
            if (total > 0) return total;
            return std::unexpected(Error::io_error);
        }
        const auto event_count = static_cast<std::size_t>(bytes) / sizeof(input_event);
        for (std::size_t index = 0; index < event_count; ++index) {
            const auto& event = native_events[index];
            output[total + index] = { event.type, event.code, event.value };
        }
        total += event_count;
        if (event_count < requested) return total;
    }
    return total;
}

std::expected<std::vector<InputEvent>, Error> EvdevInput::poll() {
    std::array<InputEvent, default_poll_events> events;
    auto count = poll(std::span<InputEvent>(events));
    if (!count) return std::unexpected(count.error());
    if (*count == 0) return std::vector<InputEvent>{};
    return std::vector<InputEvent>(events.begin(), events.begin() + *count);
}

std::expected<void, Error> EvdevInput::send_events(const std::span<const InputEvent> events) const {
    if (!is_open()) return std::unexpected(Error::invalid_argument);
    if (events.empty() || events.size() > 4) return std::unexpected(Error::invalid_argument);
    std::array<input_event, 4> native_events{};
    for (std::size_t index = 0; index < events.size(); ++index) {
        native_events[index].type = events[index].type;
        native_events[index].code = events[index].code;
        native_events[index].value = events[index].value;
    }
    return write_all(descriptor_, std::span<const input_event>(native_events.data(), events.size()));
}

std::expected<void, Error> EvdevInput::send_key(const std::uint16_t key_code, const bool pressed) const {
    if (key_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    const std::array<InputEvent, 2> events{
        InputEvent{ EV_KEY, key_code, pressed ? 1 : 0 },
        InputEvent{ EV_SYN, SYN_REPORT, 0 },
    };
    return send_events(events);
}

std::expected<void, Error> EvdevInput::send_mouse_button(const std::uint16_t button_code, const bool pressed) const {
    return send_key(button_code, pressed);
}

std::expected<void, Error> EvdevInput::click_mouse_button(const std::uint16_t button_code) const {
    if (button_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    const std::array<InputEvent, 4> events{
        InputEvent{ EV_KEY, button_code, 1 },
        InputEvent{ EV_SYN, SYN_REPORT, 0 },
        InputEvent{ EV_KEY, button_code, 0 },
        InputEvent{ EV_SYN, SYN_REPORT, 0 },
    };
    return send_events(events);
}

std::expected<void, Error> EvdevInput::move_relative(const std::int32_t x, const std::int32_t y) const {
    if (x == 0 && y == 0) return {};
    std::array<InputEvent, 3> events{};
    std::size_t count = 0;
    if (x != 0) {
        events[count++] = { EV_REL, REL_X, x };
    }
    if (y != 0) {
        events[count++] = { EV_REL, REL_Y, y };
    }
    events[count++] = { EV_SYN, SYN_REPORT, 0 };
    return send_events(std::span<const InputEvent>(events.data(), count));
}

}
