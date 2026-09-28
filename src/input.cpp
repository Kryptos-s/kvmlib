#include "kvmlib/input.hpp"

#include "detail.hpp"
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
#include <string>
#include <string_view>
#include <system_error>
#include <sys/ioctl.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using kvmlib::Error;

constexpr std::size_t default_poll_events = 128;
constexpr std::size_t poll_batch_events = 128;
constexpr std::size_t maximum_poll_events = 4096;
constexpr std::string_view device_directory = "/dev/input/by-id";

struct DeviceList {
    std::vector<std::filesystem::path> paths;
    std::error_code iteration_error;
};

std::expected<DeviceList, Error> list_devices(const auto& predicate) {
    DeviceList result;
    std::error_code error;
    std::filesystem::directory_iterator current(std::filesystem::path(device_directory), error);
    if (error) return std::unexpected(kvmlib::detail::from_error_code(error));
    const std::filesystem::directory_iterator end;
    for (; current != end; current.increment(error)) {
        if (error) break;
        const auto path = current->path();
        if (predicate(path.filename().string())) result.paths.push_back(path);
    }
    result.iteration_error = error;
    return result;
}

void prefer_guest_devices(std::vector<std::filesystem::path>& paths) {
    std::ranges::stable_sort(paths, [](const auto& left, const auto& right) {
        return left.filename().string().starts_with("baykus-")
            > right.filename().string().starts_with("baykus-");
    });
}

void prefer_path_order(std::vector<std::filesystem::path>& paths) {
    std::ranges::sort(paths);
}

void remember_error(std::optional<Error>& chosen, const Error candidate) {
    if (!chosen || *chosen == Error::not_found || candidate == Error::permission_denied) {
        chosen = candidate;
    }
}

std::expected<kvmlib::EvdevInput, Error> open_candidates(
    std::vector<std::filesystem::path>& paths,
    const std::error_code iteration_error = {}) {
    std::optional<Error> chosen_error;
    for (const auto& path : paths) {
        auto input = kvmlib::EvdevInput::open(path.string());
        if (input) return input;
        remember_error(chosen_error, input.error());
    }
    if (chosen_error && *chosen_error != Error::not_found) return std::unexpected(*chosen_error);
    if (iteration_error) return std::unexpected(kvmlib::detail::from_error_code(iteration_error));
    if (chosen_error) return std::unexpected(*chosen_error);
    return std::unexpected(Error::not_found);
}

std::expected<kvmlib::EvdevInput, Error> open_kind(
    const std::string_view kind,
    const bool host_only) {
    auto devices = list_devices([&](const std::string& name) {
        return (!host_only || !name.starts_with("baykus-"))
            && name.contains(kind) && name.contains("event");
    });
    if (!devices) return std::unexpected(devices.error());
    prefer_guest_devices(devices->paths);
    return open_candidates(devices->paths, devices->iteration_error);
}

std::expected<std::vector<kvmlib::EvdevInput>, Error> open_many(
    const auto& predicate) {
    auto devices = list_devices(predicate);
    if (!devices) return std::unexpected(devices.error());
    prefer_path_order(devices->paths);

    std::vector<kvmlib::EvdevInput> result;
    result.reserve(devices->paths.size());
    std::optional<Error> chosen_error;
    for (const auto& path : devices->paths) {
        auto input = kvmlib::EvdevInput::open(path.string());
        if (input) result.push_back(std::move(*input));
        else remember_error(chosen_error, input.error());
    }
    if (devices->iteration_error) {
        return std::unexpected(kvmlib::detail::from_error_code(devices->iteration_error));
    }
    if (!result.empty()) return result;
    return std::unexpected(chosen_error.value_or(Error::not_found));
}

std::expected<void, Error> write_events(
    const int descriptor,
    const std::span<const input_event> events) {
    const auto* bytes = reinterpret_cast<const std::byte*>(events.data());
    const auto total = events.size_bytes();
    std::size_t written_total{};
    while (written_total < total) {
        const auto written = ::write(descriptor, bytes + written_total, total - written_total);
        if (written < 0) {
            if (errno == EINTR) continue;
            return std::unexpected(written_total == 0
                ? kvmlib::detail::from_errno() : Error::partial_write);
        }
        if (written == 0) {
            return std::unexpected(written_total == 0 ? Error::io_error : Error::partial_write);
        }
        const auto count = static_cast<std::size_t>(written);
        if (count > total - written_total || count % sizeof(input_event) != 0) {
            return std::unexpected(Error::partial_write);
        }
        written_total += count;
    }
    return {};
}

}

namespace kvmlib {

EvdevInput::EvdevInput(const int descriptor) noexcept : descriptor_(descriptor) {}

EvdevInput::~EvdevInput() {
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
}

EvdevInput::EvdevInput(EvdevInput&& other) noexcept
    : descriptor_(std::exchange(other.descriptor_, -1)) {}

EvdevInput& EvdevInput::operator=(EvdevInput&& other) noexcept {
    if (this == &other) return *this;
    if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
    descriptor_ = std::exchange(other.descriptor_, -1);
    return *this;
}

std::expected<EvdevInput, Error> EvdevInput::open(std::string path) {
    if (path.empty()) return std::unexpected(Error::invalid_argument);
    if (const auto root = require_root(); !root) return std::unexpected(root.error());
    detail::UniqueFd descriptor(::open(path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC));
    if (!descriptor) return std::unexpected(detail::from_errno());
    return EvdevInput{descriptor.release()};
}

std::expected<EvdevInput, Error> EvdevInput::open_mouse() {
    return open_kind("mouse", false);
}

std::expected<EvdevInput, Error> EvdevInput::open_keyboard() {
    auto result = open_kind("kbd", false);
    if (result) return result;
    std::optional<Error> chosen_error{result.error()};
    result = open_kind("keyboard", false);
    if (result) return result;
    remember_error(chosen_error, result.error());
    return std::unexpected(*chosen_error);
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_mouse() {
    return open("/dev/input/by-id/baykus-vmouse-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_guest_keyboard() {
    return open("/dev/input/by-id/baykus-vkbd-event");
}

std::expected<EvdevInput, Error> EvdevInput::open_host_keyboard() {
    auto result = open_kind("kbd", true);
    if (result) return result;
    std::optional<Error> chosen_error{result.error()};
    result = open_kind("keyboard", true);
    if (result) return result;
    remember_error(chosen_error, result.error());
    return std::unexpected(*chosen_error);
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_keyboards() {
    return open_many([](const std::string& name) {
        return !name.starts_with("baykus-") && name.contains("event")
            && (name.contains("kbd") || name.contains("keyboard"));
    });
}

std::expected<std::vector<EvdevInput>, Error> EvdevInput::open_host_mice() {
    return open_many([](const std::string& name) {
        return !name.starts_with("baykus-") && name.contains("event") && name.contains("mouse");
    });
}

bool EvdevInput::is_open() const noexcept {
    return descriptor_ >= 0;
}

int EvdevInput::native_handle() const noexcept {
    return descriptor_;
}

std::expected<bool, Error> EvdevInput::key_down(const std::uint16_t key_code) const {
    if (!is_open() || key_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    std::array<unsigned char, KEY_MAX / 8 + 1> state{};
    if (::ioctl(descriptor_, EVIOCGKEY(state.size()), state.data()) < 0) {
        return std::unexpected(detail::from_errno());
    }
    return (state[key_code / 8] & (1U << (key_code % 8))) != 0;
}

std::expected<bool, Error> EvdevInput::mouse_button_down(const std::uint16_t button_code) const {
    return key_down(button_code);
}

std::expected<std::size_t, Error> EvdevInput::poll(const std::span<InputEvent> output) {
    if (!is_open()) return std::unexpected(Error::invalid_argument);
    const auto limit = std::min(output.size(), maximum_poll_events);
    if (limit == 0) return std::size_t{};

    std::array<input_event, poll_batch_events> input{};
    std::size_t total{};
    while (total < limit) {
        const auto requested = std::min(limit - total, input.size());
        const auto byte_count = requested * sizeof(input_event);
        const auto bytes = ::read(descriptor_, input.data(), byte_count);
        if (bytes < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return total;
            return total ? std::expected<std::size_t, Error>{total}
                         : std::unexpected(detail::from_errno());
        }
        if (bytes > static_cast<ssize_t>(byte_count)
            || bytes % static_cast<ssize_t>(sizeof(input_event)) != 0) {
            return total ? std::expected<std::size_t, Error>{total}
                         : std::unexpected(Error::io_error);
        }

        const auto count = static_cast<std::size_t>(bytes) / sizeof(input_event);
        for (std::size_t index{}; index < count; ++index) {
            const auto& event = input[index];
            output[total + index] = {event.type, event.code, event.value};
        }
        total += count;
        if (count < requested) break;
    }
    return total;
}

std::expected<std::vector<InputEvent>, Error> EvdevInput::poll() {
    std::array<InputEvent, default_poll_events> output{};
    const auto count = poll(output);
    if (!count) return std::unexpected(count.error());
    return std::vector<InputEvent>(output.begin(), output.begin() + *count);
}

std::expected<void, Error> EvdevInput::send_events(const std::span<const InputEvent> events) const {
    if (!is_open() || events.empty() || events.size() > 4) {
        return std::unexpected(Error::invalid_argument);
    }
    std::array<input_event, 4> native{};
    for (std::size_t index{}; index < events.size(); ++index) {
        native[index].type = events[index].type;
        native[index].code = events[index].code;
        native[index].value = events[index].value;
    }
    return write_events(descriptor_, std::span<const input_event>(native).first(events.size()));
}

std::expected<void, Error> EvdevInput::send_key(const std::uint16_t key_code, const bool pressed) const {
    if (key_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    const std::array events{
        InputEvent{EV_KEY, key_code, pressed ? 1 : 0},
        InputEvent{EV_SYN, SYN_REPORT, 0}
    };
    return send_events(events);
}

std::expected<void, Error> EvdevInput::send_mouse_button(
    const std::uint16_t button_code,
    const bool pressed) const {
    return send_key(button_code, pressed);
}

std::expected<void, Error> EvdevInput::click_mouse_button(const std::uint16_t button_code) const {
    if (button_code > KEY_MAX) return std::unexpected(Error::invalid_argument);
    const std::array events{
        InputEvent{EV_KEY, button_code, 1},
        InputEvent{EV_SYN, SYN_REPORT, 0},
        InputEvent{EV_KEY, button_code, 0},
        InputEvent{EV_SYN, SYN_REPORT, 0}
    };
    return send_events(events);
}

std::expected<void, Error> EvdevInput::move_relative(const std::int32_t x, const std::int32_t y) const {
    if (x == 0 && y == 0) return {};
    std::array<InputEvent, 3> events{};
    std::size_t count{};
    if (x != 0) events[count++] = {EV_REL, REL_X, x};
    if (y != 0) events[count++] = {EV_REL, REL_Y, y};
    events[count++] = {EV_SYN, SYN_REPORT, 0};
    return send_events(std::span<const InputEvent>(events).first(count));
}

}
