#pragma once

#include "kvmlib/error.hpp"

#include <cstdint>
#include <cstddef>
#include <expected>
#include <span>
#include <string>
#include <vector>

namespace kvmlib {

struct InputEvent {
    std::uint16_t type{};
    std::uint16_t code{};
    std::int32_t value{};
};

class EvdevInput {
public:
    EvdevInput() = default;
    ~EvdevInput();

    EvdevInput(const EvdevInput&) = delete;
    EvdevInput& operator=(const EvdevInput&) = delete;
    EvdevInput(EvdevInput&& other) noexcept;
    EvdevInput& operator=(EvdevInput&& other) noexcept;

    [[nodiscard]] static std::expected<EvdevInput, Error> open(std::string path);
    [[nodiscard]] static std::expected<EvdevInput, Error> open_mouse();
    [[nodiscard]] static std::expected<EvdevInput, Error> open_keyboard();
    [[nodiscard]] static std::expected<EvdevInput, Error> open_guest_mouse();
    [[nodiscard]] static std::expected<EvdevInput, Error> open_guest_keyboard();
    [[nodiscard]] static std::expected<EvdevInput, Error> open_host_keyboard();
    [[nodiscard]] static std::expected<std::vector<EvdevInput>, Error> open_host_keyboards();
    [[nodiscard]] static std::expected<std::vector<EvdevInput>, Error> open_host_mice();
    [[nodiscard]] bool is_open() const noexcept;
    [[nodiscard]] int native_handle() const noexcept;
    [[nodiscard]] std::expected<bool, Error> key_down(std::uint16_t key_code) const;
    [[nodiscard]] std::expected<bool, Error> mouse_button_down(std::uint16_t button_code) const;
    [[nodiscard]] std::expected<std::size_t, Error> poll(std::span<InputEvent> output);
    [[nodiscard]] std::expected<std::vector<InputEvent>, Error> poll();
    [[nodiscard]] std::expected<void, Error> send_key(std::uint16_t key_code, bool pressed) const;
    [[nodiscard]] std::expected<void, Error> send_mouse_button(std::uint16_t button_code, bool pressed) const;
    [[nodiscard]] std::expected<void, Error> click_mouse_button(std::uint16_t button_code) const;
    [[nodiscard]] std::expected<void, Error> move_relative(std::int32_t x, std::int32_t y) const;

private:
    explicit EvdevInput(int descriptor) noexcept;
    [[nodiscard]] std::expected<void, Error> send_events(std::span<const InputEvent> events) const;

    int descriptor_{ -1 };
};

}
