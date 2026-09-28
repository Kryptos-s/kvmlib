#include <kvmlib/cr3_trace.hpp>
#include <kvmlib/input.hpp>
#include <kvmlib/privilege.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <iostream>
#include <linux/input.h>
#include <span>
#include <string>
#include <string_view>
#include <sys/file.h>
#include <vector>

namespace {

struct MockCr3Event {
    std::uint64_t timestamp_ns;
    std::uint32_t virtual_cpu;
    std::uint32_t padding;
    std::uint64_t previous;
    std::uint64_t current;
};

static_assert(sizeof(MockCr3Event) == 32);

enum class WriteMode {
    full,
    short_aligned,
    interrupted,
    eagain_after_prefix,
    eagain_zero,
    malformed_short,
};

struct MockState {
    int next_descriptor{ 100 };
    int owner_descriptor{ -1 };
    int flock_calls{};
    int close_calls{};
    int disarm_calls{};
    int fail_disarms{};
    int read_calls{};
    int write_calls{};
    WriteMode write_mode{ WriteMode::full };
    std::size_t cr3_events_remaining{};
    std::size_t cr3_events_emitted{};
    int trace_read_calls{};
    int trace_fail_after{ -1 };
    bool cr3_eintr{};
    std::vector<input_event> input_events;
    std::size_t input_cursor{};
    bool input_eintr{};
    int input_read_calls{};
    int input_fail_after{ -1 };
    std::vector<int> trace_descriptors;
    std::vector<int> input_descriptors;
    std::vector<int> closed_descriptors;
    std::vector<std::string> open_paths;
    std::vector<std::vector<std::byte>> writes;
};

MockState state;
int failures{};

bool is_trace_descriptor(const int descriptor) {
    for (const auto value : state.trace_descriptors) {
        if (value == descriptor) return true;
    }
    return false;
}

bool is_input_descriptor(const int descriptor) {
    for (const auto value : state.input_descriptors) {
        if (value == descriptor) return true;
    }
    return false;
}

bool is_mock_descriptor(const int descriptor) {
    return is_trace_descriptor(descriptor) || is_input_descriptor(descriptor);
}

void reset_state() {
    state = MockState{};
}

bool check(const bool condition, const std::string_view label) {
    if (condition) return true;
    ++failures;
    std::cerr << "FAIL " << label << '\n';
    return false;
}

template <typename T>
bool check_error(const std::expected<T, kvmlib::Error>& result, const kvmlib::Error error, const std::string_view label) {
    return check(!result && result.error() == error, label);
}

std::vector<input_event> decoded_writes() {
    std::vector<input_event> result;
    for (const auto& payload : state.writes) {
        for (std::size_t offset = 0; offset + sizeof(input_event) <= payload.size(); offset += sizeof(input_event)) {
            input_event event{};
            std::memcpy(&event, payload.data() + offset, sizeof(event));
            result.push_back(event);
        }
    }
    return result;
}

bool check_event(const input_event& actual, const std::uint16_t type, const std::uint16_t code,
    const std::int32_t value, const std::string_view label) {
    return check(actual.type == type && actual.code == code && actual.value == value, label);
}

input_event mock_input_event(const std::uint16_t type, const std::uint16_t code, const std::int32_t value) {
    input_event event{};
    event.type = type;
    event.code = code;
    event.value = value;
    return event;
}

input_event decoded_write_event(const std::size_t write_index) {
    input_event event{};
    if (write_index < state.writes.size() && state.writes[write_index].size() >= sizeof(event)) {
        std::memcpy(&event, state.writes[write_index].data(), sizeof(event));
    }
    return event;
}

void clear_writes(const WriteMode mode) {
    state.write_mode = mode;
    state.write_calls = 0;
    state.writes.clear();
}

bool test_default_objects() {
    reset_state();
    kvmlib::Cr3Trace trace;
    kvmlib::EvdevInput input;
    std::array<kvmlib::Cr3Event, 1> trace_events;
    std::array<kvmlib::InputEvent, 1> input_events;
    check(!trace.enabled(), "default trace disabled");
    check(trace.native_handle() == -1, "default trace handle");
    const auto default_start = trace.start();
    check_error(default_start, kvmlib::Error::invalid_argument, "default trace start");
    check(!trace.poll(std::span<kvmlib::Cr3Event>(trace_events)), "default trace span poll");
    check(!trace.poll(), "default trace vector poll");
    check(input.native_handle() == -1, "default input handle");
    check(!input.poll(std::span<kvmlib::InputEvent>(input_events)), "default input span poll");
    check(!input.poll(), "default input vector poll");
    check(!input.send_key(KEY_A, true), "default input send");
    check(state.read_calls == 0 && state.write_calls == 0, "default no syscalls");
    return true;
}

bool test_trace_lifecycle() {
    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "trace open")) return false;
        auto& trace = *opened;
        check(trace.native_handle() >= 100, "trace native handle");
        check(!trace.enabled(), "trace initially disabled");
        std::array<kvmlib::Cr3Event, 2> output;
        const auto stopped_poll = trace.poll(std::span<kvmlib::Cr3Event>(output));
        check(stopped_poll && *stopped_poll == 0, "stopped trace empty poll");
        check(trace.start().has_value(), "trace start");
        check(trace.enabled(), "trace enabled");
        state.fail_disarms = 1;
        const auto failed_stop = trace.stop();
        check_error(failed_stop, kvmlib::Error::io_error, "failed trace stop");
        check(trace.enabled(), "failed stop preserves enabled");
        check(trace.stop().has_value(), "trace stop retry");
        check(!trace.enabled(), "trace disabled after retry");
        state.cr3_events_remaining = 1;
        const auto tail = trace.poll(std::span<kvmlib::Cr3Event>(output));
        check(tail && *tail == 1, "stopped trace tail poll");
        if (tail && *tail == 1) {
            check(output[0].timestamp_ns == 1000, "trace tail timestamp");
            check(output[0].virtual_cpu == 7, "trace tail vcpu");
            check(output[0].previous == 0x1000, "trace tail previous");
            check(output[0].current == 0x2000, "trace tail current");
        }
        const auto empty_vector = trace.poll();
        check(empty_vector && empty_vector->empty(), "trace empty vector poll");
    }
    check(state.close_calls == 1, "trace close once");
    for (const auto& path : state.open_paths) check(!path.starts_with("/dev/"), "trace no device open");

    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "trace destructor retry open")) return false;
        check(opened->start().has_value(), "trace destructor retry start");
        state.fail_disarms = 1;
        check_error(opened->stop(), kvmlib::Error::io_error, "trace destructor retry first failure");
        check(opened->enabled(), "trace destructor retry remains enabled");
    }
    check(state.disarm_calls == 2, "trace destructor retries disarm");
    return true;
}

bool test_trace_lock_and_moves() {
    reset_state();
    {
        auto first = kvmlib::Cr3Trace::open("mock-trace");
        check(first.has_value(), "first trace owner");
        auto second = kvmlib::Cr3Trace::open("mock-trace");
        check_error(second, kvmlib::Error::busy, "second trace owner rejected");
        check(state.flock_calls == 2, "flock call count");
        check(state.close_calls == 1, "failed owner descriptor closed");
    }
    check(state.close_calls == 2, "owner close after contention");

    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "trace move source open")) return false;
        const auto descriptor = opened->native_handle();
        kvmlib::Cr3Trace moved(std::move(*opened));
        check(opened->native_handle() == -1 && !opened->enabled(), "trace move constructor source");
        check(moved.native_handle() == descriptor, "trace move constructor target");
        kvmlib::Cr3Trace target;
        target = std::move(moved);
        check(moved.native_handle() == -1, "trace move assignment source");
        check(target.native_handle() == descriptor, "trace move assignment target");
    }
    check(state.close_calls == 1, "moved trace closes once");

    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "trace cleanup open")) return false;
        check(opened->start().has_value(), "trace cleanup start");
        kvmlib::Cr3Trace target(std::move(*opened));
        state.fail_disarms = 1;
        target = kvmlib::Cr3Trace{};
        check(target.native_handle() == -1 && !target.enabled(), "failed cleanup resets move target");
        check(state.disarm_calls == 1, "failed cleanup attempted disarm");
        check(state.close_calls == 1, "failed cleanup closes descriptor");
    }
    return true;
}

bool test_trace_large_poll() {
    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "large trace open")) return false;
        std::vector<kvmlib::Cr3Event> output(5000);
        state.cr3_events_remaining = 5000;
        const auto count = opened->poll(std::span<kvmlib::Cr3Event>(output));
        check(count && *count == 4096, "bounded large trace poll");
        check(state.read_calls == 32, "bounded trace read batches");
        if (count && *count == 4096) {
            check(output[4095].timestamp_ns == 5095, "large trace last event");
            check(output[4095].virtual_cpu == 7, "large trace last vcpu");
        }
    }
    return true;
}

bool test_poll_prefix_on_error() {
    reset_state();
    {
        auto opened = kvmlib::Cr3Trace::open("mock-trace");
        if (!check(opened.has_value(), "trace prefix open")) return false;
        std::vector<kvmlib::Cr3Event> output(256);
        state.cr3_events_remaining = 256;
        state.trace_fail_after = 1;
        const auto count = opened->poll(std::span<kvmlib::Cr3Event>(output));
        check(count && *count == 128, "trace prefix retained after read error");
        check(state.read_calls == 2, "trace prefix read error call");
        if (count && *count == 128) check(output[127].timestamp_ns == 1127, "trace prefix last event");
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "input prefix open")) return false;
        state.input_events.resize(256);
        for (std::size_t index = 0; index < state.input_events.size(); ++index) {
            state.input_events[index] = mock_input_event(EV_REL, REL_Y, static_cast<int>(index));
        }
        std::vector<kvmlib::InputEvent> output(256);
        state.input_fail_after = 1;
        const auto count = opened->poll(std::span<kvmlib::InputEvent>(output));
        check(count && *count == 128, "input prefix retained after read error");
        check(state.read_calls == 2, "input prefix read error call");
        if (count && *count == 128) check(output[127].value == 127, "input prefix last event");
    }
    return true;
}

bool test_input_batches() {
    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "input open")) return false;
        check(opened->native_handle() >= 100, "input native handle");
        clear_writes(WriteMode::full);
        check(opened->send_key(KEY_A, true).has_value(), "batched key");
        check(state.write_calls == 1 && state.writes.size() == 1, "key one write");
        auto key_events = decoded_writes();
        check(key_events.size() == 2, "key event count");
        if (key_events.size() == 2) {
            check_event(key_events[0], EV_KEY, KEY_A, 1, "key event");
            check_event(key_events[1], EV_SYN, SYN_REPORT, 0, "key sync");
        }
        clear_writes(WriteMode::full);
        check(opened->click_mouse_button(BTN_LEFT).has_value(), "batched click");
        check(state.write_calls == 1 && state.writes.size() == 1, "click one write");
        auto click_events = decoded_writes();
        check(click_events.size() == 4, "click event count");
        if (click_events.size() == 4) {
            check_event(click_events[0], EV_KEY, BTN_LEFT, 1, "click press");
            check_event(click_events[1], EV_SYN, SYN_REPORT, 0, "click press sync");
            check_event(click_events[2], EV_KEY, BTN_LEFT, 0, "click release");
            check_event(click_events[3], EV_SYN, SYN_REPORT, 0, "click release sync");
        }
        clear_writes(WriteMode::full);
        check(opened->move_relative(8, -4).has_value(), "batched move");
        check(state.write_calls == 1 && state.writes.size() == 1, "move one write");
        auto move_events = decoded_writes();
        check(move_events.size() == 3, "move event count");
        if (move_events.size() == 3) {
            check_event(move_events[0], EV_REL, REL_X, 8, "move x");
            check_event(move_events[1], EV_REL, REL_Y, -4, "move y");
            check_event(move_events[2], EV_SYN, SYN_REPORT, 0, "move sync");
        }
        clear_writes(WriteMode::full);
        check(opened->move_relative(0, 0).has_value(), "empty move");
        check(state.write_calls == 0, "empty move no write");
    }
    for (const auto& path : state.open_paths) check(!path.starts_with("/dev/"), "input no device open");
    return true;
}

bool test_input_write_failures() {
    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "short write input open")) return false;
        clear_writes(WriteMode::short_aligned);
        check(opened->send_key(KEY_B, true).has_value(), "aligned short write retry");
        check(state.write_calls == 2, "aligned short write calls");
        check(state.writes.size() == 2 && state.writes[1].size() == sizeof(input_event), "aligned short write no replay");
        if (state.writes.size() == 2 && state.writes[1].size() == sizeof(input_event)) {
            check_event(decoded_write_event(0), EV_KEY, KEY_B, 1, "aligned short key");
            check_event(decoded_write_event(1), EV_SYN, SYN_REPORT, 0, "aligned short sync");
        }
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "interrupt input open")) return false;
        clear_writes(WriteMode::interrupted);
        check(opened->send_key(KEY_C, true).has_value(), "interrupted write retry");
        check(state.write_calls == 2, "interrupted write calls");
        check(state.writes.size() == 2 && state.writes[1].size() == 2 * sizeof(input_event), "interrupted write payload");
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "partial input open")) return false;
        clear_writes(WriteMode::eagain_after_prefix);
        const auto result = opened->send_key(KEY_D, true);
        check_error(result, kvmlib::Error::partial_write, "partial write error");
        check(state.write_calls == 2 && state.writes.size() == 2 && state.writes[1].size() == sizeof(input_event), "partial write no replay");
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "empty eagain input open")) return false;
        clear_writes(WriteMode::eagain_zero);
        const auto result = opened->send_key(KEY_E, true);
        check_error(result, kvmlib::Error::io_error, "zero progress eagain error");
        check(state.write_calls == 1, "zero progress eagain calls");
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "malformed input open")) return false;
        clear_writes(WriteMode::malformed_short);
        const auto result = opened->send_key(KEY_F, true);
        check_error(result, kvmlib::Error::partial_write, "malformed short error");
        check(state.write_calls == 1, "malformed short no replay");
    }
    return true;
}

bool test_input_poll() {
    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "input poll open")) return false;
        state.input_events = {
            mock_input_event(EV_KEY, KEY_A, 1),
            mock_input_event(EV_SYN, SYN_REPORT, 0),
            mock_input_event(EV_REL, REL_X, 3),
        };
        std::array<kvmlib::InputEvent, 4> output;
        const auto count = opened->poll(std::span<kvmlib::InputEvent>(output));
        check(count && *count == 3, "input span poll");
        if (count && *count == 3) {
            check(output[0].type == EV_KEY && output[0].code == KEY_A && output[0].value == 1, "input poll key");
            check(output[1].type == EV_SYN && output[1].code == SYN_REPORT, "input poll sync");
            check(output[2].type == EV_REL && output[2].code == REL_X && output[2].value == 3, "input poll rel");
        }
        const auto before_empty = state.read_calls;
        const auto empty_span = opened->poll(std::span<kvmlib::InputEvent>{});
        check(empty_span && *empty_span == 0, "input empty span poll");
        check(state.read_calls == before_empty, "input empty span no read");
        const auto empty_vector = opened->poll();
        check(empty_vector && empty_vector->empty(), "input empty vector poll");
    }

    reset_state();
    {
        auto opened = kvmlib::EvdevInput::open("mock-input");
        if (!check(opened.has_value(), "large input poll open")) return false;
        state.input_events.resize(5000);
        for (std::size_t index = 0; index < state.input_events.size(); ++index) {
            state.input_events[index] = mock_input_event(EV_REL, REL_X, static_cast<int>(index));
        }
        std::vector<kvmlib::InputEvent> output(5000);
        const auto count = opened->poll(std::span<kvmlib::InputEvent>(output));
        check(count && *count == 4096, "bounded large input poll");
        check(state.read_calls == 32, "bounded input read batches");
        if (count && *count == 4096) check(output[4095].value == 4095, "large input last event");
    }
    return true;
}

bool test_invalid_open_paths() {
    reset_state();
    std::string input_path{"mock-input"};
    input_path.push_back('\0');
    input_path += "suffix";
    const auto input = kvmlib::EvdevInput::open(input_path);
    check_error(input, kvmlib::Error::invalid_argument, "input embedded nul path");
    check(state.open_paths.empty(), "input embedded nul no open");

    reset_state();
    std::string trace_path{"mock-trace"};
    trace_path.push_back('\0');
    trace_path += "suffix";
    const auto trace = kvmlib::Cr3Trace::open(trace_path);
    check_error(trace, kvmlib::Error::invalid_argument, "trace embedded nul path");
    check(state.open_paths.empty(), "trace embedded nul no open");

    reset_state();
    const auto empty_trace = kvmlib::Cr3Trace::open({});
    check_error(empty_trace, kvmlib::Error::invalid_argument, "trace empty path");
    check(state.open_paths.empty(), "trace empty no open");
    return true;
}

}

extern "C" int __real_close(int);
extern "C" int __real_flock(int, int);
extern "C" ssize_t __real_read(int, void*, std::size_t);
extern "C" ssize_t __real_write(int, const void*, std::size_t);
extern "C" int __real_open(const char*, int, ...);

extern "C" int __wrap_open(const char* path, const int flags, ...) {
    const std::string value = path == nullptr ? std::string{} : std::string(path);
    if (!value.starts_with("mock-")) return __real_open(path, flags);
    const int descriptor = state.next_descriptor++;
    state.open_paths.push_back(value);
    if (value.contains("trace")) state.trace_descriptors.push_back(descriptor);
    else state.input_descriptors.push_back(descriptor);
    return descriptor;
}

extern "C" int __wrap_close(const int descriptor) {
    if (!is_mock_descriptor(descriptor)) return __real_close(descriptor);
    ++state.close_calls;
    state.closed_descriptors.push_back(descriptor);
    if (state.owner_descriptor == descriptor) state.owner_descriptor = -1;
    return 0;
}

extern "C" ssize_t __wrap_read(const int descriptor, void* buffer, const std::size_t count) {
    if (!is_mock_descriptor(descriptor)) return __real_read(descriptor, buffer, count);
    ++state.read_calls;
    if (is_trace_descriptor(descriptor)) {
        ++state.trace_read_calls;
        if (state.trace_fail_after >= 0 && state.trace_read_calls > state.trace_fail_after) {
            errno = EIO;
            return -1;
        }
        if (state.cr3_eintr) {
            state.cr3_eintr = false;
            errno = EINTR;
            return -1;
        }
        const auto capacity = count / sizeof(MockCr3Event);
        const auto amount = std::min(capacity, state.cr3_events_remaining);
        auto* events = static_cast<MockCr3Event*>(buffer);
        for (std::size_t index = 0; index < amount; ++index) {
            const auto sequence = state.cr3_events_emitted + index;
            events[index] = MockCr3Event{ 1000 + sequence, 7, 0, 0x1000 + sequence, 0x2000 + sequence };
        }
        state.cr3_events_remaining -= amount;
        state.cr3_events_emitted += amount;
        if (amount == 0) {
            errno = EAGAIN;
            return -1;
        }
        return static_cast<ssize_t>(amount * sizeof(MockCr3Event));
    }
    ++state.input_read_calls;
    if (state.input_fail_after >= 0 && state.input_read_calls > state.input_fail_after) {
        errno = EIO;
        return -1;
    }
    if (state.input_eintr) {
        state.input_eintr = false;
        errno = EINTR;
        return -1;
    }
    const auto capacity = count / sizeof(input_event);
    const auto available = state.input_events.size() - state.input_cursor;
    const auto amount = std::min(capacity, available);
    if (amount == 0) {
        errno = EAGAIN;
        return -1;
    }
    std::memcpy(buffer, state.input_events.data() + state.input_cursor, amount * sizeof(input_event));
    state.input_cursor += amount;
    return static_cast<ssize_t>(amount * sizeof(input_event));
}

extern "C" ssize_t __wrap_write(const int descriptor, const void* buffer, const std::size_t count) {
    if (!is_mock_descriptor(descriptor)) return __real_write(descriptor, buffer, count);
    ++state.write_calls;
    const auto* bytes = reinterpret_cast<const std::byte*>(buffer);
    state.writes.emplace_back(bytes, bytes + count);
    const auto attempt = state.write_calls;
    if (state.write_mode == WriteMode::full) return static_cast<ssize_t>(count);
    if (state.write_mode == WriteMode::short_aligned && attempt == 1) return static_cast<ssize_t>(sizeof(input_event));
    if (state.write_mode == WriteMode::interrupted && attempt == 1) {
        errno = EINTR;
        return -1;
    }
    if (state.write_mode == WriteMode::eagain_after_prefix) {
        if (attempt == 1) return static_cast<ssize_t>(sizeof(input_event));
        errno = EAGAIN;
        return -1;
    }
    if (state.write_mode == WriteMode::eagain_zero) {
        errno = EAGAIN;
        return -1;
    }
    if (state.write_mode == WriteMode::malformed_short && attempt == 1) return 1;
    return static_cast<ssize_t>(count);
}

extern "C" int __wrap_ioctl(const int descriptor, const unsigned long command, ...) {
    if (!is_mock_descriptor(descriptor)) return 0;
    const auto disarm = (0xC3UL << 8) | 2UL;
    if (command == disarm) {
        ++state.disarm_calls;
        if (state.fail_disarms > 0) {
            --state.fail_disarms;
            errno = EIO;
            return -1;
        }
    }
    return 0;
}

extern "C" int __wrap_flock(const int descriptor, const int operation) {
    if (!is_mock_descriptor(descriptor)) return __real_flock(descriptor, operation);
    ++state.flock_calls;
    if ((operation & LOCK_EX) != 0 && (operation & LOCK_NB) != 0) {
        if (state.owner_descriptor >= 0) {
            errno = EWOULDBLOCK;
            return -1;
        }
        state.owner_descriptor = descriptor;
    }
    if ((operation & LOCK_UN) != 0 && state.owner_descriptor == descriptor) state.owner_descriptor = -1;
    return 0;
}

namespace kvmlib {

std::expected<void, Error> require_root() noexcept {
    return {};
}

}

int main() {
    test_default_objects();
    test_trace_lifecycle();
    test_trace_lock_and_moves();
    test_trace_large_poll();
    test_poll_prefix_on_error();
    test_input_batches();
    test_input_write_failures();
    test_input_poll();
    test_invalid_open_paths();
    if (failures != 0) {
        std::cerr << failures << " host checks failed\n";
        return 1;
    }
    std::cout << "host checks passed\n";
    return 0;
}
