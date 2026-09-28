#include <kvmlib/kvmlib.hpp>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

bool check(const bool condition, const std::string_view label, int& failures) {
    if (condition) {
        return true;
    }
    std::cerr << "FAIL " << label << '\n';
    ++failures;
    return false;
}

}

namespace {

bool inject_pread_eintr{};
bool inject_pread_success{};
std::size_t wrapped_pread_calls{};
std::size_t wrapped_pread_max_count{};

}

extern "C" ssize_t __real_pread(int descriptor, void* destination, std::size_t count, off_t offset);

extern "C" ssize_t __wrap_pread(
    int descriptor, void* destination, std::size_t count, off_t offset) {
    ++wrapped_pread_calls;
    wrapped_pread_max_count = std::max(wrapped_pread_max_count, count);
    if (inject_pread_eintr) {
        inject_pread_eintr = false;
        errno = EINTR;
        return -1;
    }
    if (inject_pread_success) {
        std::memset(destination, 0, count);
        return static_cast<ssize_t>(count);
    }
    return __real_pread(descriptor, destination, count, offset);
}

int main() {
    int failures{};

    const auto memory = kvmlib::memory_info();
    if (check(memory.has_value(), "memory_info", failures)) {
        check(memory->total_bytes > 0, "memory_info total", failures);
        check(memory->available_bytes <= memory->total_bytes, "memory_info available", failures);
    }

    const auto topology = kvmlib::cpu_topology();
    if (check(topology.has_value(), "cpu_topology", failures)) {
        check(!topology->threads.empty(), "cpu_topology threads", failures);
        check(topology->physical_core_count() > 0, "cpu_topology cores", failures);
        if (!topology->threads.empty()) {
            const auto logical_id = topology->threads.front().logical_id;
            const auto found = topology->find(logical_id);
            check(found != nullptr && found->logical_id == logical_id, "cpu_topology find", failures);
            check(!topology->threads.front().siblings.empty(), "cpu_topology siblings", failures);
        }
        check(topology->find(std::numeric_limits<std::uint32_t>::max()) == nullptr,
            "cpu_topology missing find", failures);
    }

    const auto invalid_process = kvmlib::ProcessMemory::open(0);
    check(!invalid_process && invalid_process.error() == kvmlib::Error::invalid_argument,
        "invalid process id", failures);

    const auto process = kvmlib::ProcessMemory::open(getpid());
    if (!check(process.has_value(), "open self", failures)) {
        return failures == 0 ? 1 : failures;
    }

    const std::array<char, 6> small_text{ 'h', 'e', 'l', 'l', 'o', '\0' };
    const auto small = process->read_string(reinterpret_cast<std::uintptr_t>(small_text.data()), 64);
    check(small && *small == "hello", "read_string small", failures);

    wrapped_pread_calls = 0;
    wrapped_pread_max_count = 0;
    const auto bounded = process->read_string(reinterpret_cast<std::uintptr_t>(small_text.data()), 1024);
    check(bounded && *bounded == "hello", "read_string bounded request", failures);
    check(wrapped_pread_calls == 1 && wrapped_pread_max_count <= 256,
        "read_string bounded chunk", failures);

    std::array<char, 1024> long_text{};
    long_text.fill('z');
    long_text[700] = '\0';
    const auto long_result = process->read_string(reinterpret_cast<std::uintptr_t>(long_text.data()), 1024);
    check(long_result && *long_result == std::string(700, 'z'), "read_string long", failures);

    const std::array<char, 5> limited_text{ 'a', 'b', 'c', 'd', 'e' };
    const auto limited = process->read_string(reinterpret_cast<std::uintptr_t>(limited_text.data()), 5);
    check(limited && *limited == "abcde", "read_string limit", failures);

    const auto zero = kvmlib::ProcessMemory{}.read_string(0, 0);
    check(zero && zero->empty(), "read_string zero", failures);

    std::array<std::byte, 2> bytes{};
    std::array<std::byte, 2> retry_destination{};
    inject_pread_eintr = true;
    const auto retried = process->read(
        reinterpret_cast<std::uintptr_t>(small_text.data()), retry_destination);
    inject_pread_eintr = false;
    check(retried && *retried == retry_destination.size(), "read EINTR retry", failures);
    const auto invalid_read = process->read(0, bytes);
    check(!invalid_read && invalid_read.error() == kvmlib::Error::invalid_argument,
        "read zero address", failures);

    const auto overflow_read = process->read(std::numeric_limits<std::uintptr_t>::max(), bytes);
    check(!overflow_read && overflow_read.error() == kvmlib::Error::invalid_argument,
        "read address overflow", failures);

    const auto overflow_string = process->read_string(
        std::numeric_limits<std::uintptr_t>::max(), 2);
    check(!overflow_string && overflow_string.error() == kvmlib::Error::invalid_argument,
        "read_string address overflow", failures);

    inject_pread_success = true;
    const auto end_read = process->read(std::numeric_limits<std::uintptr_t>::max() - 1, bytes);
    const auto end_string = process->read_string(std::numeric_limits<std::uintptr_t>::max(), 1);
    inject_pread_success = false;
    check(end_read && *end_read == 2, "read range ends at maximum address", failures);
    check(end_string && end_string->empty(), "string at maximum address", failures);

    std::vector<char> large_text(128 * 1024, 'k');
    large_text.back() = '\0';
    wrapped_pread_calls = 0;
    const auto large_string = process->read_string(
        reinterpret_cast<std::uintptr_t>(large_text.data()), large_text.size());
    check(large_string && *large_string == std::string(large_text.size() - 1, 'k'),
        "read_string large", failures);
    check(wrapped_pread_calls == 3, "large strings use bounded larger reads", failures);

    const std::array<std::uint32_t, 2> object_source{ 0x12345678, 0x9abcdef0 };
    const auto copied = process->read_object<std::array<std::uint32_t, 2>>(
        reinterpret_cast<std::uintptr_t>(object_source.data()));
    check(copied && *copied == object_source, "read_object", failures);
    const auto invalid_object = kvmlib::ProcessMemory{}.read_object<std::uint32_t>(1);
    check(!invalid_object && invalid_object.error() == kvmlib::Error::invalid_argument,
        "invalid read_object", failures);

    auto moved_source = kvmlib::ProcessMemory::open(getpid());
    if (check(moved_source.has_value(), "open moved source", failures)) {
        kvmlib::ProcessMemory moved_target{ std::move(*moved_source) };
        check(!moved_source->is_open(), "moved source closed", failures);
        check(moved_target.is_open(), "moved target open", failures);
        const auto moved_read = moved_source->read(1, bytes);
        check(!moved_read && moved_read.error() == kvmlib::Error::invalid_argument,
            "moved source read", failures);
        const auto moved_object = moved_source->read_object<std::uint32_t>(
            reinterpret_cast<std::uintptr_t>(object_source.data()));
        check(!moved_object && moved_object.error() == kvmlib::Error::invalid_argument,
            "moved source read_object", failures);
        kvmlib::ProcessMemory assigned;
        assigned = std::move(moved_target);
        check(assigned.is_open() && !moved_target.is_open(), "move assignment", failures);
    }

    const auto regions = process->regions();
    if (check(regions.has_value(), "regions", failures)) {
        const auto has_name = [&regions](const std::string_view name) {
            return std::ranges::any_of(*regions, [name](const kvmlib::MemoryRegion& region) {
                return region.name == name;
            });
        };
        const std::array<std::string_view, 3> labels{ "[heap]", "[stack]", "[vdso]" };
        std::array<bool, labels.size()> present{};
        std::ifstream maps("/proc/self/maps");
        std::string line;
        while (std::getline(maps, line)) {
            for (std::size_t index{}; index < labels.size(); ++index) {
                present[index] = present[index] || line.ends_with(labels[index]);
            }
        }
        bool exercised{};
        for (std::size_t index{}; index < labels.size(); ++index) {
            if (present[index]) {
                exercised = true;
                check(has_name(labels[index]), "regions known label", failures);
            }
        }
        check(exercised, "regions label coverage", failures);
    }

    const auto page_size = ::sysconf(_SC_PAGESIZE);
    if (check(page_size > 0, "page size", failures)) {
        const auto mapping_size = static_cast<std::size_t>(page_size) * 2;
        void* mapping = ::mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (check(mapping != MAP_FAILED, "mmap boundary", failures)) {
            std::memset(mapping, 'x', mapping_size);
            std::vector<std::byte> partial_destination(
                static_cast<std::size_t>(page_size) + 16);
            auto* second_page = static_cast<std::byte*>(mapping) + page_size;
            if (check(::munmap(second_page, static_cast<std::size_t>(page_size)) == 0,
                    "munmap boundary", failures)) {
                const auto partial = process->read(
                    reinterpret_cast<std::uintptr_t>(mapping), partial_destination);
                check(partial && *partial == static_cast<std::size_t>(page_size),
                    "read cross page partial", failures);

                const auto cross_page = process->read_string(
                    reinterpret_cast<std::uintptr_t>(mapping), mapping_size);
                check(cross_page && cross_page->size() == static_cast<std::size_t>(page_size),
                    "read_string cross page partial", failures);
            }
            check(::munmap(mapping, static_cast<std::size_t>(page_size)) == 0,
                "munmap first page", failures);
        }
    }

    return failures == 0 ? 0 : 1;
}
