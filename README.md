# KVMLib

Linux C++23 library for process memory, CPU topology, evdev input, KVM CR3 tracing, and optional MemProcFS access.

`ProcessMemory` reads through `/proc/<pid>/mem` and follows ptrace permissions. MemProcFS supports guest-memory reads and writes; evdev supports input capture and injection. MemProcFS, evdev, and CR3 tracing require root. CR3 tracing also requires the matching custom kernel driver.

## Build

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

Requires Linux, CMake 3.25+, and a C++23 compiler with `std::expected`.

Tests use self-process reads and mocked device/backend calls. Checks stay active in Release builds. Tests and examples are disabled by default under `add_subdirectory`. For standalone builds, disable them with `KVMLIB_BUILD_TESTS=OFF` and `KVMLIB_BUILD_EXAMPLES=OFF`; `BUILD_TESTING=OFF` also disables tests.

## MemProcFS backend

```sh
cmake -S . -B build-memprocfs -DCMAKE_BUILD_TYPE=Release \
  -DKVMLIB_ENABLE_MEMPROCFS=ON \
  -DMEMPROCFS_ROOT=/path/to/MemProcFS \
  -DMEMPROCFS_LIBRARY_DIR=/path/to/vmm-runtime
cmake --build build-memprocfs
ctest --test-dir build-memprocfs --output-on-failure
```

The runtime directory must contain `vmm.so` and its dependencies. Check `MemProcFs::available()` for build support. Without it, backend methods return `Error::unsupported`.

Process names use exact, case-insensitive matching. Duplicate matches are errors. QEMU discovery parses `-name` and matches the complete guest name; ambiguous options and comma-escaped arguments are rejected. Call `refresh()` when process information needs updating.

Pass a QMP socket to `open_qemu(name, qmp_path, refresh_mode)`, or use the default `/tmp/qmp-<name>.sock`. Names and paths cannot contain commas or NUL characters.

Reads default to `MemoryCachePolicy::fresh`. Set `MemProcFsOptions::cache_policy` to `cached` when stale data is acceptable. Fresh reads still use cached page tables; translation refresh is separate.

Use `read_batch(pid)` for repeated scatter reads. Matching addresses, buffers, and sizes reuse the prepared requests. Changed requests are rebuilt. A batch owns its backend session and remains valid if the original backend object is moved or destroyed.

```cpp
#include <kvmlib/memprocfs.hpp>

#include <array>
#include <cstddef>
#include <cstdint>

int sample_twice(const kvmlib::MemProcFs& backend, std::uint32_t pid, std::uint64_t address) {
    std::array<std::byte, 64> bytes{};
    std::array transfers{ kvmlib::MemoryTransfer{ address, bytes, 0 } };
    auto batch = backend.read_batch(pid);
    if (!batch) {
        return 1;
    }
    for (int sample = 0; sample < 2; ++sample) {
        if (!batch->execute(transfers)) {
            return 1;
        }
    }
    return !batch->clear();
}
```

Keep destination buffers alive until `clear()`, successful `rebind()`, or destruction. The descriptor array is not retained. Use each batch from one caller at a time.

`bytes_read` reports completed reads. Scatter writes reuse this field for total bytes written, which may not form a contiguous prefix. Partial writes return `Error::partial_write`. Completed writes are not rolled back; retrying an entire failed batch can repeat them. Batches are not transactions or consistent memory snapshots.

Dumps replace regular files after all writes and close succeed. Failures preserve the previous file. Symlinks and device files are rejected. Dumps do not provide power-loss durability.

## Use from CMake

Embed the source:

```cmake
add_subdirectory(path/to/KVMLib)
target_link_libraries(my_app PRIVATE kvmlib::kvmlib)
```

Or install and consume the package:

```sh
cmake --install build --prefix /path/to/kvmlib-install
```

```cmake
find_package(KVMLib 0.1 CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE kvmlib::kvmlib)
```

Set `CMAKE_PREFIX_PATH` to the install prefix. With MemProcFS enabled, set `MEMPROCFS_LIBRARY_DIR` or provide `KVMLib::MemProcFS`. Deploy the external runtime separately. Consumers do not need MemProcFS headers.

## Basic usage

```cpp
#include <kvmlib/kvmlib.hpp>

#include <iostream>
#include <unistd.h>

int main() {
    const auto host_memory = kvmlib::memory_info();
    const auto cpu = kvmlib::cpu_topology();
    const auto kvm = kvmlib::kvm_status();
    const auto self = kvmlib::ProcessMemory::open(getpid());
    if (!host_memory || !cpu || !kvm || !self) {
        return 1;
    }
    std::cout << host_memory->available_bytes << '\n';
    std::cout << cpu->physical_core_count() << '\n';
    std::cout << cpu->smt_enabled() << '\n';
    std::cout << kvm->device_accessible << '\n';
}
```

Topology covers online CPUs. Missing required topology data returns an error. `smt_enabled()` checks sibling relationships, not the kernel SMT switch. `kvm_status()` checks device presence, permissions, and CPU flags; it does not create a VM.

## Process memory

```cpp
#include <kvmlib/memory.hpp>

#include <array>
#include <cstdint>
#include <unistd.h>

int main() {
    const auto process = kvmlib::ProcessMemory::open(getpid());
    if (!process) {
        return 1;
    }
    const std::array<char, 6> text{ 'h', 'e', 'l', 'l', 'o', '\0' };
    const auto address = reinterpret_cast<std::uintptr_t>(text.data());
    const auto value = process->read_object<std::array<char, 6>>(address);
    const auto string = process->read_string(address, text.size());
    const auto mappings = process->regions();
    return !value || !string || *string != "hello" || !mappings;
}
```

Reads return byte counts and may be short. Object reads require every byte. String reads stop at NUL, the size limit, or an unreadable boundary. Mapping names include labels such as `[heap]`, `[stack]`, and `[vdso]`.

## CR3 trace

```cpp
#include <kvmlib/cr3_trace.hpp>

int main() {
    auto trace = kvmlib::Cr3Trace::open();
    if (!trace || !trace->start()) {
        return 1;
    }
    const auto events = trace->poll();
    if (!events || !trace->stop()) {
        return 1;
    }
    for (;;) {
        const auto tail = trace->poll();
        if (!tail) {
            return 1;
        }
        if (tail->empty()) {
            break;
        }
    }
}
```

Opening takes an advisory exclusive lock. Another cooperating owner receives `Error::busy`. Clients that bypass the lock can still change the driver's global state.

`start()` flushes and arms the tracer. `stop()` preserves enabled state on failure and allows buffered events to be drained afterward. Destruction attempts to stop and closes the descriptor. Exact capture cutoffs depend on driver synchronization.

## Input

```cpp
#include <kvmlib/input.hpp>
#include <linux/input-event-codes.h>

int main() {
    auto input = kvmlib::EvdevInput::open("/dev/input/by-id/baykus-vmouse-event");
    if (!input || !input->move_relative(8, -4)) {
        return 1;
    }
    if (!input->click_mouse_button(BTN_LEFT)) {
        return 1;
    }
    const auto events = input->poll();
    return !events;
}
```

`open_mouse()` and `open_keyboard()` scan `/dev/input/by-id`, preferring Baykus endpoints. Use `open(path)` for an explicit device. Discovery reports permission and I/O failures.

Input actions batch their events and SYN_REPORT records. A partial submission returns `Error::partial_write`; do not replay the whole action without handling events already sent. Serialize access to each input or trace object, including moves and destruction.

`poll(std::span<InputEvent>)` and `poll(std::span<Cr3Event>)` fill caller-owned buffers without allocating results. They return at most 4,096 events per call; repeat until zero to drain the queue. A later read failure can return the valid prefix already collected. Vector overloads return at most 128 events.

`native_handle()` provides a borrowed descriptor for `poll` or `epoll`. Do not close it or use it after the owning object releases it.

Operations return `std::expected` with `kvmlib::Error`. Allocation failures may throw.
