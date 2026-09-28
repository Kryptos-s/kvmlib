# KVMLib

C++23 library for Linux process memory, VM memory through MemProcFS, evdev input, and KVM CR3 tracing. It also provides system memory stats, CPU/SMT topology, and `/dev/kvm` availability checks.

## Build

Requires Linux, CMake 3.25+, and a C++23 compiler with `std::expected` support.

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

For a library-only build, pass `-DKVMLIB_BUILD_TESTS=OFF -DKVMLIB_BUILD_EXAMPLES=OFF`. Both are off by default when included with `add_subdirectory`.

Tests use local process reads and mocked input, trace, and MemProcFS calls.

## Add it to a project

```cmake
add_subdirectory(path/to/KVMLib)
target_link_libraries(my_app PRIVATE kvmlib::kvmlib)
```

Or install it:

```sh
cmake --install build --prefix /path/to/kvmlib-install
```

Then set `CMAKE_PREFIX_PATH` to that directory and use:

```cmake
find_package(KVMLib 0.1 CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE kvmlib::kvmlib)
```

## Read process memory

`ProcessMemory` reads `/proc/<pid>/mem` using the host's ptrace permissions.

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

`read()` returns the number of bytes read, which can be less than requested. `read_object<T>()` requires the full object. `read_string()` stops at NUL, the size limit, or an unreadable boundary.

Host information is available through `memory_info()`, `cpu_topology()`, and `kvm_status()`. Topology covers online CPUs. `smt_enabled()` checks CPU siblings; `kvm_status()` checks the device and CPU flags without starting a VM.

## MemProcFS

Enable this backend for guest process lookup, modules, exports, heaps, virtual and physical reads, virtual writes, scatter transfers, and memory dumps.

```sh
cmake -S . -B build-memprocfs -DCMAKE_BUILD_TYPE=Release \
  -DKVMLIB_ENABLE_MEMPROCFS=ON \
  -DMEMPROCFS_ROOT=/path/to/MemProcFS \
  -DMEMPROCFS_LIBRARY_DIR=/path/to/vmm-runtime
cmake --build build-memprocfs
```

`MEMPROCFS_ROOT` must contain `includes/vmmdll.h`. The runtime directory must contain `vmm.so` and its dependencies. Applications using an installed KVMLib package also need that runtime; set `MEMPROCFS_LIBRARY_DIR` or provide the `KVMLib::MemProcFS` target.

MemProcFS calls require root. `MemProcFs::available()` reports whether the backend was compiled in. A build without it returns `Error::unsupported` from backend operations.

- `open_qemu(name)` uses `/tmp/qmp-<name>.sock`. Use `open_qemu(name, qmp_path)` for another socket. Guest names must match exactly and be unique; names and socket paths cannot contain commas or NULs.
- `process_id(name)` matches the full process name, ignoring case. Multiple matches return an error.
- Reads use `MemoryCachePolicy::fresh` by default. Page tables can still be cached. Use `refresh()` for a full refresh or `refresh_tlb_partial()` for a partial translation-cache refresh.
- Dumps replace the output file once reading, writing, and closing succeed. Failure leaves an existing output file intact. Symlinks and device files are rejected; writes are not synced for power-loss recovery.

For repeated reads, keep a batch and reuse its buffers:

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

Keep destination buffers alive until `clear()`, a successful `rebind()`, or batch destruction. A batch keeps its MemProcFS session alive and reuses preparation when the addresses, buffers, and sizes match.

`MemoryTransfer::bytes_read` counts completed bytes. Scatter writes use the same field for total bytes written, which may be scattered across the request. `Error::partial_write` means some data was already written; retrying the whole batch can repeat those writes. Scatter transfers do not provide a consistent memory snapshot.

## Input and CR3 tracing

Both APIs require root.

- `EvdevInput::open(path)` opens a specific evdev device. `open_mouse()` and `open_keyboard()` search `/dev/input/by-id` and prefer Baykus devices. Use `poll()` to read events, `send_key()` or `click_mouse_button()` for buttons, and `move_relative()` for mouse movement.
- `Cr3Trace` requires [CatCaller's CR3-Tracer kernel patch and driver](https://github.com/CatCaller/CR3-Tracer) at `/dev/kvm_cr3trace`. Call `start()` to flush and arm it, `poll()` to read events, then `stop()`. Buffered events can be drained after stopping. A failed stop can be retried; destruction also attempts to stop the trace.

The tracer takes an advisory exclusive lock and returns `Error::busy` if another cooperating client owns it. Other clients can bypass that lock and change the driver's state.

The span overloads of `poll()` fill caller-owned storage, up to 4,096 events per call. Vector overloads return up to 128. Poll again until zero to drain the queue. A read error after some events have arrived can return that valid prefix.

Input writes can also return `Error::partial_write`; some events may already have been sent. Use each input, trace, or batch object from one caller at a time. `native_handle()` is borrowed and must not be closed by the caller.

Fallible operations return `std::expected` with `kvmlib::Error`. Allocation failures can throw.

## Credits

Original base: [CatCaller's KVMLib](https://github.com/CatCaller/KVMLib).

CR3 tracing dependency: [CatCaller's CR3-Tracer](https://github.com/CatCaller/CR3-Tracer).

The optional memory backend uses [MemProcFS](https://github.com/ufrisk/MemProcFS) by Ulf Frisk.
