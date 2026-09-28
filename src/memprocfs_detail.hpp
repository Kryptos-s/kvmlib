#pragma once

#include "kvmlib/memprocfs.hpp"
#include "detail.hpp"

extern "C" {
#include "vmmdll.h"
}

#include <cstddef>
#include <cstdint>
#include <memory>

namespace kvmlib {

struct MemProcFsSession {
    VMM_HANDLE handle{};
    DWORD read_flags{};

    ~MemProcFsSession() {
        if (handle) VMMDLL_Close(handle);
    }
};

namespace detail {

static_assert(sizeof(DWORD) == sizeof(std::uint32_t));

inline constexpr DWORD physical_memory = static_cast<DWORD>(-1);

struct MemFreeDeleter {
    void operator()(void* pointer) const noexcept {
        if (pointer) VMMDLL_MemFree(pointer);
    }
};

struct ScatterDeleter {
    void operator()(void* pointer) const noexcept {
        if (pointer) VMMDLL_Scatter_CloseHandle(static_cast<VMMDLL_SCATTER_HANDLE>(pointer));
    }
};

template <typename T>
using MemFreePtr = std::unique_ptr<T, MemFreeDeleter>;

using ScatterPtr = std::unique_ptr<void, ScatterDeleter>;

inline bool session_ready(const std::shared_ptr<MemProcFsSession>& session) noexcept {
    return session && session->handle;
}

inline bool valid_transfer(const MemoryTransfer& transfer) noexcept {
    return kvmlib::detail::valid_range(transfer.address, transfer.bytes.size());
}

}
}
