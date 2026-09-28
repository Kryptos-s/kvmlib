#pragma once

#include "kvmlib/error.hpp"

#include <cstdint>
#include <expected>
#include <vector>

namespace kvmlib {

struct CpuThread {
    std::uint32_t logical_id{};
    std::uint32_t package_id{};
    std::uint32_t core_id{};
    std::vector<std::uint32_t> siblings;
};

struct CpuTopology {
    std::vector<CpuThread> threads;

    [[nodiscard]] std::uint32_t physical_core_count() const;
    [[nodiscard]] bool smt_enabled() const;
    [[nodiscard]] const CpuThread* find(const std::uint32_t logical_id) const;
};

struct KvmStatus {
    bool device_present{};
    bool device_accessible{};
    bool virtualization_supported{};
};

[[nodiscard]] std::expected<CpuTopology, Error> cpu_topology();
[[nodiscard]] std::expected<KvmStatus, Error> kvm_status();

}
