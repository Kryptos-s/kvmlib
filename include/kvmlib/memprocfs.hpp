#pragma once

#include "kvmlib/error.hpp"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace kvmlib {

enum class RefreshMode {
    automatic,
    manual,
};

enum class MemoryCachePolicy {
    fresh,
    cached,
};

struct MemProcFsOptions {
    std::string device;
    bool disable_python{ true };
    bool wait_initialize{};
    RefreshMode refresh_mode{ RefreshMode::automatic };
    MemoryCachePolicy cache_policy{ MemoryCachePolicy::fresh };
};

struct MemoryTransfer {
    std::uint64_t address{};
    std::span<std::byte> bytes;
    std::size_t bytes_read{};
};

struct ProcessInfo {
    std::uint32_t process_id{};
    std::uint64_t dtb{};
    std::uint64_t user_dtb{};
    std::uint64_t eprocess{};
    std::string name;
};

struct ModuleInfo {
    std::uint64_t base{};
    std::uint64_t entry{};
    std::uint32_t image_size{};
    std::uint32_t raw_size{};
    bool wow64{};
    std::string name;
    std::string path;
};

struct ExportInfo {
    std::uint64_t address{};
    std::uint32_t ordinal{};
    std::string name;
    std::string forwarder;
};

struct HeapInfo {
    std::uint64_t address{};
    std::uint32_t type{};
    std::uint32_t index{};
    std::uint32_t number{};
    bool wow64{};
};

struct HeapAllocation {
    std::uint64_t address{};
    std::uint32_t size{};
    std::uint32_t type{};
};

struct MemoryRange {
    std::uint64_t start{};
    std::uint64_t end{};
    std::uint32_t protection{};
    std::uint32_t heap_number{};
    std::uint32_t committed_pages{};
    bool committed{};
    bool private_memory{};
    bool heap{};
    bool stack{};
    std::string name;
};

struct MemProcFsSession;

class MemProcFsReadBatch {
public:
    MemProcFsReadBatch() = default;
    ~MemProcFsReadBatch();
    MemProcFsReadBatch(const MemProcFsReadBatch&) = delete;
    MemProcFsReadBatch& operator=(const MemProcFsReadBatch&) = delete;
    MemProcFsReadBatch(MemProcFsReadBatch&& other) noexcept;
    MemProcFsReadBatch& operator=(MemProcFsReadBatch&& other) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::expected<void, Error> execute(std::span<MemoryTransfer> transfers);
    [[nodiscard]] std::expected<void, Error> clear();
    [[nodiscard]] std::expected<void, Error> rebind(std::uint32_t process_id);
    [[nodiscard]] std::expected<void, Error> rebind(const class MemProcFs& backend, std::uint32_t process_id);

private:
    friend class MemProcFs;
    MemProcFsReadBatch(std::shared_ptr<MemProcFsSession> session, std::uint32_t process_id) noexcept;

    struct PreparedTransfer {
        std::uint64_t address{};
        std::byte* data{};
        std::size_t size{};
    };

    std::shared_ptr<MemProcFsSession> session_;
    std::uint32_t process_id_{};
    void* scatter_{};
    std::vector<std::uint32_t> counts_;
    std::vector<PreparedTransfer> prepared_transfers_;
    bool prepared_{};
};

class MemProcFs {
public:
    using ReadBatch = MemProcFsReadBatch;

    MemProcFs() = default;
    ~MemProcFs();
    MemProcFs(const MemProcFs&) = delete;
    MemProcFs& operator=(const MemProcFs&) = delete;
    MemProcFs(MemProcFs&& other) noexcept;
    MemProcFs& operator=(MemProcFs&& other) noexcept;

    [[nodiscard]] static bool available() noexcept;
    [[nodiscard]] static std::expected<MemProcFs, Error> open(const MemProcFsOptions& options);
    [[nodiscard]] static std::expected<MemProcFs, Error> open_qemu(std::string_view guest_name, RefreshMode refresh_mode = RefreshMode::automatic);
    [[nodiscard]] static std::expected<MemProcFs, Error> open_qemu(std::string_view guest_name, const std::filesystem::path& qmp_path, RefreshMode refresh_mode = RefreshMode::automatic);
    [[nodiscard]] std::expected<void, Error> refresh() const;
    [[nodiscard]] std::expected<void, Error> refresh_tlb_partial() const;
    [[nodiscard]] std::expected<std::vector<ProcessInfo>, Error> processes() const;
    [[nodiscard]] std::expected<std::uint32_t, Error> process_id(std::string_view name) const;
    [[nodiscard]] std::expected<void, Error> force_process_dtb(std::uint32_t process_id, std::uint64_t dtb) const;
    [[nodiscard]] std::expected<ProcessInfo, Error> process_info(std::uint32_t process_id) const;
    [[nodiscard]] std::expected<std::vector<ModuleInfo>, Error> modules(std::uint32_t process_id) const;
    [[nodiscard]] std::expected<std::vector<ExportInfo>, Error> exports(std::uint32_t process_id, std::string_view module) const;
    [[nodiscard]] std::expected<std::vector<HeapInfo>, Error> heaps(std::uint32_t process_id) const;
    [[nodiscard]] std::expected<std::vector<HeapAllocation>, Error> heap_allocations(std::uint32_t process_id, std::uint64_t heap_number_or_address) const;
    [[nodiscard]] std::expected<std::vector<MemoryRange>, Error> memory_ranges(std::uint32_t process_id) const;
    [[nodiscard]] std::expected<std::uint64_t, Error> module_base(std::uint32_t process_id, std::string_view module) const;
    [[nodiscard]] std::expected<std::size_t, Error> read(std::uint32_t process_id, std::uint64_t address, std::span<std::byte> bytes) const;
    [[nodiscard]] std::expected<std::size_t, Error> write(std::uint32_t process_id, std::uint64_t address, std::span<const std::byte> bytes) const;
    [[nodiscard]] std::expected<std::size_t, Error> read_physical(std::uint64_t address, std::span<std::byte> bytes) const;
    [[nodiscard]] std::expected<void, Error> scatter_read(std::uint32_t process_id, std::span<MemoryTransfer> transfers) const;
    [[nodiscard]] std::expected<void, Error> scatter_write(std::uint32_t process_id, std::span<MemoryTransfer> transfers) const;
    [[nodiscard]] std::expected<MemProcFsReadBatch, Error> read_batch(std::uint32_t process_id) const;
    [[nodiscard]] std::expected<void, Error> dump_process(std::uint32_t process_id, std::uint64_t address, std::uint64_t size, const std::filesystem::path& output) const;
    [[nodiscard]] std::expected<void, Error> dump_physical(std::uint64_t address, std::uint64_t size, const std::filesystem::path& output) const;

private:
    friend class MemProcFsReadBatch;
    explicit MemProcFs(std::shared_ptr<MemProcFsSession> session) noexcept;
    std::shared_ptr<MemProcFsSession> session_;
};

}
