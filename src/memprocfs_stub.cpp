#include "kvmlib/memprocfs.hpp"

#include <utility>

namespace kvmlib {

MemProcFs::MemProcFs(std::shared_ptr<MemProcFsSession> session) noexcept
    : session_(std::move(session)) {
}

MemProcFs::~MemProcFs() = default;
MemProcFs::MemProcFs(MemProcFs&& other) noexcept = default;
MemProcFs& MemProcFs::operator=(MemProcFs&& other) noexcept = default;

bool MemProcFs::available() noexcept {
    return false;
}

std::expected<MemProcFs, Error> MemProcFs::open(const MemProcFsOptions&) {
    return std::unexpected(Error::unsupported);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(std::string_view, const RefreshMode) {
    return std::unexpected(Error::unsupported);
}

std::expected<MemProcFs, Error> MemProcFs::open_qemu(std::string_view, const std::filesystem::path&, const RefreshMode) {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::refresh() const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::refresh_tlb_partial() const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ProcessInfo>, Error> MemProcFs::processes() const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::uint32_t, Error> MemProcFs::process_id(std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::force_process_dtb(std::uint32_t, std::uint64_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<ProcessInfo, Error> MemProcFs::process_info(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ModuleInfo>, Error> MemProcFs::modules(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<ExportInfo>, Error> MemProcFs::exports(std::uint32_t, std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<HeapInfo>, Error> MemProcFs::heaps(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<HeapAllocation>, Error> MemProcFs::heap_allocations(std::uint32_t, std::uint64_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::vector<MemoryRange>, Error> MemProcFs::memory_ranges(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::uint64_t, Error> MemProcFs::module_base(std::uint32_t, std::string_view) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error> MemProcFs::read(std::uint32_t, std::uint64_t, std::span<std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error> MemProcFs::write(std::uint32_t, std::uint64_t, std::span<const std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<std::size_t, Error> MemProcFs::read_physical(std::uint64_t, std::span<std::byte>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::scatter_read(std::uint32_t, std::span<MemoryTransfer>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::scatter_write(std::uint32_t, std::span<MemoryTransfer>) const {
    return std::unexpected(Error::unsupported);
}

std::expected<MemProcFsReadBatch, Error> MemProcFs::read_batch(std::uint32_t) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::dump_process(std::uint32_t, std::uint64_t, std::uint64_t, const std::filesystem::path&) const {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFs::dump_physical(std::uint64_t, std::uint64_t, const std::filesystem::path&) const {
    return std::unexpected(Error::unsupported);
}

MemProcFsReadBatch::MemProcFsReadBatch(std::shared_ptr<MemProcFsSession> session, const std::uint32_t process_id) noexcept
    : session_(std::move(session)), process_id_(process_id) {
}

MemProcFsReadBatch::~MemProcFsReadBatch() = default;
MemProcFsReadBatch::MemProcFsReadBatch(MemProcFsReadBatch&& other) noexcept = default;
MemProcFsReadBatch& MemProcFsReadBatch::operator=(MemProcFsReadBatch&& other) noexcept = default;

bool MemProcFsReadBatch::valid() const noexcept {
    return false;
}

std::expected<void, Error> MemProcFsReadBatch::execute(std::span<MemoryTransfer>) {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFsReadBatch::clear() {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFsReadBatch::rebind(std::uint32_t) {
    return std::unexpected(Error::unsupported);
}

std::expected<void, Error> MemProcFsReadBatch::rebind(const MemProcFs&, std::uint32_t) {
    return std::unexpected(Error::unsupported);
}

}
