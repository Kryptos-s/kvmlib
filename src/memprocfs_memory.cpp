#include "memprocfs_detail.hpp"

#include "detail.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <limits>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <unistd.h>
#include <utility>
#include <vector>

namespace {

using kvmlib::Error;

bool valid_range(const std::uint64_t address, const std::uint64_t size) noexcept {
    return kvmlib::detail::valid_range(address, size);
}

std::uint64_t pages_for(const std::uint64_t address, const std::size_t size) noexcept {
    if (size == 0) return 0;
    const auto first_page_bytes = std::min(
        size, std::size_t{0x1000} - static_cast<std::size_t>(address & 0xFFF));
    const auto remaining = size - first_page_bytes;
    return 1 + remaining / 0x1000 + static_cast<std::uint64_t>(remaining % 0x1000 != 0);
}

class TemporaryFile {
public:
    TemporaryFile(const int descriptor, std::vector<char> path) noexcept
        : descriptor_(descriptor), path_(std::move(path)) {}
    ~TemporaryFile() {
        if (descriptor_ >= 0) static_cast<void>(::close(descriptor_));
        if (!path_.empty()) static_cast<void>(::unlink(path_.data()));
    }
    TemporaryFile(const TemporaryFile&) = delete;
    TemporaryFile& operator=(const TemporaryFile&) = delete;

    static std::expected<TemporaryFile, Error> create(const std::filesystem::path& destination) {
        const auto parent = destination.parent_path().empty()
            ? std::filesystem::path(".") : destination.parent_path();
        std::string name = (parent / ".kvmlib-XXXXXX").string();
        std::vector<char> buffer(name.begin(), name.end());
        buffer.push_back('\0');
        const int descriptor = ::mkstemp(buffer.data());
        if (descriptor < 0) return std::unexpected(Error::io_error);
        if (::fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0) {
            const int saved_errno = errno;
            static_cast<void>(::close(descriptor));
            static_cast<void>(::unlink(buffer.data()));
            errno = saved_errno;
            return std::unexpected(kvmlib::detail::from_errno());
        }
        return std::expected<TemporaryFile, Error>(
            std::in_place, descriptor, std::move(buffer));
    }

    std::expected<void, Error> write(const std::span<const std::byte> input) {
        const auto* cursor = input.data();
        std::size_t remaining = input.size();
        while (remaining != 0) {
            const auto count = ::write(descriptor_, cursor, remaining);
            if (count < 0) {
                if (errno == EINTR) continue;
                return std::unexpected(kvmlib::detail::from_errno());
            }
            if (count == 0) return std::unexpected(Error::io_error);
            cursor += count;
            remaining -= static_cast<std::size_t>(count);
        }
        return {};
    }

    std::expected<void, Error> commit(const std::filesystem::path& destination) {
        const int descriptor = std::exchange(descriptor_, -1);
        if (descriptor >= 0 && ::close(descriptor) != 0) {
            return std::unexpected(kvmlib::detail::from_errno());
        }
        if (::rename(path_.data(), destination.c_str()) != 0) {
            return std::unexpected(kvmlib::detail::from_errno());
        }
        path_.clear();
        return {};
    }

private:
    int descriptor_{-1};
    std::vector<char> path_;
};

std::expected<void, Error> validate_output(const std::filesystem::path& output) {
    if (output.empty() || output.filename().empty()
        || output.native().find('\0') != std::string::npos) {
        return std::unexpected(Error::invalid_argument);
    }
    std::error_code error;
    const auto status = std::filesystem::symlink_status(output, error);
    if (error && error != std::errc::no_such_file_or_directory) {
        return std::unexpected(kvmlib::detail::from_error_code(error));
    }
    if (!error && (std::filesystem::is_symlink(status)
        || (std::filesystem::exists(status) && !std::filesystem::is_regular_file(status)))) {
        return std::unexpected(Error::invalid_argument);
    }

    error.clear();
    const auto parent = output.parent_path().empty()
        ? std::filesystem::path(".") : output.parent_path();
    const auto parent_status = std::filesystem::status(parent, error);
    if (error) return std::unexpected(kvmlib::detail::from_error_code(error));
    if (!std::filesystem::is_directory(parent_status)) return std::unexpected(Error::io_error);
    return {};
}

std::expected<void, Error> dump(
    const kvmlib::MemProcFs& backend,
    const std::uint32_t process_id,
    const std::uint64_t address,
    const std::uint64_t size,
    const std::filesystem::path& output,
    const bool physical) {
    if ((!physical && process_id == 0) || !valid_range(address, size)) {
        return std::unexpected(Error::invalid_argument);
    }
    if (const auto valid = validate_output(output); !valid) return std::unexpected(valid.error());
    auto file = TemporaryFile::create(output);
    if (!file) return std::unexpected(file.error());

    std::vector<std::byte> buffer(static_cast<std::size_t>(
        std::min<std::uint64_t>(size, 1 << 20)));
    for (std::uint64_t offset{}; offset < size;) {
        const auto count = static_cast<std::size_t>(
            std::min<std::uint64_t>(buffer.size(), size - offset));
        const auto bytes = std::span<std::byte>(buffer).first(count);
        const auto read = physical
            ? backend.read_physical(address + offset, bytes)
            : backend.read(process_id, address + offset, bytes);
        if (!read) return std::unexpected(read.error());
        if (*read != count) return std::unexpected(Error::io_error);
        if (const auto written = file->write(bytes); !written) {
            return std::unexpected(written.error());
        }
        offset += count;
    }
    return file->commit(output);
}

}

namespace kvmlib {

std::expected<std::size_t, Error> MemProcFs::read(
    const std::uint32_t process_id,
    const std::uint64_t address,
    const std::span<std::byte> bytes) const {
    if (!detail::session_ready(session_) || process_id == 0
        || bytes.size() > std::numeric_limits<DWORD>::max()
        || !valid_range(address, bytes.size())) {
        return std::unexpected(Error::invalid_argument);
    }
    if (bytes.empty()) return std::size_t{};
    DWORD completed{};
    const bool success = VMMDLL_MemReadEx(session_->handle, process_id, address,
        reinterpret_cast<PBYTE>(bytes.data()), static_cast<DWORD>(bytes.size()),
        &completed, session_->read_flags);
    if (!success && completed == 0) return std::unexpected(Error::io_error);
    return static_cast<std::size_t>(completed);
}

std::expected<std::size_t, Error> MemProcFs::write(
    const std::uint32_t process_id,
    const std::uint64_t address,
    const std::span<const std::byte> bytes) const {
    if (!detail::session_ready(session_) || process_id == 0
        || bytes.size() > std::numeric_limits<DWORD>::max()
        || !valid_range(address, bytes.size())) {
        return std::unexpected(Error::invalid_argument);
    }
    if (bytes.empty()) return std::size_t{};
    auto* source = const_cast<std::byte*>(bytes.data());
    if (!VMMDLL_MemWrite(session_->handle, process_id, address,
        reinterpret_cast<PBYTE>(source), static_cast<DWORD>(bytes.size()))) {
        return std::unexpected(Error::io_error);
    }
    return bytes.size();
}

std::expected<std::size_t, Error> MemProcFs::read_physical(
    const std::uint64_t address,
    const std::span<std::byte> bytes) const {
    if (!detail::session_ready(session_)
        || bytes.size() > std::numeric_limits<DWORD>::max()
        || !valid_range(address, bytes.size())) {
        return std::unexpected(Error::invalid_argument);
    }
    if (bytes.empty()) return std::size_t{};
    DWORD completed{};
    const bool success = VMMDLL_MemReadEx(session_->handle, detail::physical_memory,
        address, reinterpret_cast<PBYTE>(bytes.data()), static_cast<DWORD>(bytes.size()),
        &completed, session_->read_flags);
    if (!success && completed == 0) return std::unexpected(Error::io_error);
    return static_cast<std::size_t>(completed);
}

std::expected<void, Error> MemProcFs::scatter_read(
    const std::uint32_t process_id,
    const std::span<MemoryTransfer> transfers) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    if (transfers.empty()) return {};

    bool has_data{};
    std::vector<DWORD> completed(transfers.size());
    for (const auto& transfer : transfers) {
        if (!detail::valid_transfer(transfer)
            || transfer.bytes.size() > std::numeric_limits<DWORD>::max()) {
            return std::unexpected(Error::invalid_argument);
        }
        has_data = has_data || !transfer.bytes.empty();
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    if (!has_data) return {};

    detail::ScatterPtr scatter(
        VMMDLL_Scatter_Initialize(session_->handle, process_id, session_->read_flags));
    if (!scatter) return std::unexpected(Error::io_error);
    const auto handle = static_cast<VMMDLL_SCATTER_HANDLE>(scatter.get());

    bool prepared = true;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        const auto& transfer = transfers[index];
        if (transfer.bytes.empty()) continue;
        const bool current = VMMDLL_Scatter_PrepareEx(handle, transfer.address,
            static_cast<DWORD>(transfer.bytes.size()),
            reinterpret_cast<PBYTE>(transfer.bytes.data()), &completed[index]);
        prepared = current && prepared;
    }
    const bool executed = prepared && VMMDLL_Scatter_ExecuteRead(handle);
    bool complete = executed;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        transfers[index].bytes_read = completed[index];
        complete = complete && completed[index] == transfers[index].bytes.size();
    }
    return complete ? std::expected<void, Error>{}
                    : std::unexpected(Error::io_error);
}

std::expected<void, Error> MemProcFs::scatter_write(
    const std::uint32_t process_id,
    const std::span<MemoryTransfer> transfers) const {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }

    std::uint64_t count{};
    for (const auto& transfer : transfers) {
        if (!detail::valid_transfer(transfer)) return std::unexpected(Error::invalid_argument);
        const auto pages = pages_for(transfer.address, transfer.bytes.size());
        if (pages > std::numeric_limits<DWORD>::max() - count) {
            return std::unexpected(Error::invalid_argument);
        }
        count += pages;
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    if (count == 0) return {};

    std::vector<MEM_SCATTER> descriptors(static_cast<std::size_t>(count));
    std::vector<PMEM_SCATTER> descriptor_ptrs(static_cast<std::size_t>(count));
    std::vector<std::size_t> owners(static_cast<std::size_t>(count));
    std::size_t descriptor_index{};
    for (std::size_t owner{}; owner < transfers.size(); ++owner) {
        const auto& transfer = transfers[owner];
        for (std::size_t offset{}; offset < transfer.bytes.size();) {
            const auto address = transfer.address + offset;
            const auto length = std::min(
                std::size_t{0x1000} - static_cast<std::size_t>(address & 0xFFF),
                transfer.bytes.size() - offset);
            auto& descriptor = descriptors[descriptor_index];
            descriptor.version = MEM_SCATTER_VERSION;
            descriptor.f = false;
            descriptor.qwA = address;
            descriptor.pb = reinterpret_cast<PBYTE>(transfer.bytes.data() + offset);
            descriptor.cb = static_cast<DWORD>(length);
            descriptor.iStack = 0;
            descriptor_ptrs[descriptor_index] = &descriptor;
            owners[descriptor_index] = owner;
            ++descriptor_index;
            offset += length;
        }
    }

    const auto reported = VMMDLL_MemWriteScatter(session_->handle, process_id,
        descriptor_ptrs.data(), static_cast<DWORD>(descriptor_ptrs.size()));
    std::size_t successes{};
    for (std::size_t index{}; index < descriptors.size(); ++index) {
        if (!descriptors[index].f) continue;
        ++successes;
        transfers[owners[index]].bytes_read += descriptors[index].cb;
    }
    bool complete = reported == successes;
    for (const auto& transfer : transfers) {
        complete = complete && transfer.bytes_read == transfer.bytes.size();
    }
    if (complete) return {};
    return std::unexpected(successes ? Error::partial_write : Error::io_error);
}

std::expected<void, Error> MemProcFs::dump_process(
    const std::uint32_t process_id,
    const std::uint64_t address,
    const std::uint64_t size,
    const std::filesystem::path& output) const {
    if (!detail::session_ready(session_)) return std::unexpected(Error::invalid_argument);
    return dump(*this, process_id, address, size, output, false);
}

std::expected<void, Error> MemProcFs::dump_physical(
    const std::uint64_t address,
    const std::uint64_t size,
    const std::filesystem::path& output) const {
    if (!detail::session_ready(session_)) return std::unexpected(Error::invalid_argument);
    return dump(*this, 0, address, size, output, true);
}

MemProcFsReadBatch::MemProcFsReadBatch(
    std::shared_ptr<MemProcFsSession> session,
    const std::uint32_t process_id) noexcept
    : session_(std::move(session)), process_id_(process_id) {}

MemProcFsReadBatch::~MemProcFsReadBatch() {
    detail::ScatterPtr scatter(scatter_);
    scatter_ = nullptr;
}

MemProcFsReadBatch::MemProcFsReadBatch(MemProcFsReadBatch&& other) noexcept
    : session_(std::move(other.session_)),
      process_id_(std::exchange(other.process_id_, 0)),
      scatter_(std::exchange(other.scatter_, nullptr)),
      counts_(std::move(other.counts_)),
      prepared_transfers_(std::move(other.prepared_transfers_)),
      prepared_(std::exchange(other.prepared_, false)) {}

MemProcFsReadBatch& MemProcFsReadBatch::operator=(MemProcFsReadBatch&& other) noexcept {
    if (this == &other) return *this;
    {
        detail::ScatterPtr old_scatter(scatter_);
        scatter_ = nullptr;
    }
    scatter_ = std::exchange(other.scatter_, nullptr);
    session_ = std::move(other.session_);
    process_id_ = std::exchange(other.process_id_, 0);
    counts_ = std::move(other.counts_);
    prepared_transfers_ = std::move(other.prepared_transfers_);
    prepared_ = std::exchange(other.prepared_, false);
    return *this;
}

bool MemProcFsReadBatch::valid() const noexcept {
    return detail::session_ready(session_) && process_id_ != 0;
}

std::expected<void, Error> MemProcFsReadBatch::clear() {
    if (!valid()) return std::unexpected(Error::invalid_argument);
    if (scatter_ && !VMMDLL_Scatter_Clear(
        static_cast<VMMDLL_SCATTER_HANDLE>(scatter_), process_id_, session_->read_flags)) {
        {
            detail::ScatterPtr failed(std::exchange(scatter_, nullptr));
        }
        prepared_ = false;
        prepared_transfers_.clear();
        counts_.clear();
        return std::unexpected(Error::io_error);
    }
    prepared_ = false;
    prepared_transfers_.clear();
    counts_.clear();
    return {};
}

std::expected<void, Error> MemProcFsReadBatch::execute(
    const std::span<MemoryTransfer> transfers) {
    if (!valid()) return std::unexpected(Error::invalid_argument);
    for (const auto& transfer : transfers) {
        if (!detail::valid_transfer(transfer)
            || transfer.bytes.size() > std::numeric_limits<DWORD>::max()) {
            return std::unexpected(Error::invalid_argument);
        }
    }
    for (auto& transfer : transfers) transfer.bytes_read = 0;
    const bool has_data = std::ranges::any_of(transfers, [](const MemoryTransfer& transfer) {
        return !transfer.bytes.empty();
    });
    if (!has_data) return clear();

    bool same = prepared_ && prepared_transfers_.size() == transfers.size();
    if (same) {
        for (std::size_t index{}; index < transfers.size(); ++index) {
            const auto& cached = prepared_transfers_[index];
            const auto& request = transfers[index];
            if (cached.address != request.address || cached.data != request.bytes.data()
                || cached.size != request.bytes.size()) {
                same = false;
                break;
            }
        }
    }

    const auto close_and_reset = [&] {
        {
            detail::ScatterPtr old(std::exchange(scatter_, nullptr));
        }
        prepared_ = false;
        prepared_transfers_.clear();
        counts_.clear();
    };

    if (!same) {
        if (scatter_ && !VMMDLL_Scatter_Clear(
            static_cast<VMMDLL_SCATTER_HANDLE>(scatter_), process_id_, session_->read_flags)) {
            close_and_reset();
            return std::unexpected(Error::io_error);
        }
        prepared_ = false;
        prepared_transfers_.clear();
        if (!scatter_) {
            scatter_ = VMMDLL_Scatter_Initialize(
                session_->handle, process_id_, session_->read_flags);
            if (!scatter_) return std::unexpected(Error::io_error);
        }

        counts_.assign(transfers.size(), 0);
        prepared_transfers_.resize(transfers.size());
        const auto handle = static_cast<VMMDLL_SCATTER_HANDLE>(scatter_);
        bool all_prepared = true;
        for (std::size_t index{}; index < transfers.size(); ++index) {
            const auto& transfer = transfers[index];
            prepared_transfers_[index] = {
                transfer.address, transfer.bytes.data(), transfer.bytes.size()
            };
            if (transfer.bytes.empty()) continue;
            const bool current = VMMDLL_Scatter_PrepareEx(handle, transfer.address,
                static_cast<DWORD>(transfer.bytes.size()),
                reinterpret_cast<PBYTE>(transfer.bytes.data()),
                reinterpret_cast<PDWORD>(&counts_[index]));
            all_prepared = current && all_prepared;
        }
        if (!all_prepared) {
            close_and_reset();
            return std::unexpected(Error::io_error);
        }
        prepared_ = true;
    } else {
        std::ranges::fill(counts_, DWORD{});
    }

    const bool executed = VMMDLL_Scatter_ExecuteRead(
        static_cast<VMMDLL_SCATTER_HANDLE>(scatter_));
    bool complete = executed;
    for (std::size_t index{}; index < transfers.size(); ++index) {
        transfers[index].bytes_read = counts_[index];
        complete = complete && counts_[index] == transfers[index].bytes.size();
    }
    return complete ? std::expected<void, Error>{}
                    : std::unexpected(Error::io_error);
}

std::expected<void, Error> MemProcFsReadBatch::rebind(const std::uint32_t process_id) {
    if (!detail::session_ready(session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    {
        detail::ScatterPtr old(std::exchange(scatter_, nullptr));
    }
    process_id_ = process_id;
    counts_.clear();
    prepared_transfers_.clear();
    prepared_ = false;
    return {};
}

std::expected<void, Error> MemProcFsReadBatch::rebind(
    const MemProcFs& backend,
    const std::uint32_t process_id) {
    if (!detail::session_ready(backend.session_) || process_id == 0) {
        return std::unexpected(Error::invalid_argument);
    }
    {
        detail::ScatterPtr old(scatter_);
        scatter_ = nullptr;
    }
    session_ = backend.session_;
    process_id_ = process_id;
    counts_.clear();
    prepared_transfers_.clear();
    prepared_ = false;
    return {};
}

}
