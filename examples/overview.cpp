#include <kvmlib/kvmlib.hpp>

#include <iostream>
#include <unistd.h>

int main() {
    const auto memory = kvmlib::memory_info();
    const auto topology = kvmlib::cpu_topology();
    const auto kvm = kvmlib::kvm_status();
    const auto self = kvmlib::ProcessMemory::open(getpid());

    if (!memory || !topology || !kvm || !self) {
        return 1;
    }

    std::cout << "Memory available: " << memory->available_bytes << " bytes\n";
    std::cout << "Logical CPUs: " << topology->threads.size() << "\n";
    std::cout << "Physical cores: " << topology->physical_core_count() << "\n";
    std::cout << "SMT enabled: " << topology->smt_enabled() << "\n";
    std::cout << "KVM available: " << kvm->device_accessible << "\n";
    std::cout << "Opened process: " << self->process_id() << "\n";
}
