#pragma once

#include "driver_sight.hpp"
#include "vuln_patterns.hpp"
#include <vector>

namespace ds {

class MemoryVerifier {
public:
    std::vector<Vulnerability> verify_vulnerabilities(
        HANDLE device,
        const std::wstring& device_path,
        const std::wstring& driver_name,
        const std::vector<IoctlResult>& ioctl_results);

private:
    // Physical memory access (MmMapIoSpace patterns)
    int test_physical_memory(HANDLE device, DWORD ioctl_code);

    // Virtual memory access (MmCopyVirtualMemory patterns)
    int test_virtual_memory(HANDLE device, DWORD ioctl_code);

    // Generic read primitives
    int test_arbitrary_read(HANDLE device, DWORD ioctl_code);

    // Generic write primitives
    int test_arbitrary_write(HANDLE device, DWORD ioctl_code);

    // MSR access (RDMSR/WRMSR)
    bool test_msr_access(HANDLE device, DWORD ioctl_code);

    // Port I/O (IN/OUT)
    bool test_port_io(HANDLE device, DWORD ioctl_code);

    // PCI configuration space
    bool test_pci_config(HANDLE device, DWORD ioctl_code);

    // CR3/page table access
    bool test_cr3_access(HANDLE device, DWORD ioctl_code);

    // Process/module enumeration
    bool test_process_query(HANDLE device, DWORD ioctl_code);

    // METHOD_NEITHER check
    bool test_method_neither(HANDLE device, DWORD ioctl_code);

    // Privilege verification
    bool test_privilege_check(HANDLE device, DWORD ioctl_code);
};

} // namespace ds
