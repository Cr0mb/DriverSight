#include "memory_verifier.hpp"
#include "vuln_patterns.hpp"
#include <format>
#include <vector>

namespace {

// SEH wrapper for safe IOCTL calls
BOOL safe_ioctl(HANDLE device, DWORD code, void* in_buf, DWORD in_size,
                void* out_buf, DWORD out_size, DWORD* bytes_returned) {
    __try {
        *bytes_returned = 0;
        return DeviceIoControl(device, code, in_buf, in_size,
                               out_buf, out_size, bytes_returned, nullptr);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

} // anonymous namespace

namespace ds {

std::vector<Vulnerability> MemoryVerifier::verify_vulnerabilities(
    HANDLE device,
    const std::wstring& device_path,
    const std::wstring& driver_name,
    const std::vector<IoctlResult>& ioctl_results) {

    std::vector<Vulnerability> vulns;

    for (const auto& result : ioctl_results) {
        if (!result.success) continue;

        DWORD ioctl = result.ioctl_code;

        // Test METHOD_NEITHER
        if ((ioctl & 0x3) == 3) {
            auto pattern = get_vuln_pattern(VulnCategory::MethodNeither);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::MethodNeither,
                pattern.description, pattern.severity});
        }

        // Test physical memory access patterns
        auto phys_result = test_physical_memory(device, ioctl);
        if (phys_result > 0) {
            auto pattern = get_vuln_pattern(VulnCategory::PhysicalMemory);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryRead,
                std::format("{} (pattern {})", pattern.description, phys_result), pattern.severity});
        }

        // Test virtual memory access patterns
        auto virt_result = test_virtual_memory(device, ioctl);
        if (virt_result > 0) {
            auto pattern = get_vuln_pattern(VulnCategory::VirtualMemory);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryRead,
                std::format("{} (pattern {})", pattern.description, virt_result), pattern.severity});
        }

        // Test arbitrary read patterns
        auto read_result = test_arbitrary_read(device, ioctl);
        if (read_result > 0) {
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryRead,
                std::format("Arbitrary kernel memory read capability (pattern {})", read_result), 9});
        }

        // Test arbitrary write patterns
        auto write_result = test_arbitrary_write(device, ioctl);
        if (write_result > 0) {
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryWrite,
                std::format("Arbitrary kernel memory write capability (pattern {})", write_result), 10});
        }

        // Test MSR access
        if (test_msr_access(device, ioctl)) {
            auto pattern = get_vuln_pattern(VulnCategory::MsrAccess);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryWrite,
                pattern.description, pattern.severity});
        }

        // Test port I/O
        if (test_port_io(device, ioctl)) {
            auto pattern = get_vuln_pattern(VulnCategory::PortIo);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryWrite,
                pattern.description, pattern.severity});
        }

        // Test PCI config access
        if (test_pci_config(device, ioctl)) {
            auto pattern = get_vuln_pattern(VulnCategory::PciConfig);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryWrite,
                pattern.description, pattern.severity});
        }

        // Test CR3/page table access
        if (test_cr3_access(device, ioctl)) {
            auto pattern = get_vuln_pattern(VulnCategory::Cr3PageTable);
            vulns.push_back({driver_name, device_path, ioctl, VulnType::ArbitraryRead,
                pattern.description, pattern.severity});
        }

        // Test process/module query
        if (test_process_query(device, ioctl)) {
            vulns.push_back({driver_name, device_path, ioctl, VulnType::PrivilegeCheck,
                "Process/module enumeration capability - may leak kernel addresses", 5});
        }
    }

    // Check privilege level
    if (!vulns.empty() && test_privilege_check(device, 0)) {
        vulns.push_back({driver_name, device_path, 0, VulnType::PrivilegeCheck,
            "Driver accessible without administrator privileges", 6});
    }

    return vulns;
}

int MemoryVerifier::test_physical_memory(HANDLE device, DWORD ioctl) {
    // Pattern 1: PhysMemRequest style (MmMapIoSpace)
    {
        PhysMemRequest req{};
        BYTE resp[256] = {0};
        req.physical_address = 0x1000;  // BIOS area - safe to read
        req.size = 16;
        req.cache_type = 1;  // MmCached

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes > 0) return 1;
        }
    }

    // Pattern 2: Simple physical address input, data output
    {
        UINT64 phys_addr = 0x1000;
        BYTE resp[64] = {0};

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &phys_addr, sizeof(phys_addr), resp, sizeof(resp), &bytes)) {
            if (bytes > 0) return 2;
        }
    }

    // Pattern 3: Returns mapped kernel address
    {
        PhysMemRequest req{};
        UINT64 resp = 0;
        req.physical_address = 0x1000;
        req.size = 0x1000;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &resp, sizeof(resp), &bytes)) {
            if (bytes >= sizeof(UINT64) && resp > 0xFFFF000000000000ULL) {
                return 3;  // Returned a kernel address
            }
        }
    }

    return 0;
}

int MemoryVerifier::test_virtual_memory(HANDLE device, DWORD ioctl) {
    // Pattern 1: VirtMemRequest style (MmCopyVirtualMemory)
    {
        VirtMemRequest req{};
        BYTE resp[256] = {0};
        req.process_id = GetCurrentProcessId();
        req.address = reinterpret_cast<UINT64>(&req);
        req.buffer = reinterpret_cast<UINT64>(resp);
        req.size = sizeof(req);
        req.write = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes > 0 && memcmp(resp, &req, sizeof(req)) == 0) {
                return 1;
            }
        }
    }

    // Pattern 2: Attach + read style
    {
        AttachReadRequest req{};
        BYTE resp[256] = {0};
        req.target_pid = GetCurrentProcessId();
        req.target_address = reinterpret_cast<UINT64>(&req);
        req.output_buffer = reinterpret_cast<UINT64>(resp);
        req.size = sizeof(req);

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes > 0) return 2;
        }
    }

    return 0;
}

int MemoryVerifier::test_arbitrary_read(HANDLE device, DWORD ioctl) {
    // Test multiple common read primitive patterns

    // Pattern 1: Address + Size structure
    {
        SimpleReadWrite req{};
        BYTE resp[256] = {0};
        req.address = reinterpret_cast<UINT64>(&req);
        req.size = sizeof(req);

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes > 0 && memcmp(resp, &req, sizeof(req)) == 0) {
                return 1;
            }
        }
    }

    // Pattern 2: Size first, then address
    {
        struct { UINT32 size; UINT32 pad; UINT64 address; } req{};
        BYTE resp[256] = {0};
        req.size = 16;
        req.address = reinterpret_cast<UINT64>(&req);

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes > 0 && memcmp(resp, &req, 16) == 0) {
                return 2;
            }
        }
    }

    // Pattern 3: 32-bit address variant
    {
        struct { UINT32 address; UINT32 size; } req{};
        BYTE resp[256] = {0};
        req.address = static_cast<UINT32>(reinterpret_cast<UINT64>(&req) & 0xFFFFFFFF);
        req.size = 8;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), resp, sizeof(resp), &bytes)) {
            if (bytes >= 8) return 3;
        }
    }

    // Pattern 4: Just an address, output is data
    {
        UINT64 addr = reinterpret_cast<UINT64>(&addr);
        BYTE resp[64] = {0};

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &addr, sizeof(addr), resp, sizeof(resp), &bytes)) {
            if (bytes > 0 && memcmp(resp, &addr, sizeof(addr)) == 0) {
                return 4;
            }
        }
    }

    // Pattern 5: memcpy style (dest, src, size)
    {
        MemcpyRequest req{};
        static BYTE dest[64] = {0};
        req.dest = reinterpret_cast<UINT64>(dest);
        req.src = reinterpret_cast<UINT64>(&req);
        req.size = sizeof(req);

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), nullptr, 0, &bytes)) {
            if (memcmp(dest, &req, sizeof(req)) == 0) {
                memset(dest, 0, sizeof(dest));
                return 5;
            }
        }
    }

    return 0;
}

int MemoryVerifier::test_arbitrary_write(HANDLE device, DWORD ioctl) {
    // Pattern 1: Address + value write
    {
        struct { UINT64 address; UINT64 value; } req{};
        static UINT64 target = 0xDEADBEEF;
        req.address = reinterpret_cast<UINT64>(&target);
        req.value = 0x1234567890ABCDEF;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), nullptr, 0, &bytes)) {
            if (target == 0x1234567890ABCDEF) {
                target = 0xDEADBEEF;
                return 1;
            }
        }
    }

    // Pattern 2: Address + size + data
    {
        struct { UINT64 address; UINT32 size; UINT32 data; } req{};
        static UINT32 target = 0xAAAAAAAA;
        req.address = reinterpret_cast<UINT64>(&target);
        req.size = sizeof(UINT32);
        req.data = 0x55555555;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), nullptr, 0, &bytes)) {
            if (target == 0x55555555) {
                target = 0xAAAAAAAA;
                return 2;
            }
        }
    }

    // Pattern 3: memcpy write
    {
        MemcpyRequest req{};
        static BYTE dest[32] = {0};
        static BYTE src[32] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
        req.dest = reinterpret_cast<UINT64>(dest);
        req.src = reinterpret_cast<UINT64>(src);
        req.size = 16;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), nullptr, 0, &bytes)) {
            if (memcmp(dest, src, 16) == 0) {
                memset(dest, 0, sizeof(dest));
                return 3;
            }
        }
    }

    return 0;
}

bool MemoryVerifier::test_msr_access(HANDLE device, DWORD ioctl) {
    // Pattern 1: MsrRequest style
    {
        MsrRequest req{};
        UINT64 resp = 0;
        req.msr_register = 0x10;  // IA32_TIME_STAMP_COUNTER (safe)
        req.cpu_number = 0;
        req.write = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &resp, sizeof(resp), &bytes)) {
            if (bytes == sizeof(UINT64) && resp != 0) {
                return true;
            }
        }
    }

    // Pattern 2: Simple MSR index
    {
        UINT32 msr = 0x10;
        UINT64 resp = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &msr, sizeof(msr), &resp, sizeof(resp), &bytes)) {
            if (bytes == sizeof(UINT64) && resp != 0) {
                return true;
            }
        }
    }

    return false;
}

bool MemoryVerifier::test_port_io(HANDLE device, DWORD ioctl) {
    // Pattern 1: PortIoRequest style
    {
        PortIoRequest req{};
        UINT32 resp = 0;
        req.port = 0x64;  // Keyboard controller (safe read)
        req.size = 1;
        req.write = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &resp, sizeof(resp), &bytes)) {
            if (bytes >= 1) return true;
        }
    }

    // Pattern 2: Simple port + response
    {
        UINT16 port = 0x64;
        BYTE resp = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &port, sizeof(port), &resp, sizeof(resp), &bytes)) {
            if (bytes == 1) return true;
        }
    }

    return false;
}

bool MemoryVerifier::test_pci_config(HANDLE device, DWORD ioctl) {
    // Pattern 1: PciConfigRequest style
    {
        PciConfigRequest req{};
        UINT32 resp = 0;
        req.bus = 0;
        req.device = 0;
        req.function = 0;
        req.offset = 0;  // Vendor ID
        req.size = 2;
        req.write = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &resp, sizeof(resp), &bytes)) {
            if (bytes >= 2 && (resp & 0xFFFF) != 0 && (resp & 0xFFFF) != 0xFFFF) {
                return true;  // Got a valid vendor ID
            }
        }
    }

    return false;
}

bool MemoryVerifier::test_cr3_access(HANDLE device, DWORD ioctl) {
    // Pattern 1: Cr3Request style
    {
        Cr3Request req{};
        req.process_id = GetCurrentProcessId();
        req.cr3_out = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &req, sizeof(req), &bytes)) {
            // CR3 should be page-aligned and in a valid range
            if (req.cr3_out != 0 && (req.cr3_out & 0xFFF) == 0) {
                return true;
            }
        }
    }

    // Pattern 2: PID in, CR3 out
    {
        UINT64 pid = GetCurrentProcessId();
        UINT64 cr3 = 0;

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &pid, sizeof(pid), &cr3, sizeof(cr3), &bytes)) {
            if (cr3 != 0 && (cr3 & 0xFFF) == 0) {
                return true;
            }
        }
    }

    return false;
}

bool MemoryVerifier::test_process_query(HANDLE device, DWORD ioctl) {
    // Pattern 1: ModuleRequest style
    {
        ModuleRequest req{};
        req.process_id = GetCurrentProcessId();
        wcscpy_s(req.module_name, L"ntdll.dll");

        DWORD bytes = 0;
        if (safe_ioctl(device, ioctl, &req, sizeof(req), &req, sizeof(req), &bytes)) {
            if (req.base_address_out != 0) {
                return true;
            }
        }
    }

    return false;
}

bool MemoryVerifier::test_method_neither(HANDLE device, DWORD ioctl) {
    (void)device;
    return (ioctl & 0x3) == 3;
}

bool MemoryVerifier::test_privilege_check(HANDLE device, DWORD ioctl) {
    (void)device;
    (void)ioctl;

    BOOL is_admin = FALSE;
    SID_IDENTIFIER_AUTHORITY nt_authority = SECURITY_NT_AUTHORITY;
    PSID admin_group = nullptr;

    if (AllocateAndInitializeSid(&nt_authority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &admin_group)) {
        CheckTokenMembership(nullptr, admin_group, &is_admin);
        FreeSid(admin_group);
    }

    return !is_admin;
}

} // namespace ds
