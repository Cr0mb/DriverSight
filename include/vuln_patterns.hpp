#pragma once

#include "driver_sight.hpp"
#include <vector>
#include <string>

namespace ds {

// Common IOCTL request structures based on real-world drivers
#pragma pack(push, 1)

// Pattern: Physical memory read (MmMapIoSpace style)
struct PhysMemRequest {
    UINT64 physical_address;
    UINT32 size;
    UINT32 cache_type;  // 0=NonCached, 1=Cached, 2=WriteCombined
};

// Pattern: Virtual memory read/write (MmCopyVirtualMemory style)
struct VirtMemRequest {
    UINT64 process_id;
    UINT64 address;
    UINT64 buffer;
    UINT32 size;
    UINT32 write;  // 0=read, 1=write
};

// Pattern: CR3/DirectoryBase request
struct Cr3Request {
    UINT64 process_id;
    UINT64 cr3_out;  // Output: DirectoryTableBase
};

// Pattern: Process attachment read
struct AttachReadRequest {
    UINT64 target_pid;
    UINT64 target_address;
    UINT64 output_buffer;
    UINT64 size;
};

// Pattern: MDL-based mapping
struct MdlMapRequest {
    UINT64 virtual_address;
    UINT32 size;
    UINT32 access_mode;  // 0=read, 1=write
    UINT64 mapped_address_out;
};

// Pattern: Section/shared memory
struct SectionRequest {
    UINT64 section_size;
    UINT32 protection;
    UINT32 flags;
    UINT64 mapped_base_out;
};

// Pattern: MSR read/write
struct MsrRequest {
    UINT32 msr_register;
    UINT32 cpu_number;
    UINT64 value;
    UINT32 write;  // 0=read, 1=write
};

// Pattern: Port I/O
struct PortIoRequest {
    UINT16 port;
    UINT16 size;  // 1, 2, or 4 bytes
    UINT32 value;
    UINT32 write;  // 0=read, 1=write
};

// Pattern: PCI config space
struct PciConfigRequest {
    UINT32 bus;
    UINT32 device;
    UINT32 function;
    UINT32 offset;
    UINT32 size;
    UINT32 value;
    UINT32 write;
};

// Pattern: Kernel object manipulation
struct ObjectRequest {
    UINT64 process_id;
    UINT64 handle;
    UINT32 access_mask;
    UINT32 operation;  // 0=query, 1=duplicate, 2=close
};

// Pattern: Module/base address query
struct ModuleRequest {
    UINT64 process_id;
    wchar_t module_name[64];
    UINT64 base_address_out;
    UINT64 size_out;
};

// Pattern: Simple address + size
struct SimpleReadWrite {
    UINT64 address;
    UINT64 size;
};

// Pattern: memcpy style
struct MemcpyRequest {
    UINT64 dest;
    UINT64 src;
    UINT64 size;
};

#pragma pack(pop)

// Vulnerability classification
enum class VulnCategory {
    PhysicalMemory,      // MmMapIoSpace, \\Device\\PhysicalMemory
    VirtualMemory,       // MmCopyVirtualMemory, Zw*VirtualMemory
    ProcessAttach,       // KeStackAttachProcess
    MdlManipulation,     // MDL-based access
    Cr3PageTable,        // CR3/page table walking
    MsrAccess,           // RDMSR/WRMSR
    PortIo,              // IN/OUT instructions
    PciConfig,           // PCI configuration space
    SharedSection,       // Section objects
    ObjectManipulation,  // Handle/object access
    KernelExecution,     // Arbitrary code execution
    MethodNeither,       // Unsafe IOCTL method
    NoPrivilegeCheck,    // Missing caller validation
};

struct VulnPattern {
    VulnCategory category;
    int severity;  // 1-10
    std::string name;
    std::string description;
    std::string mitigation;
};

// Get vulnerability details
const VulnPattern& get_vuln_pattern(VulnCategory cat);

// Category to string
std::string category_to_string(VulnCategory cat);

} // namespace ds
