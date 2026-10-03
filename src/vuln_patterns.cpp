#include "vuln_patterns.hpp"
#include <unordered_map>

namespace ds {

static const std::unordered_map<VulnCategory, VulnPattern> patterns = {
    {VulnCategory::PhysicalMemory, {
        VulnCategory::PhysicalMemory, 10,
        "Physical Memory Access",
        "Driver allows mapping arbitrary physical memory via MmMapIoSpace or similar. "
        "This bypasses all memory protections and can read/write any process memory, kernel memory, or MMIO regions.",
        "Remove physical memory mapping capabilities or restrict to device-specific MMIO ranges only."
    }},
    {VulnCategory::VirtualMemory, {
        VulnCategory::VirtualMemory, 9,
        "Cross-Process Virtual Memory Access",
        "Driver provides MmCopyVirtualMemory or ZwRead/WriteVirtualMemory primitives. "
        "Allows reading/writing any process's virtual memory including protected processes.",
        "Remove cross-process memory access or validate caller is authorized."
    }},
    {VulnCategory::ProcessAttach, {
        VulnCategory::ProcessAttach, 9,
        "Process Attachment Primitive",
        "Driver uses KeStackAttachProcess to attach to arbitrary processes. "
        "Combined with memory operations, allows full process memory access.",
        "Restrict process attachment to specific authorized PIDs."
    }},
    {VulnCategory::MdlManipulation, {
        VulnCategory::MdlManipulation, 8,
        "MDL-Based Memory Manipulation",
        "Driver uses MDL (Memory Descriptor List) to map user-controlled memory regions. "
        "Can be abused to map kernel memory into user space or vice versa.",
        "Validate MDL operations and restrict to legitimate use cases."
    }},
    {VulnCategory::Cr3PageTable, {
        VulnCategory::Cr3PageTable, 10,
        "CR3/Page Table Walking",
        "Driver exposes CR3 (DirectoryTableBase) or performs manual page table walking. "
        "This is the most fundamental memory access primitive, bypassing all protections.",
        "Never expose CR3 values. Page table operations should be internal only."
    }},
    {VulnCategory::MsrAccess, {
        VulnCategory::MsrAccess, 9,
        "Model Specific Register Access",
        "Driver allows reading/writing CPU MSRs. MSR writes can disable security features (SMEP, SMAP), "
        "modify CPU behavior, or enable arbitrary code execution in ring 0.",
        "Remove MSR access or whitelist only safe, read-only MSRs."
    }},
    {VulnCategory::PortIo, {
        VulnCategory::PortIo, 7,
        "Direct Port I/O Access",
        "Driver allows IN/OUT instructions to arbitrary I/O ports. "
        "Can be used to reprogram hardware, access CMOS/RTC, or interact with legacy devices.",
        "Remove port I/O or restrict to specific device ports."
    }},
    {VulnCategory::PciConfig, {
        VulnCategory::PciConfig, 8,
        "PCI Configuration Space Access",
        "Driver allows reading/writing PCI configuration space. "
        "Can modify device BARs, enable DMA, or reconfigure hardware.",
        "Remove PCI config access or restrict to enumeration only."
    }},
    {VulnCategory::SharedSection, {
        VulnCategory::SharedSection, 6,
        "Shared Kernel Section",
        "Driver creates a shared memory section between kernel and user mode. "
        "If section contains sensitive data or pointers, can lead to information disclosure.",
        "Ensure shared sections contain no sensitive kernel data."
    }},
    {VulnCategory::ObjectManipulation, {
        VulnCategory::ObjectManipulation, 7,
        "Kernel Object Manipulation",
        "Driver allows manipulating kernel handles or objects. "
        "Can duplicate handles, close protected handles, or modify object security.",
        "Validate all object operations and restrict access rights."
    }},
    {VulnCategory::KernelExecution, {
        VulnCategory::KernelExecution, 10,
        "Arbitrary Kernel Code Execution",
        "Driver allows executing arbitrary code in kernel mode. "
        "Complete system compromise, can disable all security features.",
        "Never allow arbitrary code execution. All code paths must be predefined."
    }},
    {VulnCategory::MethodNeither, {
        VulnCategory::MethodNeither, 8,
        "METHOD_NEITHER IOCTL Usage",
        "Driver uses METHOD_NEITHER which passes raw user-mode pointers to kernel. "
        "Improper validation leads to arbitrary kernel read/write.",
        "Use METHOD_BUFFERED or METHOD_DIRECT. If NEITHER required, validate all pointers."
    }},
    {VulnCategory::NoPrivilegeCheck, {
        VulnCategory::NoPrivilegeCheck, 6,
        "Missing Privilege Verification",
        "Driver does not verify caller privileges before performing sensitive operations. "
        "Any user can access privileged functionality.",
        "Use SeAccessCheck, IoIs32bitProcess, or SeSinglePrivilegeCheck to validate callers."
    }},
};

const VulnPattern& get_vuln_pattern(VulnCategory cat) {
    static const VulnPattern unknown = {
        VulnCategory::MethodNeither, 5,
        "Unknown Vulnerability",
        "Unclassified security issue detected.",
        "Review driver implementation for security issues."
    };

    auto it = patterns.find(cat);
    if (it != patterns.end()) {
        return it->second;
    }
    return unknown;
}

std::string category_to_string(VulnCategory cat) {
    switch (cat) {
        case VulnCategory::PhysicalMemory: return "PHYS_MEM";
        case VulnCategory::VirtualMemory: return "VIRT_MEM";
        case VulnCategory::ProcessAttach: return "PROC_ATTACH";
        case VulnCategory::MdlManipulation: return "MDL_MANIP";
        case VulnCategory::Cr3PageTable: return "CR3_WALK";
        case VulnCategory::MsrAccess: return "MSR_ACCESS";
        case VulnCategory::PortIo: return "PORT_IO";
        case VulnCategory::PciConfig: return "PCI_CONFIG";
        case VulnCategory::SharedSection: return "SHARED_SEC";
        case VulnCategory::ObjectManipulation: return "OBJ_MANIP";
        case VulnCategory::KernelExecution: return "KERN_EXEC";
        case VulnCategory::MethodNeither: return "METHOD_NEITHER";
        case VulnCategory::NoPrivilegeCheck: return "NO_PRIV_CHK";
        default: return "UNKNOWN";
    }
}

} // namespace ds
