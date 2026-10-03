#pragma once

#include <windows.h>
#include <winternl.h>
#include <string>
#include <vector>
#include <optional>

// NT access rights not defined in headers
#ifndef DIRECTORY_QUERY
#define DIRECTORY_QUERY 0x0001
#endif
#ifndef SYMBOLIC_LINK_QUERY
#define SYMBOLIC_LINK_QUERY 0x0001
#endif

namespace ds {

// NT API types not in winternl.h
typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, *POBJECT_NAME_INFORMATION;

// Function pointer types for NT APIs
typedef NTSTATUS(NTAPI* PNtOpenDirectoryObject)(
    PHANDLE DirectoryHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* PNtQueryDirectoryObject)(
    HANDLE DirectoryHandle,
    PVOID Buffer,
    ULONG Length,
    BOOLEAN ReturnSingleEntry,
    BOOLEAN RestartScan,
    PULONG Context,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* PNtOpenSymbolicLinkObject)(
    PHANDLE LinkHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef NTSTATUS(NTAPI* PNtQuerySymbolicLinkObject)(
    HANDLE LinkHandle,
    PUNICODE_STRING LinkTarget,
    PULONG ReturnedLength
);

typedef NTSTATUS(NTAPI* PNtQueryObject)(
    HANDLE Handle,
    OBJECT_INFORMATION_CLASS ObjectInformationClass,
    PVOID ObjectInformation,
    ULONG ObjectInformationLength,
    PULONG ReturnLength
);

// Additional object info class
constexpr OBJECT_INFORMATION_CLASS ObjectNameInformation = static_cast<OBJECT_INFORMATION_CLASS>(1);

class NtHelpers {
public:
    NtHelpers();
    ~NtHelpers();

    bool is_initialized() const { return initialized_; }

    // Enumerate objects in a directory (e.g., "\\Device", "\\Driver")
    std::vector<std::pair<std::wstring, std::wstring>> enumerate_directory(const std::wstring& path);

    // Resolve a symbolic link
    std::optional<std::wstring> resolve_symlink(const std::wstring& link_path);

    // Get the NT object name for a handle
    std::optional<std::wstring> get_object_name(HANDLE handle);

private:
    HMODULE ntdll_;
    bool initialized_;

    PNtOpenDirectoryObject NtOpenDirectoryObject_;
    PNtQueryDirectoryObject NtQueryDirectoryObject_;
    PNtOpenSymbolicLinkObject NtOpenSymbolicLinkObject_;
    PNtQuerySymbolicLinkObject NtQuerySymbolicLinkObject_;
    PNtQueryObject NtQueryObject_;
};

// Map a device path to its driver name
std::optional<std::wstring> get_driver_for_device(const std::wstring& device_path);

} // namespace ds
