#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include <format>

namespace ds {

struct DriverInfo {
    std::wstring name;
    std::wstring path;
    PVOID base_address;
    SIZE_T image_size;
};

struct DeviceInfo {
    std::wstring device_path;
    std::wstring driver_name;
    bool readable;
    bool writable;
    DWORD last_error;
};

struct IoctlResult {
    DWORD ioctl_code;
    bool success;
    DWORD bytes_returned;
    DWORD last_error;
    std::string method_type;
};

enum class VulnType {
    None,
    ArbitraryRead,
    ArbitraryWrite,
    BufferOverflow,
    PrivilegeCheck,
    MethodNeither
};

struct Vulnerability {
    std::wstring driver_name;
    std::wstring device_path;
    DWORD ioctl_code;
    VulnType type;
    std::string description;
    int severity; // 1-10
};

inline std::string ioctl_to_string(DWORD code) {
    DWORD device_type = (code >> 16) & 0xFFFF;
    DWORD access = (code >> 14) & 0x3;
    DWORD function = (code >> 2) & 0xFFF;
    DWORD method = code & 0x3;

    const char* method_str[] = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
    const char* access_str[] = {"ANY", "READ", "WRITE", "READ|WRITE"};

    return std::format("0x{:08X} [DevType={}, Func={}, Method={}, Access={}]",
        code, device_type, function, method_str[method], access_str[access]);
}

inline DWORD make_ioctl(DWORD device_type, DWORD function, DWORD method, DWORD access) {
    return (device_type << 16) | (access << 14) | (function << 2) | method;
}

} // namespace ds
