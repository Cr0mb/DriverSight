#pragma once

#include "driver_sight.hpp"
#include <vector>
#include <string>

namespace ds {

struct RegistryDeviceInfo {
    std::wstring service_name;
    std::wstring display_name;
    std::wstring image_path;
    std::wstring device_path;
    DWORD start_type;
    DWORD type;
    bool is_kernel_driver;
};

class RegistryScanner {
public:
    // Enumerate all kernel drivers from registry
    std::vector<RegistryDeviceInfo> enumerate_kernel_services();

    // Find device interfaces from registry
    std::vector<std::wstring> enumerate_device_interfaces();

    // Get symbolic links from GLOBAL??
    std::vector<std::wstring> enumerate_dos_devices();

    // Find devices by class GUID
    std::vector<std::wstring> enumerate_by_class(const std::wstring& class_guid);

private:
    std::wstring read_reg_string(HKEY key, const wchar_t* value_name);
    DWORD read_reg_dword(HKEY key, const wchar_t* value_name, DWORD default_val);
};

} // namespace ds
