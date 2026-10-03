#pragma once

#include "driver_sight.hpp"
#include <windows.h>
#include <setupapi.h>
#include <devguid.h>
#include <vector>
#include <string>

namespace ds {

class SetupApiScanner {
public:
    // Enumerate all device instances
    std::vector<std::wstring> enumerate_all_devices();

    // Enumerate devices by class
    std::vector<std::wstring> enumerate_by_guid(const GUID& class_guid);

    // Get device interfaces that can be opened
    std::vector<std::wstring> enumerate_device_interfaces();

    // Get PDO (Physical Device Object) names
    std::vector<std::wstring> get_pdo_names();
};

} // namespace ds
