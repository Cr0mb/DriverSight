#pragma once

#include "driver_sight.hpp"
#include <vector>

namespace ds {

class DeviceScanner {
public:
    std::vector<DeviceInfo> scan_devices();
    std::optional<DeviceInfo> probe_device(const std::wstring& device_path);

private:
    std::vector<std::wstring> enumerate_device_paths();
};

} // namespace ds
