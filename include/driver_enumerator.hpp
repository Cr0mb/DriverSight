#pragma once

#include "driver_sight.hpp"
#include <vector>

namespace ds {

class DriverEnumerator {
public:
    std::vector<DriverInfo> enumerate_drivers();
    std::vector<DriverInfo> filter_third_party(const std::vector<DriverInfo>& drivers);

private:
    bool is_system_driver(const std::wstring& path);
};

} // namespace ds
