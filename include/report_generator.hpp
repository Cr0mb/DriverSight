#pragma once

#include "driver_sight.hpp"
#include <string>
#include <vector>

namespace ds {

class ReportGenerator {
public:
    void add_driver(const DriverInfo& driver);
    void add_device(const DeviceInfo& device);
    void add_vulnerability(const Vulnerability& vuln);

    std::string generate_json() const;
    void print_console() const;
    void save_to_file(const std::string& filename) const;

private:
    std::vector<DriverInfo> drivers_;
    std::vector<DeviceInfo> devices_;
    std::vector<Vulnerability> vulnerabilities_;
};

} // namespace ds
