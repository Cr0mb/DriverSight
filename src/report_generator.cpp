#include "report_generator.hpp"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <ctime>

namespace ds {

void ReportGenerator::add_driver(const DriverInfo& driver) {
    drivers_.push_back(driver);
}

void ReportGenerator::add_device(const DeviceInfo& device) {
    devices_.push_back(device);
}

void ReportGenerator::add_vulnerability(const Vulnerability& vuln) {
    vulnerabilities_.push_back(vuln);
}

std::string wstring_to_utf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), size, nullptr, nullptr);
    return str;
}

std::string escape_json(const std::string& s) {
    std::ostringstream o;
    for (char c : s) {
        switch (c) {
            case '"': o << "\\\""; break;
            case '\\': o << "\\\\"; break;
            case '\b': o << "\\b"; break;
            case '\f': o << "\\f"; break;
            case '\n': o << "\\n"; break;
            case '\r': o << "\\r"; break;
            case '\t': o << "\\t"; break;
            default:
                if ('\x00' <= c && c <= '\x1f') {
                    o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
                } else {
                    o << c;
                }
        }
    }
    return o.str();
}

std::string vuln_type_to_string(VulnType type) {
    switch (type) {
        case VulnType::ArbitraryRead: return "Arbitrary Kernel Read";
        case VulnType::ArbitraryWrite: return "Arbitrary Kernel Write";
        case VulnType::BufferOverflow: return "Buffer Overflow";
        case VulnType::PrivilegeCheck: return "Missing Privilege Check";
        case VulnType::MethodNeither: return "METHOD_NEITHER Usage";
        default: return "Unknown";
    }
}

std::string severity_bar(int severity) {
    std::string bar = "[";
    for (int i = 1; i <= 10; ++i) {
        if (i <= severity) {
            if (severity >= 9) bar += "#";
            else if (severity >= 7) bar += "=";
            else bar += "-";
        } else {
            bar += " ";
        }
    }
    bar += "]";
    return bar;
}

std::string severity_label(int severity) {
    if (severity >= 9) return "CRITICAL";
    if (severity >= 7) return "HIGH";
    if (severity >= 5) return "MEDIUM";
    return "LOW";
}

std::string ReportGenerator::generate_json() const {
    std::ostringstream json;

    // Get current timestamp
    time_t now = time(nullptr);
    char timestamp[64];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    json << "{\n";
    json << "  \"scan_info\": {\n";
    json << "    \"tool\": \"DriverSight\",\n";
    json << "    \"version\": \"2.0.0\",\n";
    json << "    \"timestamp\": \"" << timestamp << "\",\n";
    json << "    \"purpose\": \"Defensive Security Research - Kernel Driver Vulnerability Auditing\"\n";
    json << "  },\n";

    json << "  \"summary\": {\n";
    json << "    \"drivers_scanned\": " << drivers_.size() << ",\n";
    json << "    \"devices_accessible\": " << devices_.size() << ",\n";
    json << "    \"vulnerabilities_found\": " << vulnerabilities_.size() << ",\n";

    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& v : vulnerabilities_) {
        if (v.severity >= 9) ++critical;
        else if (v.severity >= 7) ++high;
        else if (v.severity >= 5) ++medium;
        else ++low;
    }
    json << "    \"critical\": " << critical << ",\n";
    json << "    \"high\": " << high << ",\n";
    json << "    \"medium\": " << medium << ",\n";
    json << "    \"low\": " << low << "\n";
    json << "  },\n";

    // Drivers
    json << "  \"drivers\": [\n";
    for (size_t i = 0; i < drivers_.size(); ++i) {
        const auto& d = drivers_[i];
        json << "    {\n";
        json << "      \"name\": \"" << escape_json(wstring_to_utf8(d.name)) << "\",\n";
        json << "      \"path\": \"" << escape_json(wstring_to_utf8(d.path)) << "\",\n";
        json << std::format("      \"base_address\": \"0x{:016X}\"\n",
                           reinterpret_cast<uintptr_t>(d.base_address));
        json << "    }" << (i + 1 < drivers_.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Devices
    json << "  \"accessible_devices\": [\n";
    for (size_t i = 0; i < devices_.size(); ++i) {
        const auto& d = devices_[i];
        json << "    {\n";
        json << "      \"path\": \"" << escape_json(wstring_to_utf8(d.device_path)) << "\",\n";
        json << "      \"driver\": \"" << escape_json(wstring_to_utf8(d.driver_name)) << "\",\n";
        json << "      \"readable\": " << (d.readable ? "true" : "false") << ",\n";
        json << "      \"writable\": " << (d.writable ? "true" : "false") << "\n";
        json << "    }" << (i + 1 < devices_.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    // Vulnerabilities
    json << "  \"vulnerabilities\": [\n";
    for (size_t i = 0; i < vulnerabilities_.size(); ++i) {
        const auto& v = vulnerabilities_[i];
        json << "    {\n";
        json << "      \"driver\": \"" << escape_json(wstring_to_utf8(v.driver_name)) << "\",\n";
        json << "      \"device\": \"" << escape_json(wstring_to_utf8(v.device_path)) << "\",\n";
        json << std::format("      \"ioctl_code\": \"0x{:08X}\",\n", v.ioctl_code);
        json << "      \"type\": \"" << vuln_type_to_string(v.type) << "\",\n";
        json << "      \"severity\": " << v.severity << ",\n";
        json << "      \"severity_label\": \"" << severity_label(v.severity) << "\",\n";
        json << "      \"description\": \"" << escape_json(v.description) << "\"\n";
        json << "    }" << (i + 1 < vulnerabilities_.size() ? "," : "") << "\n";
    }
    json << "  ]\n";

    json << "}\n";
    return json.str();
}

void ReportGenerator::print_console() const {
    std::cout << "\n";
    std::cout << "================================================================================\n";
    std::cout << "                        DRIVERSIGHT SCAN REPORT v2.0\n";
    std::cout << "                    Defensive Security Research Tool\n";
    std::cout << "================================================================================\n\n";

    // Summary
    std::cout << "+-- SCAN SUMMARY ------------------------------------------------------------+\n";
    std::cout << "| Drivers Loaded:     " << std::setw(5) << drivers_.size() << "                                                |\n";
    std::cout << "| Devices Accessible: " << std::setw(5) << devices_.size() << "                                                |\n";
    std::cout << "| Vulnerabilities:    " << std::setw(5) << vulnerabilities_.size() << "                                                |\n";

    int critical = 0, high = 0, medium = 0, low = 0;
    for (const auto& v : vulnerabilities_) {
        if (v.severity >= 9) ++critical;
        else if (v.severity >= 7) ++high;
        else if (v.severity >= 5) ++medium;
        else ++low;
    }

    if (!vulnerabilities_.empty()) {
        std::cout << "|   - Critical: " << critical << "  High: " << high
                  << "  Medium: " << medium << "  Low: " << low << "                              |\n";
    }
    std::cout << "+----------------------------------------------------------------------------+\n\n";

    // Drivers
    if (!drivers_.empty()) {
        std::cout << "+-- LOADED DRIVERS ----------------------------------------------------------+\n";
        for (const auto& d : drivers_) {
            std::cout << "| " << std::left << std::setw(74) << wstring_to_utf8(d.name) << " |\n";
        }
        std::cout << "+----------------------------------------------------------------------------+\n\n";
    }

    // Accessible Devices
    if (!devices_.empty()) {
        std::cout << "+-- ACCESSIBLE DEVICES ------------------------------------------------------+\n";
        for (const auto& d : devices_) {
            std::string perms = std::string(d.readable ? "R" : "-") + (d.writable ? "W" : "-");
            std::string line = wstring_to_utf8(d.device_path);
            if (line.length() > 50) line = line.substr(0, 47) + "...";
            std::cout << "| [" << perms << "] " << std::left << std::setw(50) << line;

            std::string drv = wstring_to_utf8(d.driver_name);
            if (drv.length() > 18) drv = drv.substr(0, 15) + "...";
            std::cout << " -> " << std::setw(18) << drv << " |\n";
        }
        std::cout << "+----------------------------------------------------------------------------+\n\n";
    }

    // Vulnerabilities
    if (!vulnerabilities_.empty()) {
        std::cout << "+-- VULNERABILITIES FOUND ---------------------------------------------------+\n";
        std::cout << "|                                                                            |\n";

        int vuln_num = 1;
        for (const auto& v : vulnerabilities_) {
            std::string sev_label = severity_label(v.severity);
            std::string sev_color = severity_bar(v.severity);

            std::cout << "| [" << std::setw(2) << vuln_num++ << "] " << sev_label << " " << sev_color << " (Severity: " << v.severity << "/10)\n";
            std::cout << "|      Driver: " << wstring_to_utf8(v.driver_name) << "\n";
            std::cout << "|      Device: " << wstring_to_utf8(v.device_path) << "\n";
            std::cout << std::format("|      IOCTL:  0x{:08X}\n", v.ioctl_code);
            std::cout << "|      Type:   " << vuln_type_to_string(v.type) << "\n";

            // Word-wrap description at 70 chars
            std::string desc = v.description;
            size_t pos = 0;
            while (pos < desc.length()) {
                size_t end = std::min(pos + 65, desc.length());
                if (end < desc.length()) {
                    size_t space = desc.rfind(' ', end);
                    if (space > pos) end = space;
                }
                std::cout << "|      " << (pos == 0 ? "Desc:  " : "       ") << desc.substr(pos, end - pos) << "\n";
                pos = end;
                while (pos < desc.length() && desc[pos] == ' ') ++pos;
            }
            std::cout << "|                                                                            |\n";
        }
        std::cout << "+----------------------------------------------------------------------------+\n";
    } else {
        std::cout << "+-- NO VULNERABILITIES FOUND ------------------------------------------------+\n";
        std::cout << "| The scanned devices did not exhibit known vulnerability patterns.          |\n";
        std::cout << "| This does not guarantee the drivers are secure - manual review is          |\n";
        std::cout << "| recommended for high-value targets.                                        |\n";
        std::cout << "+----------------------------------------------------------------------------+\n";
    }

    std::cout << "\n";
    std::cout << "+-- RESPONSIBLE DISCLOSURE --------------------------------------------------+\n";
    std::cout << "| Submit findings to hardware vendors before public disclosure.              |\n";
    std::cout << "| CVE coordination: https://cveform.mitre.org/                               |\n";
    std::cout << "+----------------------------------------------------------------------------+\n";
}

void ReportGenerator::save_to_file(const std::string& filename) const {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << generate_json();
        file.close();
    }
}

} // namespace ds
