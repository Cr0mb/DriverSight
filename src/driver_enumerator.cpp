#include "driver_enumerator.hpp"
#include <psapi.h>
#include <algorithm>
#include <cctype>

namespace ds {

std::vector<DriverInfo> DriverEnumerator::enumerate_drivers() {
    std::vector<DriverInfo> drivers;

    LPVOID driver_addresses[1024];
    DWORD bytes_needed;

    if (!EnumDeviceDrivers(driver_addresses, sizeof(driver_addresses), &bytes_needed)) {
        return drivers;
    }

    DWORD driver_count = bytes_needed / sizeof(LPVOID);

    for (DWORD i = 0; i < driver_count; ++i) {
        DriverInfo info{};
        info.base_address = driver_addresses[i];

        wchar_t name_buffer[MAX_PATH];
        wchar_t path_buffer[MAX_PATH];

        if (GetDeviceDriverBaseNameW(driver_addresses[i], name_buffer, MAX_PATH)) {
            info.name = name_buffer;
        }

        if (GetDeviceDriverFileNameW(driver_addresses[i], path_buffer, MAX_PATH)) {
            info.path = path_buffer;
        }

        if (!info.name.empty()) {
            drivers.push_back(std::move(info));
        }
    }

    return drivers;
}

std::vector<DriverInfo> DriverEnumerator::filter_third_party(const std::vector<DriverInfo>& drivers) {
    std::vector<DriverInfo> filtered;

    for (const auto& driver : drivers) {
        if (!is_system_driver(driver.path)) {
            filtered.push_back(driver);
        }
    }

    return filtered;
}

bool DriverEnumerator::is_system_driver(const std::wstring& path) {
    std::wstring lower_path = path;
    std::transform(lower_path.begin(), lower_path.end(), lower_path.begin(), ::towlower);

    // Known third-party keywords to preserve
    static const std::vector<std::wstring> third_party_keywords = {
        L"nvidia", L"nvld", L"nvhd", L"nvva",  // NVIDIA
        L"amd", L"ati",                          // AMD
        L"asus", L"aura", L"asusio",            // ASUS
        L"corsair", L"cue",                     // Corsair
        L"razer", L"rzdev",                     // Razer
        L"logitech", L"lgs",                    // Logitech
        L"steelseries", L"sonar",               // SteelSeries
        L"msi", L"mystic",                      // MSI
        L"gigabyte", L"rgbfusion",              // Gigabyte
        L"asrock", L"asrdrv",                   // ASRock
        L"nzxt", L"cam",                        // NZXT
        L"realtek", L"rtw", L"rtk",             // Realtek
        L"vigem", L"tbox", L"android",          // Emulators/Virtualization
        L"hwinfo", L"cpuz", L"gpuz", L"aida",   // System utilities
        L"afterburner", L"rtcore",              // Monitoring
        L"winring", L"winio"                    // Low-level I/O
    };

    // Check if it's a known third-party driver first
    for (const auto& keyword : third_party_keywords) {
        if (lower_path.find(keyword) != std::wstring::npos) {
            return false;  // Not a system driver, keep it
        }
    }

    // System paths - anything in these locations is a system driver
    if (lower_path.find(L"\\systemroot\\system32\\") != std::wstring::npos ||
        lower_path.find(L"\\windows\\system32\\") != std::wstring::npos) {
        return true;
    }

    // Program Files paths are third-party
    if (lower_path.find(L"program files") != std::wstring::npos) {
        return false;
    }

    return false;  // Default to keeping unknown drivers
}

} // namespace ds
