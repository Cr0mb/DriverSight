#include "registry_scanner.hpp"
#include <algorithm>

namespace ds {

std::wstring RegistryScanner::read_reg_string(HKEY key, const wchar_t* value_name) {
    wchar_t buffer[1024] = {0};
    DWORD size = sizeof(buffer);
    DWORD type = 0;

    if (RegQueryValueExW(key, value_name, nullptr, &type,
        reinterpret_cast<LPBYTE>(buffer), &size) == ERROR_SUCCESS) {
        if (type == REG_SZ || type == REG_EXPAND_SZ) {
            return buffer;
        }
    }
    return L"";
}

DWORD RegistryScanner::read_reg_dword(HKEY key, const wchar_t* value_name, DWORD default_val) {
    DWORD value = 0;
    DWORD size = sizeof(value);
    DWORD type = 0;

    if (RegQueryValueExW(key, value_name, nullptr, &type,
        reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS) {
        if (type == REG_DWORD) {
            return value;
        }
    }
    return default_val;
}

std::vector<RegistryDeviceInfo> RegistryScanner::enumerate_kernel_services() {
    std::vector<RegistryDeviceInfo> services;

    HKEY services_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services",
        0, KEY_READ, &services_key) != ERROR_SUCCESS) {
        return services;
    }

    wchar_t subkey_name[256];
    DWORD index = 0;
    DWORD name_size;

    while (true) {
        name_size = 256;
        LONG result = RegEnumKeyExW(services_key, index++, subkey_name,
            &name_size, nullptr, nullptr, nullptr, nullptr);

        if (result != ERROR_SUCCESS) break;

        HKEY service_key;
        std::wstring path = std::wstring(L"SYSTEM\\CurrentControlSet\\Services\\") + subkey_name;

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &service_key) == ERROR_SUCCESS) {
            RegistryDeviceInfo info{};
            info.service_name = subkey_name;
            info.type = read_reg_dword(service_key, L"Type", 0);
            info.start_type = read_reg_dword(service_key, L"Start", 4);
            info.image_path = read_reg_string(service_key, L"ImagePath");
            info.display_name = read_reg_string(service_key, L"DisplayName");

            // Type 1 = Kernel driver, Type 2 = File system driver
            info.is_kernel_driver = (info.type == 1 || info.type == 2);

            if (info.is_kernel_driver && !info.image_path.empty()) {
                // Generate potential device path from service name
                info.device_path = L"\\\\.\\" + info.service_name;
                services.push_back(info);
            }

            RegCloseKey(service_key);
        }
    }

    RegCloseKey(services_key);
    return services;
}

std::vector<std::wstring> RegistryScanner::enumerate_device_interfaces() {
    std::vector<std::wstring> interfaces;

    // Common device interface GUIDs
    static const wchar_t* interface_guids[] = {
        L"{4D36E96E-E325-11CE-BFC1-08002BE10318}", // Display
        L"{4D36E97D-E325-11CE-BFC1-08002BE10318}", // System
        L"{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}", // HID
        L"{A5DCBF10-6530-11D2-901F-00C04FB951ED}", // USB
        L"{53F5630D-B6BF-11D0-94F2-00A0C91EFB8B}", // Disk
        L"{4D36E978-E325-11CE-BFC1-08002BE10318}", // Ports (COM/LPT)
        L"{6BDD1FC1-810F-11D0-BEC7-08002BE2092F}", // Monitor
        L"{4D36E968-E325-11CE-BFC1-08002BE10318}", // Keyboard
        L"{4D36E96F-E325-11CE-BFC1-08002BE10318}", // Mouse
    };

    for (const auto& guid : interface_guids) {
        std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\" + std::wstring(guid);

        HKEY class_key;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &class_key) == ERROR_SUCCESS) {
            wchar_t subkey_name[512];
            DWORD idx = 0;
            DWORD name_size;

            while (true) {
                name_size = 512;
                if (RegEnumKeyExW(class_key, idx++, subkey_name, &name_size,
                    nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                    break;
                }

                // Convert registry path to device path
                std::wstring dev_path = subkey_name;
                // Registry uses ## instead of backslashes
                std::replace(dev_path.begin(), dev_path.end(), L'#', L'\\');

                // Check if it starts with ##?#
                if (dev_path.length() > 4 && dev_path.substr(0, 4) == L"\\\\?\\") {
                    interfaces.push_back(dev_path);
                    // Also try DOS device style
                    std::wstring dos_path = L"\\\\.\\" + dev_path.substr(4);
                    interfaces.push_back(dos_path);
                }
            }

            RegCloseKey(class_key);
        }
    }

    return interfaces;
}

std::vector<std::wstring> RegistryScanner::enumerate_dos_devices() {
    std::vector<std::wstring> devices;

    // Query DOS device names
    wchar_t buffer[65535];
    DWORD size = QueryDosDeviceW(nullptr, buffer, 65535);

    if (size > 0) {
        wchar_t* ptr = buffer;
        while (*ptr) {
            std::wstring name = ptr;

            // Filter for interesting device types
            std::wstring lower = name;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            // Skip common system devices we're not interested in
            bool skip = false;
            static const wchar_t* skip_prefixes[] = {
                L"aux", L"con", L"nul", L"prn",
                L"volume{", L"harddiskvolume",
                L"floppy", L"mailslot", L"pipe"
            };

            for (const auto& prefix : skip_prefixes) {
                if (lower.find(prefix) == 0) {
                    skip = true;
                    break;
                }
            }

            if (!skip) {
                devices.push_back(L"\\\\.\\" + name);
            }

            ptr += name.length() + 1;
        }
    }

    return devices;
}

std::vector<std::wstring> RegistryScanner::enumerate_by_class(const std::wstring& class_guid) {
    std::vector<std::wstring> devices;

    std::wstring path = L"SYSTEM\\CurrentControlSet\\Control\\Class\\" + class_guid;

    HKEY class_key;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, KEY_READ, &class_key) == ERROR_SUCCESS) {
        wchar_t subkey_name[256];
        DWORD index = 0;
        DWORD name_size;

        while (true) {
            name_size = 256;
            if (RegEnumKeyExW(class_key, index++, subkey_name, &name_size,
                nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) {
                break;
            }

            // Skip non-numeric entries
            if (subkey_name[0] < L'0' || subkey_name[0] > L'9') continue;

            HKEY device_key;
            std::wstring device_path = path + L"\\" + subkey_name;

            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, device_path.c_str(), 0, KEY_READ, &device_key) == ERROR_SUCCESS) {
                std::wstring service = read_reg_string(device_key, L"Service");
                std::wstring driver = read_reg_string(device_key, L"Driver");

                if (!service.empty()) {
                    devices.push_back(L"\\\\.\\" + service);
                }

                RegCloseKey(device_key);
            }
        }

        RegCloseKey(class_key);
    }

    return devices;
}

} // namespace ds
