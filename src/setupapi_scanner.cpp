#include "setupapi_scanner.hpp"
#include <initguid.h>
#include <devpkey.h>
#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

// Device interface GUIDs for various device types
DEFINE_GUID(GUID_DEVINTERFACE_DISK, 0x53f56307L, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);
DEFINE_GUID(GUID_DEVINTERFACE_HID, 0x4d1e55b2L, 0xf16f, 0x11cf, 0x88, 0xcb, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30);
DEFINE_GUID(GUID_DEVINTERFACE_USB_DEVICE, 0xA5DCBF10L, 0x6530, 0x11D2, 0x90, 0x1F, 0x00, 0xC0, 0x4F, 0xB9, 0x51, 0xED);
DEFINE_GUID(GUID_DEVINTERFACE_MONITOR, 0xe6f07b5fL, 0xee97, 0x4a90, 0xb0, 0x76, 0x33, 0xf5, 0x7b, 0xf4, 0xea, 0xa7);
DEFINE_GUID(GUID_DEVINTERFACE_DISPLAY_ADAPTER, 0x5b45201dL, 0xf2f2, 0x4f3b, 0x85, 0xbb, 0x30, 0xff, 0x1f, 0x95, 0x35, 0x99);

namespace ds {

std::vector<std::wstring> SetupApiScanner::enumerate_all_devices() {
    std::vector<std::wstring> devices;

    // Get all devices
    HDEVINFO dev_info = SetupDiGetClassDevsW(
        nullptr, nullptr, nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT
    );

    if (dev_info == INVALID_HANDLE_VALUE) {
        return devices;
    }

    SP_DEVINFO_DATA dev_info_data;
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data); ++i) {
        wchar_t instance_id[MAX_DEVICE_ID_LEN];

        if (CM_Get_Device_IDW(dev_info_data.DevInst, instance_id, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
            // Try to get device interface path
            wchar_t device_path[MAX_PATH];
            DWORD size = sizeof(device_path);

            if (SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data,
                SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, nullptr,
                reinterpret_cast<PBYTE>(device_path), size, &size)) {

                // Convert PDO name to DOS name
                std::wstring pdo_name = device_path;
                if (pdo_name.find(L"\\Device\\") == 0) {
                    std::wstring dos_name = L"\\\\.\\" + pdo_name.substr(8);
                    devices.push_back(dos_name);
                }
                devices.push_back(L"\\\\.\\" + std::wstring(instance_id));
            }

            // Get service name and try that too
            wchar_t service[256];
            size = sizeof(service);
            if (SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data,
                SPDRP_SERVICE, nullptr, reinterpret_cast<PBYTE>(service), size, &size)) {
                devices.push_back(L"\\\\.\\" + std::wstring(service));
            }
        }
    }

    SetupDiDestroyDeviceInfoList(dev_info);
    return devices;
}

std::vector<std::wstring> SetupApiScanner::enumerate_by_guid(const GUID& class_guid) {
    std::vector<std::wstring> devices;

    HDEVINFO dev_info = SetupDiGetClassDevsW(
        &class_guid, nullptr, nullptr,
        DIGCF_DEVICEINTERFACE | DIGCF_PRESENT
    );

    if (dev_info == INVALID_HANDLE_VALUE) {
        return devices;
    }

    SP_DEVICE_INTERFACE_DATA iface_data;
    iface_data.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInterfaces(dev_info, nullptr, &class_guid, i, &iface_data); ++i) {
        DWORD required_size = 0;
        SetupDiGetDeviceInterfaceDetailW(dev_info, &iface_data, nullptr, 0, &required_size, nullptr);

        if (required_size > 0) {
            std::vector<BYTE> buffer(required_size);
            auto* detail = reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());
            detail->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

            if (SetupDiGetDeviceInterfaceDetailW(dev_info, &iface_data, detail, required_size, nullptr, nullptr)) {
                devices.push_back(detail->DevicePath);
            }
        }
    }

    SetupDiDestroyDeviceInfoList(dev_info);
    return devices;
}

std::vector<std::wstring> SetupApiScanner::enumerate_device_interfaces() {
    std::vector<std::wstring> all_interfaces;

    // Common device interface GUIDs to check
    static const GUID guids[] = {
        GUID_DEVINTERFACE_DISK,
        GUID_DEVINTERFACE_HID,
        GUID_DEVINTERFACE_USB_DEVICE,
        GUID_DEVINTERFACE_MONITOR,
        GUID_DEVINTERFACE_DISPLAY_ADAPTER,
    };

    for (const auto& guid : guids) {
        auto interfaces = enumerate_by_guid(guid);
        all_interfaces.insert(all_interfaces.end(), interfaces.begin(), interfaces.end());
    }

    return all_interfaces;
}

std::vector<std::wstring> SetupApiScanner::get_pdo_names() {
    std::vector<std::wstring> pdo_names;

    HDEVINFO dev_info = SetupDiGetClassDevsW(
        nullptr, nullptr, nullptr,
        DIGCF_ALLCLASSES | DIGCF_PRESENT
    );

    if (dev_info == INVALID_HANDLE_VALUE) {
        return pdo_names;
    }

    SP_DEVINFO_DATA dev_info_data;
    dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

    for (DWORD i = 0; SetupDiEnumDeviceInfo(dev_info, i, &dev_info_data); ++i) {
        wchar_t pdo_name[MAX_PATH];
        DWORD size = sizeof(pdo_name);

        if (SetupDiGetDeviceRegistryPropertyW(dev_info, &dev_info_data,
            SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, nullptr,
            reinterpret_cast<PBYTE>(pdo_name), size, &size)) {
            pdo_names.push_back(pdo_name);
        }
    }

    SetupDiDestroyDeviceInfoList(dev_info);
    return pdo_names;
}

} // namespace ds
