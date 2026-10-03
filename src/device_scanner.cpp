#include "device_scanner.hpp"
#include "nt_helpers.hpp"
#include "registry_scanner.hpp"
#include "setupapi_scanner.hpp"
#include <setupapi.h>
#include <iostream>
#include <algorithm>
#include <set>

#pragma comment(lib, "setupapi.lib")

namespace ds {

std::vector<DeviceInfo> DeviceScanner::scan_devices() {
    std::vector<DeviceInfo> accessible_devices;
    std::set<std::wstring> tested_paths;  // Avoid duplicates

    auto device_paths = enumerate_device_paths();

    for (const auto& path : device_paths) {
        if (tested_paths.count(path)) continue;
        tested_paths.insert(path);

        auto info = probe_device(path);
        if (info.has_value()) {
            // Try to resolve driver name
            auto driver = get_driver_for_device(path);
            if (driver) {
                info->driver_name = *driver;
            }
            accessible_devices.push_back(std::move(*info));
        }
    }

    return accessible_devices;
}

std::optional<DeviceInfo> DeviceScanner::probe_device(const std::wstring& device_path) {
    DeviceInfo info{};
    info.device_path = device_path;
    info.readable = false;
    info.writable = false;

    // Try different access patterns
    struct AccessTest {
        DWORD access;
        const char* name;
        bool* flag;
    };

    // Try with no access first (just open)
    HANDLE h = CreateFileW(
        device_path.c_str(),
        0,  // No access
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (h != INVALID_HANDLE_VALUE) {
        // Device is accessible
        CloseHandle(h);
    }

    // Try read access
    h = CreateFileW(
        device_path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (h != INVALID_HANDLE_VALUE) {
        info.readable = true;
        CloseHandle(h);
    } else {
        info.last_error = GetLastError();
    }

    // Try write access
    h = CreateFileW(
        device_path.c_str(),
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (h != INVALID_HANDLE_VALUE) {
        info.writable = true;
        CloseHandle(h);
    }

    // Try SYNCHRONIZE only (minimal access for DeviceIoControl)
    h = CreateFileW(
        device_path.c_str(),
        SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        0,
        nullptr
    );

    if (h != INVALID_HANDLE_VALUE) {
        info.readable = true;  // Can send IOCTLs
        CloseHandle(h);
    }

    // Return device info if we have any access
    if (info.readable || info.writable) {
        return info;
    }

    return std::nullopt;
}

std::vector<std::wstring> DeviceScanner::enumerate_device_paths() {
    std::vector<std::wstring> paths;

    // Method 1: Enumerate \\Device namespace using NT APIs
    NtHelpers nt;
    if (nt.is_initialized()) {
        // Enumerate \\Device directory
        auto devices = nt.enumerate_directory(L"\\Device");
        for (const auto& [name, type] : devices) {
            if (type == L"Device") {
                // Build DOS device path
                paths.push_back(L"\\\\.\\" + name);
            }
        }

        // Enumerate \\GLOBAL?? (DOS device namespace)
        auto dos_devices = nt.enumerate_directory(L"\\GLOBAL??");
        for (const auto& [name, type] : dos_devices) {
            if (type == L"SymbolicLink") {
                // Check if it points to a Device
                auto target = nt.resolve_symlink(L"\\GLOBAL??\\" + name);
                if (target && target->find(L"\\Device\\") == 0) {
                    paths.push_back(L"\\\\.\\" + name);
                }
            }
        }
    }

    // Method 2: Known device names for peripheral drivers
    static const std::vector<std::wstring> known_devices = {
        // ASUS
        L"\\\\.\\AsusIO", L"\\\\.\\AsusIO2", L"\\\\.\\AsusIO3",
        L"\\\\.\\ASUS_WMI", L"\\\\.\\AURA", L"\\\\.\\AURA_LED",
        L"\\\\.\\ACPILED", L"\\\\.\\AsusFanControl",
        L"\\\\.\\Asusgio2", L"\\\\.\\Asusgio3",
        L"\\\\.\\GLCKIo2", L"\\\\.\\GLCKIO2",

        // Corsair
        L"\\\\.\\CorsairLink", L"\\\\.\\CorsairLLAccess", L"\\\\.\\CorsairLLAccessMaster",
        L"\\\\.\\CorsairVBusDriver", L"\\\\.\\Corsair",

        // Razer
        L"\\\\.\\RazerDeveloperEndpoint", L"\\\\.\\Razer", L"\\\\.\\RzDev",
        L"\\\\.\\RzControl", L"\\\\.\\RzChromaSDK",

        // Logitech
        L"\\\\.\\LogiLED", L"\\\\.\\LGS", L"\\\\.\\LGHUB",
        L"\\\\.\\LogiBRTLED", L"\\\\.\\Logitech",

        // SteelSeries
        L"\\\\.\\SteelEngine", L"\\\\.\\SteelSeries", L"\\\\.\\SteelEngineGlobal",
        L"\\\\.\\STEELSERIES_ENGINE",

        // NZXT
        L"\\\\.\\NZXT", L"\\\\.\\NZXTDevice", L"\\\\.\\NZXTCAM",
        L"\\\\.\\NZXTKraken", L"\\\\.\\NZXTGrid",

        // MSI
        L"\\\\.\\NTIOLib", L"\\\\.\\NTIOLib_", L"\\\\.\\RTCore",
        L"\\\\.\\RTCore64", L"\\\\.\\MysticLight", L"\\\\.\\MSI_WMI",
        L"\\\\.\\Dragon", L"\\\\.\\MSIAfterburner",

        // Gigabyte
        L"\\\\.\\GPCIDrv", L"\\\\.\\GPCIDrv64", L"\\\\.\\GIO",
        L"\\\\.\\GDRV", L"\\\\.\\RGBFusion", L"\\\\.\\GigabyteIO",

        // ASRock
        L"\\\\.\\AsrDrv", L"\\\\.\\AsrDrv101", L"\\\\.\\AsrDrv102", L"\\\\.\\AsrDrv103",
        L"\\\\.\\AsrDrv104", L"\\\\.\\AsrPolychromeRGB",

        // EVGA
        L"\\\\.\\EVGA", L"\\\\.\\EVGAPrecision", L"\\\\.\\EVGAPrecisionX",

        // System utilities
        L"\\\\.\\CPUZ", L"\\\\.\\CPUZ141", L"\\\\.\\CPUZ145", L"\\\\.\\CPUZ152",
        L"\\\\.\\GPU-Z", L"\\\\.\\GPUZDrv", L"\\\\.\\GPU-Z-Alpha",
        L"\\\\.\\AIDA64", L"\\\\.\\AIDA64Driver", L"\\\\.\\AIDA",
        L"\\\\.\\HWiNFO", L"\\\\.\\HWiNFO64", L"\\\\.\\HWiNFO64A",
        L"\\\\.\\HWINFO32", L"\\\\.\\Global\\HWiNFO",

        // Low-level I/O drivers (high risk)
        L"\\\\.\\WinRing0", L"\\\\.\\WinRing0_1", L"\\\\.\\WinRing0_1_2_0",
        L"\\\\.\\WinIo", L"\\\\.\\WinIo32", L"\\\\.\\WinIo64",
        L"\\\\.\\PhysicalMemory", L"\\\\.\\physicalmemory",
        L"\\\\.\\GIO", L"\\\\.\\DirectIO", L"\\\\.\\inpout32",
        L"\\\\.\\inpoutx64", L"\\\\.\\TVicPort", L"\\\\.\\IOPM",

        // RGB controllers
        L"\\\\.\\OpenRGB", L"\\\\.\\OpenRGBQMK", L"\\\\.\\SignalRGB",
        L"\\\\.\\RGBController", L"\\\\.\\LightingService",

        // ENE (common in many boards)
        L"\\\\.\\EneIo", L"\\\\.\\ENE_IO", L"\\\\.\\EneIo64",
        L"\\\\.\\EneSmBus", L"\\\\.\\EneTechIo", L"\\\\.\\EneKb",

        // Realtek audio
        L"\\\\.\\RtkAudioSrv", L"\\\\.\\RTKDevCtrl",

        // AMD
        L"\\\\.\\AMDLOG", L"\\\\.\\AMDRyzenMaster", L"\\\\.\\AMDRyzenMasterDriver",
        L"\\\\.\\ATILLK64", L"\\\\.\\ATIDFW64", L"\\\\.\\AmdPPM",

        // Intel
        L"\\\\.\\IntelMEI", L"\\\\.\\HECI", L"\\\\.\\pmxdrv",
        L"\\\\.\\Ixchariot", L"\\\\.\\IntelTurbo",

        // Cooler Master
        L"\\\\.\\CoolerMaster", L"\\\\.\\CMMK", L"\\\\.\\CMRGB",

        // Thermaltake
        L"\\\\.\\TtRGBPlus", L"\\\\.\\TtRiing", L"\\\\.\\TtDP",

        // EKWB
        L"\\\\.\\EKWB", L"\\\\.\\EKConnect",

        // Aqua Computer
        L"\\\\.\\AquaComputer", L"\\\\.\\Aquaero", L"\\\\.\\farbwerk",

        // Fan controllers
        L"\\\\.\\NbfcService", L"\\\\.\\fancontrol", L"\\\\.\\speedfan",
        L"\\\\.\\FanService",

        // Virtual devices / emulators
        L"\\\\.\\ViGEmBus", L"\\\\.\\ViGEmBus0", L"\\\\.\\ViGEmBus1",
        L"\\\\.\\VJoy", L"\\\\.\\vJoy", L"\\\\.\\VJoyDevice",
        L"\\\\.\\ScpVBus", L"\\\\.\\Nefarius",
        L"\\\\.\\TBoxDrv", L"\\\\.\\AndroidTbox", L"\\\\.\\TBox",

        // Audio virtual devices
        L"\\\\.\\SteelSeriesSonar", L"\\\\.\\Sonar", L"\\\\.\\SonarVAD",
        L"\\\\.\\SteelSeries-Sonar-VAD", L"\\\\.\\VirtualAudio",

        // NVIDIA control
        L"\\\\.\\NvidiaSmi", L"\\\\.\\Nvsmi", L"\\\\.\\NvControl",
        L"\\\\.\\NVAPI", L"\\\\.\\NvDef", L"\\\\.\\NvAdminDevice",

        // Hypervisors/virtualization
        L"\\\\.\\VBoxDrv", L"\\\\.\\VBoxNetAdp", L"\\\\.\\VBoxUSBMon",
        L"\\\\.\\vmci", L"\\\\.\\VMwareVMCI",

        // Security software (often vulnerable)
        L"\\\\.\\ZemanaAntiMalware", L"\\\\.\\MalwareFox",

        // Overclocking
        L"\\\\.\\ThrottleStop", L"\\\\.\\Intel_XTU",

        // Misc
        L"\\\\.\\SMBIOS", L"\\\\.\\ACPI", L"\\\\.\\DMI",
        L"\\\\.\\EFI", L"\\\\.\\UEFI", L"\\\\.\\SecureBoot",
    };

    for (const auto& dev : known_devices) {
        paths.push_back(dev);
    }

    // Method 3: Try numbered variants
    static const std::vector<std::wstring> numbered_bases = {
        L"\\\\.\\PhysicalDrive",
        L"\\\\.\\HarddiskVolume",
        L"\\\\.\\Harddisk",
        L"\\\\.\\CdRom",
        L"\\\\.\\Tape",
        L"\\\\.\\USBSTOR#",
    };

    for (const auto& base : numbered_bases) {
        for (int i = 0; i <= 9; ++i) {
            paths.push_back(base + std::to_wstring(i));
        }
    }

    // Method 4: COM ports and LPT
    for (int i = 1; i <= 16; ++i) {
        paths.push_back(L"\\\\.\\COM" + std::to_wstring(i));
        paths.push_back(L"\\\\.\\LPT" + std::to_wstring(i));
    }

    // Method 5: Generate device names from common driver name patterns
    // Many drivers create devices named similarly to their .sys name
    static const std::vector<std::wstring> driver_derived = {
        // Strip .sys and try as device name
        L"\\\\.\\nvlddmkm", L"\\\\.\\nvlddmkm0",
        L"\\\\.\\ViGEmBus", L"\\\\.\\vigem",
        L"\\\\.\\TBoxDrv", L"\\\\.\\TBox",
        L"\\\\.\\rtwlane", L"\\\\.\\rtl",
        L"\\\\.\\SteelSeries", L"\\\\.\\SSEngine",
        L"\\\\.\\gameflt", L"\\\\.\\GameFilter",
        // Common Global prefixes
        L"\\\\.\\Global\\GLOBALROOT\\Device\\00000001",
        L"\\\\.\\GLOBALROOT\\Device\\ViGEmBus",
    };

    for (const auto& dev : driver_derived) {
        paths.push_back(dev);
    }

    // Method 6: Registry-based enumeration (dynamic, system-specific)
    RegistryScanner reg_scanner;

    // Get DOS devices from QueryDosDevice
    auto dos_devices = reg_scanner.enumerate_dos_devices();
    for (const auto& dev : dos_devices) {
        paths.push_back(dev);
    }

    // Get kernel services and try their service names as device paths
    auto kernel_services = reg_scanner.enumerate_kernel_services();
    for (const auto& svc : kernel_services) {
        if (!svc.device_path.empty()) {
            paths.push_back(svc.device_path);
        }
        // Also try variations
        paths.push_back(L"\\\\.\\" + svc.service_name + L"0");
        paths.push_back(L"\\\\.\\Global\\" + svc.service_name);
    }

    // Get device interfaces from registry
    auto interfaces = reg_scanner.enumerate_device_interfaces();
    for (const auto& iface : interfaces) {
        paths.push_back(iface);
    }

    // Method 7: SetupAPI-based enumeration
    SetupApiScanner setup_scanner;

    // Get all device interfaces via SetupAPI
    auto setup_interfaces = setup_scanner.enumerate_device_interfaces();
    for (const auto& iface : setup_interfaces) {
        paths.push_back(iface);
    }

    // Get all devices
    auto all_devices = setup_scanner.enumerate_all_devices();
    for (const auto& dev : all_devices) {
        paths.push_back(dev);
    }

    return paths;
}

} // namespace ds
