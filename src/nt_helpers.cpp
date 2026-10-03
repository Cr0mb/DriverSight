#include "nt_helpers.hpp"
#include <setupapi.h>
#include <cfgmgr32.h>

#pragma comment(lib, "setupapi.lib")

namespace ds {

NtHelpers::NtHelpers() : ntdll_(nullptr), initialized_(false) {
    ntdll_ = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll_) {
        ntdll_ = LoadLibraryW(L"ntdll.dll");
    }

    if (!ntdll_) return;

    NtOpenDirectoryObject_ = reinterpret_cast<PNtOpenDirectoryObject>(
        GetProcAddress(ntdll_, "NtOpenDirectoryObject"));
    NtQueryDirectoryObject_ = reinterpret_cast<PNtQueryDirectoryObject>(
        GetProcAddress(ntdll_, "NtQueryDirectoryObject"));
    NtOpenSymbolicLinkObject_ = reinterpret_cast<PNtOpenSymbolicLinkObject>(
        GetProcAddress(ntdll_, "NtOpenSymbolicLinkObject"));
    NtQuerySymbolicLinkObject_ = reinterpret_cast<PNtQuerySymbolicLinkObject>(
        GetProcAddress(ntdll_, "NtQuerySymbolicLinkObject"));
    NtQueryObject_ = reinterpret_cast<PNtQueryObject>(
        GetProcAddress(ntdll_, "NtQueryObject"));

    initialized_ = NtOpenDirectoryObject_ && NtQueryDirectoryObject_ &&
                   NtOpenSymbolicLinkObject_ && NtQuerySymbolicLinkObject_ &&
                   NtQueryObject_;
}

NtHelpers::~NtHelpers() {
    // Don't free ntdll - it's always loaded
}

std::vector<std::pair<std::wstring, std::wstring>> NtHelpers::enumerate_directory(const std::wstring& path) {
    std::vector<std::pair<std::wstring, std::wstring>> results;

    if (!initialized_) return results;

    UNICODE_STRING dir_name;
    dir_name.Buffer = const_cast<PWSTR>(path.c_str());
    dir_name.Length = static_cast<USHORT>(path.length() * sizeof(WCHAR));
    dir_name.MaximumLength = dir_name.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &dir_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE dir_handle;
    NTSTATUS status = NtOpenDirectoryObject_(&dir_handle, DIRECTORY_QUERY, &obj_attr);

    if (status != 0) return results;

    std::vector<BYTE> buffer(8192);
    ULONG context = 0;
    ULONG return_length;
    BOOLEAN restart = TRUE;

    while (true) {
        status = NtQueryDirectoryObject_(
            dir_handle,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            FALSE,  // Return multiple entries
            restart,
            &context,
            &return_length
        );

        restart = FALSE;

        if (status != 0) break;

        auto* info = reinterpret_cast<POBJECT_DIRECTORY_INFORMATION>(buffer.data());

        while (info->Name.Buffer != nullptr) {
            std::wstring name(info->Name.Buffer, info->Name.Length / sizeof(WCHAR));
            std::wstring type(info->TypeName.Buffer, info->TypeName.Length / sizeof(WCHAR));
            results.emplace_back(name, type);
            ++info;
        }
    }

    CloseHandle(dir_handle);
    return results;
}

std::optional<std::wstring> NtHelpers::resolve_symlink(const std::wstring& link_path) {
    if (!initialized_) return std::nullopt;

    UNICODE_STRING link_name;
    link_name.Buffer = const_cast<PWSTR>(link_path.c_str());
    link_name.Length = static_cast<USHORT>(link_path.length() * sizeof(WCHAR));
    link_name.MaximumLength = link_name.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES obj_attr;
    InitializeObjectAttributes(&obj_attr, &link_name, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE link_handle;
    NTSTATUS status = NtOpenSymbolicLinkObject_(&link_handle, SYMBOLIC_LINK_QUERY, &obj_attr);

    if (status != 0) return std::nullopt;

    WCHAR target_buffer[512];
    UNICODE_STRING target;
    target.Buffer = target_buffer;
    target.Length = 0;
    target.MaximumLength = sizeof(target_buffer);

    ULONG return_length;
    status = NtQuerySymbolicLinkObject_(link_handle, &target, &return_length);

    CloseHandle(link_handle);

    if (status != 0) return std::nullopt;

    return std::wstring(target.Buffer, target.Length / sizeof(WCHAR));
}

std::optional<std::wstring> NtHelpers::get_object_name(HANDLE handle) {
    if (!initialized_) return std::nullopt;

    std::vector<BYTE> buffer(1024);
    ULONG return_length;

    NTSTATUS status = NtQueryObject_(
        handle,
        ObjectNameInformation,
        buffer.data(),
        static_cast<ULONG>(buffer.size()),
        &return_length
    );

    if (status != 0) return std::nullopt;

    auto* name_info = reinterpret_cast<POBJECT_NAME_INFORMATION>(buffer.data());
    if (name_info->Name.Buffer == nullptr) return std::nullopt;

    return std::wstring(name_info->Name.Buffer, name_info->Name.Length / sizeof(WCHAR));
}

std::optional<std::wstring> get_driver_for_device(const std::wstring& device_path) {
    std::wstring lower = device_path;
    for (auto& c : lower) c = towlower(c);

    // Comprehensive device-to-driver mapping
    static const struct { const wchar_t* pattern; const wchar_t* driver; } mappings[] = {
        // NVIDIA
        {L"nvld", L"nvlddmkm.sys"}, {L"nvidia", L"nvlddmkm.sys"}, {L"nvr0", L"nvlddmkm.sys"},
        {L"nvadmin", L"nvlddmkm.sys"}, {L"nvsmi", L"nvlddmkm.sys"}, {L"nvcontrol", L"nvlddmkm.sys"},
        // AMD
        {L"amd", L"amdkmdag.sys"}, {L"atillk", L"atillk64.sys"},
        // ASUS
        {L"asusio", L"AsIO2/AsIO3.sys"}, {L"asus_wmi", L"ASUS_WMI.sys"},
        {L"aura", L"AsusPbusDriver.sys"}, {L"glckio", L"GLCKIo2.sys"},
        // Corsair
        {L"corsair", L"CorsairLLAccess.sys"},
        // Razer (VID 1532)
        {L"razer", L"RzDev_*.sys"}, {L"rzdev", L"RzDev_*.sys"},
        {L"vid_1532", L"Razer HID (RzDev*.sys)"},
        // Logitech (VID 046D)
        {L"logiled", L"LGCoreTemp.sys"}, {L"lgs", L"LGS*.sys"},
        {L"vid_046d", L"Logitech (LGS*.sys)"},
        // SteelSeries
        {L"steelseries", L"SteelSeries*.sys"}, {L"steelengine", L"SteelSeriesEngine.sys"},
        // NZXT
        {L"nzxt", L"NZXT*.sys"},
        // MSI
        {L"ntiolib", L"NTIOLib.sys"}, {L"rtcore", L"RTCore.sys"}, {L"mysticlight", L"MysticLight.sys"},
        // Gigabyte
        {L"gpcid", L"GPCIDrv64.sys"}, {L"gio", L"gdrv.sys"}, {L"gdrv", L"gdrv.sys"},
        // ASRock
        {L"asrdrv", L"AsrDrv10*.sys"},
        // System utilities
        {L"cpuz", L"cpuz1*.sys"}, {L"gpu-z", L"GPUZDrv*.sys"}, {L"gpuz", L"GPUZDrv*.sys"},
        {L"aida", L"aida64drv.sys"}, {L"hwinfo", L"HWiNFO64A.sys"},
        // Low-level I/O
        {L"winring", L"WinRing0*.sys"}, {L"winio", L"WinIo*.sys"},
        {L"physicalmemory", L"(kernel)"}, {L"inpout", L"inpoutx64.sys"},
        // ENE (RGB)
        {L"eneio", L"EneIo64.sys"}, {L"ene_io", L"EneIo64.sys"},
        // Intel
        {L"intelmei", L"TeeDriverW10x64.sys"}, {L"heci", L"TeeDriverW10x64.sys"},
        // Virtual/Emulators
        {L"vigembus", L"ViGEmBus.sys"}, {L"vjoy", L"vjoy.sys"},
        // Storage
        {L"physicaldrive", L"disk.sys"}, {L"harddiskvolume", L"volmgr.sys"},
        {L"cdrom", L"cdrom.sys"}, {L"scsi#cdrom", L"cdrom.sys"}, {L"scsi#disk", L"disk.sys"},
        // USB vendor IDs
        {L"vid_054c", L"Sony (hidusb.sys)"},
        {L"vid_0bda", L"Realtek (rtwlane.sys)"},
        {L"vid_05e3", L"Genesys Logic USB Hub"},
        {L"vid_1ea7", L"Generic HID (hidusb.sys)"},
        {L"vid_2a7a", L"Generic HID (hidusb.sys)"},
        {L"vid_4c4a", L"Generic HID (hidusb.sys)"},
        // Common system devices
        {L"realtek_wifi", L"rtwlane.sys"},
        {L"wmidata", L"WMI Provider"},
        {L"tcp", L"tcpip.sys"}, {L"udp", L"tcpip.sys"},
        {L"ndisuio", L"ndisuio.sys"},
        {L"bthle", L"bthport.sys"}, {L"bthenum", L"bthport.sys"},
        {L"acpi#", L"ACPI.sys"},
        {L"display#", L"dxgkrnl.sys"},
        {L"root#system", L"System Device"},
        {L"root#display", L"Display Adapter"},
    };

    for (const auto& m : mappings) {
        if (lower.find(m.pattern) != std::wstring::npos) {
            return m.driver;
        }
    }

    // Extract device name from path as fallback
    size_t last_slash = device_path.rfind(L'\\');
    if (last_slash != std::wstring::npos && last_slash + 1 < device_path.length()) {
        return device_path.substr(last_slash + 1) + L" (device)";
    }

    return std::nullopt;
}

} // namespace ds
