#include "driver_sight.hpp"
#include "driver_enumerator.hpp"
#include "device_scanner.hpp"
#include "ioctl_fuzzer.hpp"
#include "memory_verifier.hpp"
#include "report_generator.hpp"

#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <string>
#include <map>
#include <algorithm>

std::string ws2s(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, str.data(), size, nullptr, nullptr);
    return str;
}

void print_banner() {
    std::cout << "\n";
    std::cout << "  ____       _                 ____  _       _     _   \n";
    std::cout << " |  _ \\ _ __(_)_   _____ _ __ / ___|(_) __ _| |__ | |_ \n";
    std::cout << " | | | | '__| \\ \\ / / _ \\ '__| \\___ \\| |/ _` | '_ \\| __|\n";
    std::cout << " | |_| | |  | |\\ V /  __/ |   ___) | | (_| | | | | |_ \n";
    std::cout << " |____/|_|  |_| \\_/ \\___|_|  |____/|_|\\__, |_| |_|\\__|\n";
    std::cout << "                                      |___/  v2.0     \n";
    std::cout << "\n";
    std::cout << "  Kernel Driver IOCTL Vulnerability Scanner\n";
    std::cout << "  For Defensive Security Research Only\n";
    std::cout << "\n";
}

void print_usage(const char* program) {
    std::cout << "Usage: " << program << " [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  --scan             Comprehensive scan for accessible devices\n";
    std::cout << "  --fuzz <device>    Fuzz a specific device path\n";
    std::cout << "  --drivers          List third-party kernel drivers\n";
    std::cout << "  --all-drivers      List all loaded kernel drivers\n";
    std::cout << "\n";
    std::cout << "Fuzzing Options:\n";
    std::cout << "  --safe             Conservative: fewer tests, skip METHOD_NEITHER\n";
    std::cout << "  --aggressive       Full coverage: all methods, large buffers\n";
    std::cout << "\n";
    std::cout << "General Options:\n";
    std::cout << "  --json <file>      Output results to JSON file\n";
    std::cout << "  --verbose          Show detailed output\n";
    std::cout << "  --help             Show this help message\n";
    std::cout << "\n";
    std::cout << "Examples:\n";
    std::cout << "  DriverSight --scan\n";
    std::cout << "  DriverSight --fuzz \\\\.\\NvAdminDevice --safe\n";
    std::cout << "  DriverSight --fuzz \\\\.\\AsusIO --aggressive --json results.json\n";
    std::cout << "\n";
    std::cout << "Safety Features:\n";
    std::cout << "  - SEH exception handling prevents crashes\n";
    std::cout << "  - Rate limiting avoids driver overload\n";
    std::cout << "  - Health checks detect unstable devices\n";
    std::cout << "  - Auto-skip after repeated errors\n";
    std::cout << "\n";
    std::cout << "WARNING: Run in a Virtual Machine for aggressive fuzzing!\n";
}

std::string categorize_device(const std::wstring& path, const std::wstring& driver) {
    std::wstring lower = path + driver;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

    if (lower.find(L"nvidia") != std::wstring::npos || lower.find(L"nvld") != std::wstring::npos ||
        lower.find(L"nvadmin") != std::wstring::npos || lower.find(L"amd") != std::wstring::npos ||
        lower.find(L"display") != std::wstring::npos || lower.find(L"dxg") != std::wstring::npos)
        return "GPU/Display";

    if (lower.find(L"hid") != std::wstring::npos || lower.find(L"razer") != std::wstring::npos ||
        lower.find(L"corsair") != std::wstring::npos || lower.find(L"steelseries") != std::wstring::npos ||
        lower.find(L"logitech") != std::wstring::npos || lower.find(L"1532") != std::wstring::npos)
        return "HID/Peripheral";

    if (lower.find(L"usb") != std::wstring::npos)
        return "USB";

    if (lower.find(L"disk") != std::wstring::npos || lower.find(L"volume") != std::wstring::npos ||
        lower.find(L"storage") != std::wstring::npos || lower.find(L"scsi") != std::wstring::npos ||
        lower.find(L"physicaldrive") != std::wstring::npos)
        return "Storage";

    if (lower.find(L"bth") != std::wstring::npos || lower.find(L"bluetooth") != std::wstring::npos)
        return "Bluetooth";

    if (lower.find(L"wifi") != std::wstring::npos || lower.find(L"wlan") != std::wstring::npos ||
        lower.find(L"realtek") != std::wstring::npos || lower.find(L"ndis") != std::wstring::npos ||
        lower.find(L"tcp") != std::wstring::npos || lower.find(L"net") != std::wstring::npos)
        return "Network";

    if (lower.find(L"acpi") != std::wstring::npos || lower.find(L"thermal") != std::wstring::npos ||
        lower.find(L"pnp") != std::wstring::npos)
        return "ACPI/Power";

    if (lower.find(L"audio") != std::wstring::npos || lower.find(L"sound") != std::wstring::npos ||
        lower.find(L"sonar") != std::wstring::npos)
        return "Audio";

    return "Other";
}

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    print_banner();

    if (argc < 2) {
        print_usage("DriverSight");
        return 0;
    }

    std::wstring command = argv[1];
    ds::ReportGenerator report;
    bool verbose = false;
    std::wstring json_output;

    // Parse global options
    for (int i = 2; i < argc; ++i) {
        if (std::wstring(argv[i]) == L"--verbose") verbose = true;
        if (std::wstring(argv[i]) == L"--json" && i + 1 < argc) {
            json_output = argv[++i];
        }
    }

    if (command == L"--help" || command == L"-h") {
        print_usage("DriverSight");
        return 0;
    }

    if (command == L"--drivers" || command == L"--all-drivers") {
        std::cout << "[*] Enumerating loaded kernel drivers...\n\n";

        ds::DriverEnumerator enumerator;
        auto all_drivers = enumerator.enumerate_drivers();

        std::vector<ds::DriverInfo> drivers;
        if (command == L"--all-drivers") {
            drivers = all_drivers;
        } else {
            drivers = enumerator.filter_third_party(all_drivers);
        }

        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| LOADED KERNEL DRIVERS";
        if (command == L"--drivers") std::cout << " (Third-party only)";
        std::cout << std::string(command == L"--drivers" ? 35 : 53, ' ') << "|\n";
        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| Count: " << drivers.size() << std::string(68 - std::to_string(drivers.size()).length(), ' ') << "|\n";
        std::cout << "+----------------------------------------------------------------------------+\n";

        for (const auto& driver : drivers) {
            std::string name = ws2s(driver.name);
            if (name.length() > 30) name = name.substr(0, 27) + "...";

            std::cout << std::format("| {:016X} | {:<30} |\n",
                reinterpret_cast<uintptr_t>(driver.base_address), name);

            if (verbose) {
                std::string path = ws2s(driver.path);
                if (path.length() > 70) path = "..." + path.substr(path.length() - 67);
                std::cout << "|                    | " << path << "\n";
            }
            report.add_driver(driver);
        }
        std::cout << "+----------------------------------------------------------------------------+\n";

        return 0;
    }

    if (command == L"--scan" || command == L"--scan-quick") {
        // Check if running as admin
        BOOL is_admin = FALSE;
        SID_IDENTIFIER_AUTHORITY nt_auth = SECURITY_NT_AUTHORITY;
        PSID admin_group = nullptr;
        if (AllocateAndInitializeSid(&nt_auth, 2, SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &admin_group)) {
            CheckTokenMembership(nullptr, admin_group, &is_admin);
            FreeSid(admin_group);
        }

        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| DEVICE SCAN                                                                |\n";
        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| Privilege Level: " << (is_admin ? "Administrator" : "Standard User")
                  << std::string(is_admin ? 43 : 44, ' ') << "|\n";
        if (!is_admin) {
            std::cout << "| TIP: Run as Administrator for full NT object enumeration                 |\n";
        }
        std::cout << "+----------------------------------------------------------------------------+\n\n";

        // First show loaded third-party drivers
        ds::DriverEnumerator enumerator;
        auto all_drivers = enumerator.enumerate_drivers();
        auto third_party = enumerator.filter_third_party(all_drivers);

        if (!third_party.empty()) {
            std::cout << "[*] Third-Party Drivers Loaded: " << third_party.size() << "\n";
            for (const auto& drv : third_party) {
                std::cout << "    - " << ws2s(drv.name) << "\n";
            }
            std::cout << "\n";
        }

        std::cout << "[*] Scanning devices...\n";

        ds::DeviceScanner scanner;
        auto devices = scanner.scan_devices();

        if (devices.empty()) {
            std::cout << "\n[!] No accessible device objects found.\n";
            return 0;
        }

        // Categorize devices
        std::map<std::string, std::vector<ds::DeviceInfo>> categorized;
        for (const auto& dev : devices) {
            std::string cat = categorize_device(dev.device_path, dev.driver_name);
            categorized[cat].push_back(dev);
            report.add_device(dev);
        }

        std::cout << "\n[+] Found " << devices.size() << " accessible devices\n\n";

        // Print by category
        for (const auto& [category, devs] : categorized) {
            std::cout << "+-- " << category << " (" << devs.size() << ") ";
            std::cout << std::string(70 - category.length() - std::to_string(devs.size()).length(), '-') << "+\n";

            for (const auto& dev : devs) {
                std::string path = ws2s(dev.device_path);
                std::string driver = ws2s(dev.driver_name);

                // Truncate long paths for display
                if (path.length() > 52) {
                    path = path.substr(0, 49) + "...";
                }
                if (driver.length() > 24) {
                    driver = driver.substr(0, 21) + "...";
                }

                std::cout << "| [" << (dev.readable ? "R" : "-") << (dev.writable ? "W" : "-") << "] ";
                std::cout << std::left << std::setw(52) << path << " -> " << driver << "\n";
            }
            std::cout << "\n";
        }

        if (!json_output.empty()) {
            report.save_to_file(ws2s(json_output));
            std::cout << "[*] Results saved to: " << ws2s(json_output) << "\n";
        }

        return 0;
    }

    if (command == L"--fuzz") {
        if (argc < 3) {
            std::cout << "[!] Error: --fuzz requires a device path\n";
            std::cout << "    Example: --fuzz \\\\.\\NvAdminDevice\n";
            return 1;
        }

        std::wstring device_path = argv[2];

        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| IOCTL FUZZING                                                              |\n";
        std::cout << "+----------------------------------------------------------------------------+\n";
        std::cout << "| Target: " << ws2s(device_path) << "\n";
        std::cout << "+----------------------------------------------------------------------------+\n\n";

        std::cout << "[*] Attempting to open device...\n";

        HANDLE device = CreateFileW(
            device_path.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            0,
            nullptr
        );

        if (device == INVALID_HANDLE_VALUE) {
            DWORD err = GetLastError();
            std::cout << std::format("[!] Failed to open device. Error: {} (0x{:08X})\n", err, err);
            if (err == 5) std::cout << "    Access denied - try running as Administrator\n";
            if (err == 2) std::cout << "    Device not found - verify the path\n";
            return 1;
        }

        std::cout << "[+] Device opened successfully!\n";

        // Parse fuzz mode
        ds::FuzzMode fuzz_mode = ds::FuzzMode::Normal;
        for (int i = 3; i < argc; ++i) {
            std::wstring arg = argv[i];
            if (arg == L"--safe") fuzz_mode = ds::FuzzMode::Safe;
            else if (arg == L"--aggressive") fuzz_mode = ds::FuzzMode::Aggressive;
        }

        std::cout << "[*] Starting IOCTL fuzzing (";
        switch (fuzz_mode) {
            case ds::FuzzMode::Safe: std::cout << "SAFE mode"; break;
            case ds::FuzzMode::Normal: std::cout << "NORMAL mode"; break;
            case ds::FuzzMode::Aggressive: std::cout << "AGGRESSIVE mode"; break;
        }
        std::cout << ")...\n";
        std::cout << "    Press Ctrl+C to stop gracefully\n\n";

        ds::FuzzConfig config;
        config.mode = fuzz_mode;
        ds::IoctlFuzzer fuzzer(config);

        std::string current_phase = "Probe";

        fuzzer.set_progress_callback([&current_phase](const std::wstring&, DWORD ioctl,
                                         size_t current, size_t total, ds::FuzzPhase phase) {
            static ds::FuzzPhase last_phase = ds::FuzzPhase::Probe;

            if (phase != last_phase) {
                last_phase = phase;
                switch (phase) {
                    case ds::FuzzPhase::Probe: current_phase = "Probe"; break;
                    case ds::FuzzPhase::Enumerate: current_phase = "Enum"; break;
                    case ds::FuzzPhase::Analyze: current_phase = "Analyze"; break;
                }
                std::cout << "\n[*] Phase: " << current_phase << "\n";
            }

            if (total > 0 && current % 50 == 0) {
                int pct = static_cast<int>(current * 100 / total);
                int bars = pct / 5;
                std::cout << "\r    [";
                for (int i = 0; i < 20; ++i) {
                    std::cout << (i < bars ? "=" : " ");
                }
                std::cout << std::format("] {:3}% IOCTL:0x{:08X}", pct, ioctl);
                std::cout.flush();
            }
        });

        auto results = fuzzer.fuzz_device(device, device_path);
        std::cout << "\n\n";

        // Print stats
        const auto& stats = fuzzer.get_stats();
        std::cout << "+-- FUZZ STATISTICS ---------------------------------------------------------+\n";
        std::cout << std::format("| IOCTLs Tested: {:6}  Successful: {:6}  Exceptions: {:4}           |\n",
            stats.total_ioctls_tested, stats.successful_ioctls, stats.exceptions_caught);
        std::cout << std::format("| Access Denied: {:6}  Timeouts: {:6}    Other Errors: {:4}          |\n",
            stats.access_denied, stats.timeouts, stats.other_errors);
        std::cout << std::format("| Elapsed: {:5}ms                                                       |\n",
            stats.elapsed.count());
        std::cout << "+----------------------------------------------------------------------------+\n\n";

        std::cout << "[+] Found " << results.size() << " interesting IOCTLs.\n";

        if (!results.empty()) {
            std::cout << "[*] Verifying vulnerability patterns...\n\n";
        }

        // Verify vulnerabilities
        ds::MemoryVerifier verifier;
        auto vulns = verifier.verify_vulnerabilities(device, device_path, L"Unknown", results);

        for (const auto& vuln : vulns) {
            report.add_vulnerability(vuln);
        }

        CloseHandle(device);

        // Output report
        report.print_console();

        if (!json_output.empty()) {
            report.save_to_file(ws2s(json_output));
            std::cout << "\n[*] JSON report saved to: " << ws2s(json_output) << "\n";
        }

        return 0;
    }

    std::cout << "[!] Unknown command: " << ws2s(command) << "\n";
    print_usage("DriverSight");
    return 1;
}
