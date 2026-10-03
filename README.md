# DriverSight

<p align="center">
  <img src="assets/logo.png" alt="DriverSight Logo" width="128" height="128">
</p>

<p align="center">
  <strong>Kernel Driver IOCTL Vulnerability Scanner for Windows</strong><br>
  <em>Defensive Security Research Tool</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/language-C%2B%2B20-orange" alt="Language">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/version-2.0.0-brightgreen" alt="Version">
</p>

---

## Overview

DriverSight is a comprehensive Windows kernel driver security auditing tool designed for defensive security research. It discovers accessible device objects, enumerates loaded drivers, and safely fuzzes IOCTL handlers to identify potential Local Privilege Escalation (LPE) vulnerabilities.

### Key Capabilities

- **Device Discovery**: 7 enumeration methods to find all accessible device objects
- **Driver Mapping**: Identifies which driver handles each device
- **IOCTL Fuzzing**: Safe, multi-phase fuzzing with SEH protection
- **Vulnerability Detection**: 13 vulnerability pattern categories
- **Detailed Reporting**: Console and JSON output formats

---

## Installation

### Prerequisites

- Windows 10/11 (x64)
- Visual Studio 2022 or Build Tools with C++20 support
- CMake 3.20+

### Build from Source

```powershell
git clone https://github.com/yourusername/DriverSight.git
cd DriverSight
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

The executable will be at `build/Release/DriverSight.exe`.

---

## Usage

### Quick Start

```powershell
# Scan for accessible devices
DriverSight.exe --scan

# List third-party drivers
DriverSight.exe --drivers

# Fuzz a specific device (safe mode)
DriverSight.exe --fuzz \\.\DeviceName --safe

# Full scan with JSON output
DriverSight.exe --fuzz \\.\DeviceName --json results.json
```

### Commands

| Command | Description |
|---------|-------------|
| `--scan` | Comprehensive scan for accessible device objects |
| `--fuzz <device>` | Fuzz a specific device path |
| `--drivers` | List third-party kernel drivers |
| `--all-drivers` | List all loaded kernel drivers |
| `--help` | Show help message |

### Fuzzing Options

| Option | Description |
|--------|-------------|
| `--safe` | Conservative mode: fewer tests, skip METHOD_NEITHER |
| `--aggressive` | Full coverage: all methods, large buffers |
| `--json <file>` | Export results to JSON file |

### Example Output

```
+-- GPU/Display (15) ---------------------------------------------------------+
| [RW] \\.\NvAdminDevice                             -> nvlddmkm.sys
| [RW] \\.\ROOT#DISPLAY#0000#{af779544-f4c3-4fc1...  -> dxgkrnl.sys

+-- HID/Peripheral (54) ------------------------------------------------------+
| [RW] \\.\HID#VID_1532&PID_0C00&MI_02#8&c94db43...  -> Razer HID (RzDev*.sys)
| [RW] \\.\USB#VID_054C&PID_09CC#5&919780d&0&8#{...  -> Sony (hidusb.sys)
```

---

## How It Works

### Device Discovery (7 Methods)

1. **NT Object Manager** - Enumerates `\\Device` and `\\GLOBAL??` namespaces
2. **Known Device Paths** - 200+ hardcoded paths for major hardware vendors
3. **Numbered Variants** - PhysicalDrive0-9, COM1-16, HarddiskVolume1-10
4. **Driver-Derived Names** - Probes device names based on loaded drivers
5. **Registry Scanner** - Queries kernel services from registry
6. **DOS Device Names** - Uses `QueryDosDevice()` for symbolic links
7. **SetupAPI** - Enumerates device interfaces via `SetupDiGetClassDevs()`

### Fuzzing Phases

```
Phase 1: PROBE    - Detect valid IOCTL device types
Phase 2: ENUMERATE - Find responding IOCTL codes
Phase 3: ANALYZE   - Deep test with various buffer sizes
```

### Vulnerability Detection Categories

| Category | Severity | Description |
|----------|----------|-------------|
| Physical Memory | 10/10 | MmMapIoSpace arbitrary physical read/write |
| CR3/Page Table | 10/10 | DirectoryTableBase exposure |
| Kernel Execution | 10/10 | Arbitrary code execution in ring 0 |
| Virtual Memory | 9/10 | MmCopyVirtualMemory cross-process access |
| Process Attach | 9/10 | KeStackAttachProcess primitives |
| MSR Access | 9/10 | RDMSR/WRMSR can disable SMEP/SMAP |
| MDL Manipulation | 8/10 | Memory Descriptor List abuse |
| METHOD_NEITHER | 8/10 | Unsafe IOCTL transfer method |
| PCI Config | 8/10 | PCI configuration space access |
| Port I/O | 7/10 | Direct IN/OUT instructions |
| Object Manipulation | 7/10 | Kernel handle/object access |
| Shared Section | 6/10 | Kernel-user shared memory |
| No Privilege Check | 6/10 | Missing caller validation |

---

## Safety Features

DriverSight is designed to minimize system instability during fuzzing:

- **SEH Exception Handling** - Catches access violations to prevent crashes
- **Rate Limiting** - Configurable delays between IOCTLs (default 5ms)
- **Health Checks** - Verifies device responsiveness every 50 IOCTLs
- **Auto-Skip** - Skips IOCTL ranges after consecutive errors
- **Dangerous IOCTL Filter** - Blocks known harmful patterns
- **Graceful Stop** - Ctrl+C stops fuzzing cleanly

### Fuzz Mode Comparison

| Mode | IOCTL Range | Buffer Sizes | METHOD_NEITHER | Risk |
|------|-------------|--------------|----------------|------|
| Safe | 64 codes | 0-128 bytes | Disabled | Low |
| Normal | 256 codes | 0-4KB | Enabled | Medium |
| Aggressive | 512 codes | 0-16KB | Enabled | High |

---

## Supported Hardware Vendors

DriverSight includes device path patterns for:

- **GPU**: NVIDIA, AMD, Intel
- **Motherboard**: ASUS, MSI, Gigabyte, ASRock
- **Peripherals**: Razer, Corsair, Logitech, SteelSeries, NZXT
- **System Utilities**: CPU-Z, GPU-Z, HWiNFO, AIDA64
- **RGB Controllers**: ENE, Aura Sync, Mystic Light
- **Virtual Devices**: ViGEmBus, vJoy

---

## JSON Report Format

```json
{
  "scan_info": {
    "tool": "DriverSight",
    "version": "2.0.0",
    "timestamp": "2026-10-03T12:00:00Z"
  },
  "summary": {
    "drivers_scanned": 18,
    "devices_accessible": 287,
    "vulnerabilities_found": 2,
    "critical": 1,
    "high": 1
  },
  "vulnerabilities": [
    {
      "driver": "example.sys",
      "device": "\\\\.\\ExampleDevice",
      "ioctl_code": "0x80002000",
      "type": "Arbitrary Kernel Read",
      "severity": 9,
      "description": "..."
    }
  ]
}
```

---

## Technical Details

### IOCTL Code Structure

```
31-16: Device Type (0x8000 = FILE_DEVICE_UNKNOWN)
15-14: Required Access
13-2:  Function Code
1-0:   Transfer Method (0=BUFFERED, 1=IN_DIRECT, 2=OUT_DIRECT, 3=NEITHER)
```

### Detection Patterns

DriverSight tests for common vulnerability primitives:

```cpp
// Physical memory read (MmMapIoSpace pattern)
struct PhysMemRequest { UINT64 physical_address; UINT32 size; };

// Virtual memory access (MmCopyVirtualMemory pattern)  
struct VirtMemRequest { UINT64 process_id; UINT64 address; UINT64 size; };

// MSR access pattern
struct MsrRequest { UINT32 msr_register; UINT64 value; UINT32 write; };
```

---

## Responsible Disclosure

If you discover vulnerabilities using DriverSight:

1. **Do not** publicly disclose without vendor coordination
2. Report to the hardware vendor's security team
3. Allow 90 days for patch development
4. Coordinate CVE assignment via [MITRE](https://cveform.mitre.org/)

---

## Legal Disclaimer

This tool is provided for **authorized security research only**. Users must:

- Have explicit permission to test target systems
- Comply with all applicable laws and regulations
- Use findings responsibly and ethically

The authors are not responsible for misuse or damage caused by this tool.

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### Areas for Contribution

- Additional device path patterns
- New vulnerability detection methods
- Platform support improvements
- Documentation enhancements

---

## License

MIT License - See [LICENSE](LICENSE) file for details.

---

## Acknowledgments

- Windows Internals community
- Security researchers who document driver vulnerabilities
- Open-source security tools that inspired this project

---

<p align="center">
  <sub>Built for defensive security research</sub>
</p>
