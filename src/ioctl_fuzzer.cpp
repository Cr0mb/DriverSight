#include "ioctl_fuzzer.hpp"
#include <thread>
#include <algorithm>
#include <set>

namespace {

// SEH wrapper - separate from C++ exception handling
struct SafeIoctlResult {
    BOOL success;
    DWORD bytes_returned;
    DWORD error_code;
    BOOL had_exception;
};

SafeIoctlResult safe_device_io_control(HANDLE device, DWORD code,
                                        void* in_buf, DWORD in_size,
                                        void* out_buf, DWORD out_size) {
    SafeIoctlResult result{};
    result.had_exception = FALSE;
    result.bytes_returned = 0;

    __try {
        result.success = DeviceIoControl(device, code, in_buf, in_size,
                                          out_buf, out_size, &result.bytes_returned, nullptr);
        result.error_code = result.success ? 0 : GetLastError();
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        result.had_exception = TRUE;
        result.success = FALSE;
        result.error_code = GetExceptionCode();
    }

    return result;
}

// Common device types used by third-party drivers
constexpr DWORD COMMON_DEVICE_TYPES[] = {
    0x8000,  // FILE_DEVICE_UNKNOWN (most common)
    0x8001, 0x8002, 0x8003, 0x8004, 0x8005,
    0x8010, 0x8020, 0x8030, 0x8040,
    0x9000, 0x9001, 0x9002,
    0xA000, 0xA001,
    0x22,    // FILE_DEVICE_KEYBOARD
    0x0F,    // FILE_DEVICE_VIDEO
    0x2A,    // FILE_DEVICE_BATTERY
    0x34,    // FILE_DEVICE_INFINIBAND
};

// Known dangerous IOCTL patterns (writes that could damage system)
constexpr DWORD DANGEROUS_PATTERNS[] = {
    0x9C402428,  // Known MSI write pattern
    0x80002048,  // Physical memory write pattern
};

} // anonymous namespace

namespace ds {

IoctlFuzzer::IoctlFuzzer(const FuzzConfig& config) : config_(config) {
    prepare_buffers();
}

void IoctlFuzzer::set_progress_callback(ProgressCallback cb) {
    progress_cb_ = std::move(cb);
}

void IoctlFuzzer::set_result_callback(ResultCallback cb) {
    result_cb_ = std::move(cb);
}

void IoctlFuzzer::request_stop() {
    stop_requested_ = true;
}

void IoctlFuzzer::prepare_buffers() {
    // Adjust buffer sizes based on mode
    if (config_.mode == FuzzMode::Safe) {
        config_.buffer_sizes = {0, 8, 32, 64, 128};
        config_.test_method_neither = false;
    } else if (config_.mode == FuzzMode::Aggressive) {
        config_.buffer_sizes = {0, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 4096, 16384};
    }

    buffers_.clear();
    for (size_t size : config_.buffer_sizes) {
        buffers_.emplace_back(size > 0 ? size : 1);
    }

    health_check_buf_.resize(64);
}

void IoctlFuzzer::fill_buffer_pattern(BYTE* buf, size_t size, DWORD ioctl) {
    if (!buf || size == 0) return;

    // Fill with recognizable pattern for crash analysis
    // Pattern: [IOCTL code bytes] [offset] [0xCC padding]
    for (size_t i = 0; i < size; ++i) {
        if (i < 4) {
            buf[i] = (ioctl >> (i * 8)) & 0xFF;
        } else if (i < 8) {
            buf[i] = static_cast<BYTE>(i & 0xFF);
        } else {
            buf[i] = 0xCC;  // INT3 - recognizable in crash dumps
        }
    }

    // First 8 bytes as zeros is safer for structure-based IOCTLs
    if (size >= 16) {
        memset(buf, 0, 8);
    }
}

bool IoctlFuzzer::is_dangerous_ioctl(DWORD code) const {
    // Check METHOD_NEITHER if disabled
    if (!config_.test_method_neither && (code & 0x3) == 3) {
        return true;
    }

    // Check known dangerous patterns
    for (DWORD pattern : DANGEROUS_PATTERNS) {
        if (code == pattern) return true;
    }

    return false;
}

bool IoctlFuzzer::check_device_health(HANDLE device) {
    // Try a simple query operation to verify device still responds
    DWORD bytes = 0;

    // Most drivers respond to invalid IOCTL with ERROR_INVALID_FUNCTION
    // If we get something else (timeout, access violation), device may be unstable
    auto result = safe_device_io_control(device, 0x00000000,
                                          health_check_buf_.data(), 0,
                                          health_check_buf_.data(),
                                          static_cast<DWORD>(health_check_buf_.size()));

    if (result.had_exception) {
        return false;  // Device is in bad state
    }

    // Check if handle is still valid
    DWORD flags;
    if (!GetHandleInformation(device, &flags)) {
        return false;
    }

    return true;
}

void IoctlFuzzer::apply_rate_limit() {
    if (config_.delay_between_ms > 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.delay_between_ms));
    }
}

void IoctlFuzzer::categorize_error(IoctlResult& result) {
    switch (result.last_error) {
        case ERROR_SUCCESS:
            ++stats_.successful_ioctls;
            break;
        case ERROR_INVALID_FUNCTION:
        case ERROR_NOT_SUPPORTED:
        case ERROR_INVALID_PARAMETER:
            ++stats_.invalid_function;
            break;
        case ERROR_ACCESS_DENIED:
        case ERROR_PRIVILEGE_NOT_HELD:
            ++stats_.access_denied;
            break;
        case ERROR_TIMEOUT:
        case WAIT_TIMEOUT:
            ++stats_.timeouts;
            break;
        case ERROR_EXCEPTION_IN_SERVICE:
        case STATUS_ACCESS_VIOLATION:
            ++stats_.exceptions_caught;
            break;
        default:
            ++stats_.other_errors;
            break;
    }
}

std::vector<DWORD> IoctlFuzzer::probe_ioctl_ranges(HANDLE device) {
    std::set<DWORD> valid_types;

    // If ranges specified in config, use those
    if (config_.device_type_start != 0 || config_.device_type_end != 0) {
        for (DWORD t = config_.device_type_start; t <= config_.device_type_end; ++t) {
            valid_types.insert(t);
        }
        return {valid_types.begin(), valid_types.end()};
    }

    // Probe common device types
    std::vector<BYTE> probe_buf(64, 0);

    for (DWORD dev_type : COMMON_DEVICE_TYPES) {
        if (stop_requested_) break;

        // Try a few function codes to see if device responds
        bool found_response = false;
        for (DWORD func = 0x800; func <= 0x810 && !found_response; ++func) {
            DWORD code = make_ioctl(dev_type, func, 0, 0);

            auto result = safe_device_io_control(device, code,
                                                  probe_buf.data(),
                                                  static_cast<DWORD>(probe_buf.size()),
                                                  probe_buf.data(),
                                                  static_cast<DWORD>(probe_buf.size()));

            // Any response other than "invalid function" suggests this device type is used
            if (!result.had_exception &&
                result.error_code != ERROR_INVALID_FUNCTION &&
                result.error_code != ERROR_NOT_SUPPORTED) {
                valid_types.insert(dev_type);
                found_response = true;
            }
        }
    }

    // If nothing found, default to FILE_DEVICE_UNKNOWN
    if (valid_types.empty()) {
        valid_types.insert(0x8000);
    }

    return {valid_types.begin(), valid_types.end()};
}

std::vector<IoctlResult> IoctlFuzzer::enumerate_ioctls(HANDLE device,
                                                         const std::vector<DWORD>& device_types) {
    std::vector<IoctlResult> interesting_results;

    DWORD func_start = config_.function_start > 0 ? config_.function_start : 0x800;
    DWORD func_end = config_.function_end > 0 ? config_.function_end : 0x900;

    // Adjust range for mode
    if (config_.mode == FuzzMode::Safe) {
        func_end = std::min(func_end, func_start + 64);
    } else if (config_.mode == FuzzMode::Aggressive) {
        func_end = std::max(func_end, func_start + 512);
    }

    size_t total = device_types.size() * (func_end - func_start + 1) * 4;
    size_t current = 0;

    std::vector<BYTE> test_buf(64, 0);

    for (DWORD dev_type : device_types) {
        if (stop_requested_) break;

        consecutive_errors_ = 0;

        for (DWORD func = func_start; func <= func_end; ++func) {
            if (stop_requested_) break;

            // Check for too many consecutive errors
            if (config_.stop_on_repeated_errors &&
                consecutive_errors_ >= config_.max_consecutive_errors) {
                break;
            }

            for (DWORD method = 0; method <= 3; ++method) {
                if (stop_requested_) break;

                // Skip METHOD_NEITHER in safe mode
                if (method == 3 && !config_.test_method_neither) {
                    ++current;
                    continue;
                }

                DWORD code = make_ioctl(dev_type, func, method, 0);

                if (is_dangerous_ioctl(code)) {
                    ++current;
                    continue;
                }

                if (progress_cb_) {
                    progress_cb_(L"", code, current, total, FuzzPhase::Enumerate);
                }
                ++current;

                auto result = try_ioctl_safe(device, code,
                                             test_buf.data(), static_cast<DWORD>(test_buf.size()),
                                             test_buf.data(), static_cast<DWORD>(test_buf.size()));

                ++stats_.total_ioctls_tested;
                categorize_error(result);

                // Track consecutive errors
                if (result.success) {
                    consecutive_errors_ = 0;
                    last_successful_ioctl_ = code;
                } else if (result.last_error != ERROR_INVALID_FUNCTION) {
                    ++consecutive_errors_;
                }

                // Record interesting results
                if (result.success ||
                    (result.last_error != ERROR_INVALID_FUNCTION &&
                     result.last_error != ERROR_NOT_SUPPORTED)) {
                    interesting_results.push_back(result);

                    if (result_cb_) {
                        result_cb_(result);
                    }
                }

                // Periodic health check
                if (stats_.total_ioctls_tested % config_.health_check_interval == 0) {
                    if (!check_device_health(device)) {
                        // Device may be unstable, pause briefly
                        std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    }
                }

                apply_rate_limit();
            }
        }
    }

    return interesting_results;
}

std::vector<IoctlResult> IoctlFuzzer::analyze_ioctls(HANDLE device,
                                                       const std::vector<IoctlResult>& candidates) {
    std::vector<IoctlResult> detailed_results;

    size_t total = candidates.size() * buffers_.size();
    size_t current = 0;

    for (const auto& candidate : candidates) {
        if (stop_requested_) break;

        DWORD code = candidate.ioctl_code;

        // Test with various buffer sizes
        for (size_t i = 0; i < buffers_.size(); ++i) {
            if (stop_requested_) break;

            auto& buf = buffers_[i];
            size_t buf_size = config_.buffer_sizes[i];

            fill_buffer_pattern(buf.data(), buf.size(), code);

            if (progress_cb_) {
                progress_cb_(L"", code, current, total, FuzzPhase::Analyze);
            }
            ++current;

            auto result = try_ioctl_safe(device, code,
                                         buf.data(), static_cast<DWORD>(buf_size),
                                         buf.data(), static_cast<DWORD>(buf.size()));

            ++stats_.total_ioctls_tested;
            categorize_error(result);

            if (result.success) {
                detailed_results.push_back(result);

                if (result_cb_) {
                    result_cb_(result);
                }
            }

            apply_rate_limit();
        }

        // Test with null buffers
        if (config_.test_null_buffers) {
            auto result = try_ioctl_safe(device, code, nullptr, 0, nullptr, 0);
            ++stats_.total_ioctls_tested;
            categorize_error(result);

            if (result.success) {
                detailed_results.push_back(result);
            }
        }
    }

    return detailed_results;
}

IoctlResult IoctlFuzzer::try_ioctl_safe(HANDLE device, DWORD code,
                                         void* in_buf, DWORD in_size,
                                         void* out_buf, DWORD out_size) {
    IoctlResult result{};
    result.ioctl_code = code;
    result.success = false;

    static const char* method_names[] = {"BUFFERED", "IN_DIRECT", "OUT_DIRECT", "NEITHER"};
    result.method_type = method_names[code & 0x3];

    auto ioctl_result = safe_device_io_control(device, code, in_buf, in_size,
                                                out_buf, out_size);

    if (ioctl_result.had_exception) {
        result.success = false;
        result.last_error = ERROR_EXCEPTION_IN_SERVICE;
        ++stats_.exceptions_caught;

        // If configured, skip this function range after exception
        if (config_.skip_on_exception) {
            consecutive_errors_ = config_.max_consecutive_errors;
        }
    } else {
        result.success = (ioctl_result.success != FALSE);
        result.bytes_returned = ioctl_result.bytes_returned;
        result.last_error = ioctl_result.error_code;
    }

    return result;
}

IoctlResult IoctlFuzzer::try_ioctl(HANDLE device, DWORD code,
                                    void* in_buf, DWORD in_size,
                                    void* out_buf, DWORD out_size) {
    return try_ioctl_safe(device, code, in_buf, in_size, out_buf, out_size);
}

std::vector<IoctlResult> IoctlFuzzer::fuzz_device(HANDLE device, const std::wstring& device_path) {
    auto start_time = std::chrono::steady_clock::now();
    stop_requested_ = false;
    stats_ = FuzzStats{};

    // Phase 1: Probe for valid IOCTL ranges
    if (progress_cb_) {
        progress_cb_(device_path, 0, 0, 1, FuzzPhase::Probe);
    }

    auto device_types = probe_ioctl_ranges(device);

    if (stop_requested_) {
        return {};
    }

    // Phase 2: Enumerate responding IOCTLs
    auto candidates = enumerate_ioctls(device, device_types);

    if (stop_requested_ || candidates.empty()) {
        auto end_time = std::chrono::steady_clock::now();
        stats_.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        return candidates;
    }

    // Phase 3: Deep analysis of interesting IOCTLs (if not in safe mode)
    std::vector<IoctlResult> final_results;

    if (config_.mode != FuzzMode::Safe) {
        final_results = analyze_ioctls(device, candidates);

        // Merge with enumeration results (avoid duplicates)
        std::set<DWORD> seen;
        for (const auto& r : final_results) {
            seen.insert(r.ioctl_code);
        }
        for (const auto& r : candidates) {
            if (seen.find(r.ioctl_code) == seen.end()) {
                final_results.push_back(r);
            }
        }
    } else {
        final_results = std::move(candidates);
    }

    auto end_time = std::chrono::steady_clock::now();
    stats_.elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);

    return final_results;
}

} // namespace ds
