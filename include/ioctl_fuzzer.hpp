#pragma once

#include "driver_sight.hpp"
#include <vector>
#include <functional>
#include <chrono>
#include <atomic>

namespace ds {

enum class FuzzMode {
    Safe,       // Conservative: small buffers, common IOCTLs only
    Normal,     // Balanced: moderate coverage
    Aggressive  // Full coverage: all methods, large buffers
};

enum class FuzzPhase {
    Probe,      // Detect valid IOCTL ranges
    Enumerate,  // Find responding IOCTLs
    Analyze     // Deep test interesting IOCTLs
};

struct FuzzConfig {
    FuzzMode mode = FuzzMode::Normal;

    // IOCTL range (auto-detected in Probe phase if zeros)
    DWORD device_type_start = 0;
    DWORD device_type_end = 0;
    DWORD function_start = 0;
    DWORD function_end = 0;

    // Buffer sizes by mode
    std::vector<size_t> buffer_sizes = {0, 8, 64, 256, 1024, 4096};

    // Timing controls
    DWORD timeout_ms = 2000;          // Per-IOCTL timeout
    DWORD delay_between_ms = 5;       // Delay between IOCTLs (stability)
    DWORD health_check_interval = 50; // Check device health every N IOCTLs

    // Safety options
    bool test_null_buffers = true;
    bool test_method_neither = true;  // METHOD_NEITHER can be dangerous
    bool skip_on_exception = true;    // Skip IOCTL range after exception
    bool stop_on_repeated_errors = true;
    int max_consecutive_errors = 20;

    // Recovery
    bool enable_checkpoints = false;
    std::wstring checkpoint_file;
};

struct FuzzStats {
    size_t total_ioctls_tested = 0;
    size_t successful_ioctls = 0;
    size_t exceptions_caught = 0;
    size_t timeouts = 0;
    size_t access_denied = 0;
    size_t invalid_function = 0;
    size_t other_errors = 0;
    std::chrono::milliseconds elapsed{0};
};

class IoctlFuzzer {
public:
    using ProgressCallback = std::function<void(const std::wstring& device, DWORD ioctl,
                                                 size_t current, size_t total, FuzzPhase phase)>;
    using ResultCallback = std::function<void(const IoctlResult& result)>;

    explicit IoctlFuzzer(const FuzzConfig& config = {});

    std::vector<IoctlResult> fuzz_device(HANDLE device, const std::wstring& device_path);

    void set_progress_callback(ProgressCallback cb);
    void set_result_callback(ResultCallback cb);
    void request_stop();

    const FuzzStats& get_stats() const { return stats_; }

private:
    // Phase handlers
    std::vector<DWORD> probe_ioctl_ranges(HANDLE device);
    std::vector<IoctlResult> enumerate_ioctls(HANDLE device, const std::vector<DWORD>& device_types);
    std::vector<IoctlResult> analyze_ioctls(HANDLE device, const std::vector<IoctlResult>& candidates);

    // Core IOCTL testing
    IoctlResult try_ioctl(HANDLE device, DWORD code, void* in_buf, DWORD in_size,
                          void* out_buf, DWORD out_size);
    IoctlResult try_ioctl_safe(HANDLE device, DWORD code, void* in_buf, DWORD in_size,
                               void* out_buf, DWORD out_size);

    // Health and safety
    bool check_device_health(HANDLE device);
    bool is_dangerous_ioctl(DWORD code) const;
    void apply_rate_limit();
    void categorize_error(IoctlResult& result);

    // Buffer management
    void prepare_buffers();
    void fill_buffer_pattern(BYTE* buf, size_t size, DWORD ioctl);

    FuzzConfig config_;
    FuzzStats stats_;
    ProgressCallback progress_cb_;
    ResultCallback result_cb_;
    std::atomic<bool> stop_requested_{false};

    // Preallocated buffers
    std::vector<std::vector<BYTE>> buffers_;
    std::vector<BYTE> health_check_buf_;

    // State tracking
    DWORD last_successful_ioctl_ = 0;
    int consecutive_errors_ = 0;
};

} // namespace ds
