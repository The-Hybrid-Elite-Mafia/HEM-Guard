#include "hem_guard/throttle.hpp"

#include <thread>

namespace hem::guard {

double throttle_sleep_seconds(double busy, double share) {
    if (share >= 1.0 || share <= 0.0 || busy <= 0.0) return 0.0;
    return busy * (1.0 - share) / share;
}

CpuThrottle::CpuThrottle(double share) : share_(share), mark_(std::chrono::steady_clock::now()) {}

void CpuThrottle::tick() {
    using clock = std::chrono::steady_clock;
    const auto now = clock::now();
    const double busy = std::chrono::duration<double>(now - mark_).count();
    debt_ += throttle_sleep_seconds(busy, share_);
    // Sleeping in tiny slices is wasteful and Windows rounds sleeps up, so pay the debt in lumps.
    if (debt_ >= 0.004) {
        const auto before = clock::now();
        std::this_thread::sleep_for(std::chrono::duration<double>(debt_));
        const double actual = std::chrono::duration<double>(clock::now() - before).count();
        slept_ += actual;
        debt_ = 0.0;  // if the OS slept longer than asked, we simply ran cooler than the limit
    }
    mark_ = clock::now();
}

}  // namespace hem::guard
