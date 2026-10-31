// HEM Guard - CPU share limiter for the scanner.
//
// How it works: the scanner calls tick() often. Time spent working since the last tick
// is "busy". For every busy second we pause (1 - share) / share seconds, so the scanner
// is awake about `share` of the time. If the scanner waits on the disk, that wait counts
// as busy too, so real CPU use ends up at or below the limit, never above it.
#pragma once

#include <chrono>

namespace hem::guard {

// Pure math, tested on its own. share >= 1 (or <= 0) means "no limit".
double throttle_sleep_seconds(double busy_seconds, double share);

class CpuThrottle {
public:
    explicit CpuThrottle(double share);
    void tick();
    double total_slept_seconds() const { return slept_; }

private:
    double share_;
    double debt_ = 0.0;
    double slept_ = 0.0;
    std::chrono::steady_clock::time_point mark_;
};

}  // namespace hem::guard
