#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct ProbeResult {
    uint32_t ip;
    int latency_ms;
};

void prober_init();
ProbeResult prober_best_ip(const std::string& domain);