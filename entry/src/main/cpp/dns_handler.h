#pragma once
#include <cstdint>
#include <string>
#include <vector>

struct DnsResult {
    bool accelerated;
    std::vector<uint8_t> response;
};

void dns_set_domains(const std::vector<std::string>& domains);
DnsResult dns_handle(const uint8_t* packet, size_t len, int tun_fd);