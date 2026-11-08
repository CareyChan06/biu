#pragma once
#include <cstdint>

void tun_start(int tun_fd);
void tun_stop();
bool tun_is_running();
uint64_t tun_dns_queries();
uint64_t tun_accelerated_queries();
bool tun_protect(int fd);
void tun_set_stats_path(const char* path);