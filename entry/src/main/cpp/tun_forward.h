#ifndef BIU_TUN_FORWARD_H
#define BIU_TUN_FORWARD_H

#include <cstddef>
#include <cstdint>

void fw_start(int tun_fd);
void fw_stop();
void fw_enqueue_tcp(const uint8_t* packet, size_t len);
void fw_enqueue_udp(const uint8_t* packet, size_t len);
uint64_t fw_tcp_connections();
uint64_t fw_tcp_packets();
uint64_t fw_udp_packets();
uint64_t fw_tcp_syns();

#endif
