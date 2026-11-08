#include "tun_reader.h"
#include "dns_handler.h"
#include "ip_prober.h"

#include <atomic>
#include <cerrno>
#include <cstring>
#include <thread>
#include <unistd.h>
#include <hilog/log.h>

#undef LOG_TAG
#define LOG_TAG "BiuTun"

static std::atomic<bool> g_running{false};
static std::thread g_thread;
static int g_tun_fd = -1;
static std::atomic<uint64_t> g_dns_queries{0};
static std::atomic<uint64_t> g_accelerated{0};

bool tun_protect(int fd) {
    (void)fd;
    return true;
}

static void tun_loop() {
    uint8_t buf[65536];
    OH_LOG_INFO(LOG_APP, "TUN reader loop started, fd=%{public}d", g_tun_fd);

    while (g_running.load()) {
        ssize_t n = read(g_tun_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            if (!g_running.load()) break;
            OH_LOG_ERROR(LOG_APP, "TUN read error: %{public}s", strerror(errno));
            break;
        }
        if (n == 0) continue;
        if (n < 20) continue;

        uint8_t version = (buf[0] >> 4) & 0x0F;
        if (version != 4) continue;

        uint8_t protocol = buf[9];
        if (protocol != 17) continue;

        uint8_t ihl = (buf[0] & 0x0F) * 4;
        if (n < ihl + 8) continue;

        uint16_t dst_port = (buf[ihl + 2] << 8) | buf[ihl + 3];
        if (dst_port != 53) continue;

        g_dns_queries.fetch_add(1);

        DnsResult result = dns_handle(buf, static_cast<size_t>(n), g_tun_fd);
        if (result.accelerated) {
            g_accelerated.fetch_add(1);
        }

        if (!result.response.empty()) {
            ssize_t written = write(g_tun_fd, result.response.data(), result.response.size());
            if (written < 0) {
                OH_LOG_ERROR(LOG_APP, "TUN write error: %{public}s", strerror(errno));
            }
        }
    }

    OH_LOG_INFO(LOG_APP, "TUN reader loop stopped");
}

void tun_start(int tun_fd) {
    if (g_running.load()) return;

    g_tun_fd = tun_fd;
    g_dns_queries.store(0);
    g_accelerated.store(0);
    g_running.store(true);

    prober_init();
    g_thread = std::thread(tun_loop);
}

void tun_stop() {
    if (!g_running.load()) return;
    g_running.store(false);
    if (g_thread.joinable()) {
        g_thread.join();
    }
    g_tun_fd = -1;
}

bool tun_is_running() {
    return g_running.load();
}

uint64_t tun_dns_queries() {
    return g_dns_queries.load();
}

uint64_t tun_accelerated_queries() {
    return g_accelerated.load();
}
