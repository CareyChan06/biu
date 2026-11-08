#include "tun_reader.h"
#include "dns_handler.h"
#include "ip_prober.h"
#include "tun_forward.h"

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <mutex>
#include <poll.h>
#include <string>
#include <thread>
#include <vector>
#include <unistd.h>
#include <hilog/log.h>

#undef LOG_TAG
#define LOG_TAG "BiuTun"

static std::atomic<bool> g_running{false};
static std::thread g_reader;
static std::atomic<int> g_tun_fd{-1};
static std::atomic<uint64_t> g_dns_queries{0};
static std::atomic<uint64_t> g_accelerated{0};

static std::mutex g_stats_path_mutex;
static std::string g_stats_path;

static std::mutex g_queue_mutex;
static std::condition_variable g_queue_cv;
static std::deque<std::vector<uint8_t>> g_queue;
static std::vector<std::thread> g_workers;

static constexpr size_t MAX_QUEUE = 512;
static constexpr int WORKER_COUNT = 4;

static const char* WARMUP_DOMAINS[] = {
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "github.githubassets.com",
    "avatars.githubusercontent.com",
    "objects.githubusercontent.com",
    "gist.github.com",
};

bool tun_protect(int fd) {
    (void)fd;
    return true;
}

void tun_set_stats_path(const char* path) {
    std::lock_guard<std::mutex> lock(g_stats_path_mutex);
    g_stats_path = path ? path : "";
}

static void flush_stats(bool running) {
    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_stats_path_mutex);
        path = g_stats_path;
    }
    if (path.empty()) return;

    std::string tmp = path + ".tmp";
    FILE* fp = fopen(tmp.c_str(), "w");
    if (!fp) return;
    fprintf(fp,
            "{\"running\":%s,\"dnsQueries\":%llu,\"acceleratedQueries\":%llu,"
            "\"tcpPackets\":%llu,\"udpPackets\":%llu,\"tcpSyns\":%llu,\"tcpConns\":%llu}",
            running ? "true" : "false",
            static_cast<unsigned long long>(g_dns_queries.load()),
            static_cast<unsigned long long>(g_accelerated.load()),
            static_cast<unsigned long long>(fw_tcp_packets()),
            static_cast<unsigned long long>(fw_udp_packets()),
            static_cast<unsigned long long>(fw_tcp_syns()),
            static_cast<unsigned long long>(fw_tcp_connections()));
    fclose(fp);
    rename(tmp.c_str(), path.c_str());
}

static void warmup_probe() {
    for (const char* domain : WARMUP_DOMAINS) {
        if (!g_running.load()) break;
        ProbeResult best = prober_best_ip(domain);
        if (best.ip != 0) {
            OH_LOG_INFO(LOG_APP, "warmup %{public}s %{public}d ms", domain, best.latency_ms);
        }
    }
}

static void dns_worker() {
    for (;;) {
        std::vector<uint8_t> packet;
        {
            std::unique_lock<std::mutex> lock(g_queue_mutex);
            g_queue_cv.wait(lock, [] { return !g_queue.empty() || !g_running.load(); });
            if (g_queue.empty()) {
                if (!g_running.load()) break;
                continue;
            }
            packet = std::move(g_queue.front());
            g_queue.pop_front();
        }

        int fd = g_tun_fd.load();
        if (fd < 0) continue;

        auto t0 = std::chrono::steady_clock::now();
        DnsResult result = dns_handle(packet.data(), packet.size(), fd);
        auto cost = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0).count();

        if (result.accelerated) {
            g_accelerated.fetch_add(1);
        }
        if (cost > 400) {
            OH_LOG_WARN(LOG_APP, "slow dns handling: %{public}lld ms", static_cast<long long>(cost));
        }

        if (!result.response.empty()) {
            ssize_t written = write(fd, result.response.data(), result.response.size());
            if (written < 0) {
                OH_LOG_ERROR(LOG_APP, "TUN write error: %{public}s", strerror(errno));
            }
        }
    }
}

static void tun_loop() {
    uint8_t buf[65536];
    int fd = g_tun_fd.load();
    OH_LOG_INFO(LOG_APP, "TUN reader loop started, fd=%{public}d", fd);
    flush_stats(true);

    auto last_flush = std::chrono::steady_clock::now();

    while (g_running.load()) {
        struct pollfd pfd = { fd, POLLIN, 0 };
        int pr = poll(&pfd, 1, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            OH_LOG_ERROR(LOG_APP, "TUN poll error: %{public}s", strerror(errno));
            break;
        }

        auto now = std::chrono::steady_clock::now();
        if (now - last_flush > std::chrono::milliseconds(500)) {
            flush_stats(g_running.load());
            last_flush = now;
        }
        if (pr == 0) continue;

        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            if (!g_running.load()) break;
            OH_LOG_ERROR(LOG_APP, "TUN read error: %{public}s", strerror(errno));
            break;
        }
        if (n == 0) continue;
        if (n < 20) continue;

        uint8_t version = (buf[0] >> 4) & 0x0F;
        if (version != 4) continue;

        uint8_t protocol = buf[9];
        uint8_t ihl = (buf[0] & 0x0F) * 4;
        if (n < ihl + 8) continue;

        uint16_t dst_port = (buf[ihl + 2] << 8) | buf[ihl + 3];

        if (protocol == 6) {
            fw_enqueue_tcp(buf, static_cast<size_t>(n));
            continue;
        }
        if (protocol != 17) continue;
        if (dst_port != 53) {
            fw_enqueue_udp(buf, static_cast<size_t>(n));
            continue;
        }

        g_dns_queries.fetch_add(1);

        {
            std::lock_guard<std::mutex> lock(g_queue_mutex);
            if (g_queue.size() >= MAX_QUEUE) continue;
            g_queue.push_back(std::vector<uint8_t>(buf, buf + n));
        }
        g_queue_cv.notify_one();
    }

    g_running.store(false);
    flush_stats(false);
    OH_LOG_INFO(LOG_APP, "TUN reader loop stopped");
}

void tun_start(int tun_fd) {
    if (g_running.load()) return;

    g_tun_fd.store(tun_fd);
    g_dns_queries.store(0);
    g_accelerated.store(0);
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        g_queue.clear();
    }
    g_running.store(true);

    prober_init();

    g_workers.clear();
    for (int i = 0; i < WORKER_COUNT; i++) {
        g_workers.emplace_back(dns_worker);
    }
    fw_start(tun_fd);
    std::thread(warmup_probe).detach();
    g_reader = std::thread(tun_loop);
}

void tun_stop() {
    if (!g_running.load()) return;
    g_running.store(false);
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        g_queue.clear();
    }
    g_queue_cv.notify_all();
    fw_stop();

    if (g_reader.joinable()) {
        g_reader.join();
    }
    for (auto& worker : g_workers) {
        if (worker.joinable()) worker.join();
    }
    g_workers.clear();
    g_tun_fd.store(-1);
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
