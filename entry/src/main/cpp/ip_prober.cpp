#include "ip_prober.h"
#include "tun_reader.h"

#include <arpa/inet.h>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <hilog/log.h>

#undef LOG_TAG
#define LOG_TAG "BiuProbe"

static const int TLS_TIMEOUT_MS = 1500;
static const int MAX_PROBES = 6;
static const int CACHE_OK_TTL_S = 600;
static const int CACHE_FAIL_TTL_S = 30;

struct CacheEntry {
    ProbeResult result;
    std::chrono::steady_clock::time_point at;
};

static std::mutex g_mutex;
static std::map<std::string, std::vector<uint32_t>> g_domain_ips;
static std::map<std::string, CacheEntry> g_cache;

static uint32_t ip(const char* s) { return inet_addr(s); }

void prober_init() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_domain_ips["github.com"] = {
        ip("20.205.243.166"), ip("140.82.112.3"), ip("140.82.113.3"),
        ip("140.82.112.4"), ip("140.82.114.3"), ip("140.82.121.3"),
        ip("20.27.177.113"), ip("20.200.245.247")
    };
    g_domain_ips["api.github.com"] = {
        ip("20.205.243.168"), ip("140.82.112.5"), ip("140.82.112.6"),
        ip("140.82.113.5"), ip("140.82.113.6"), ip("140.82.114.5"),
        ip("20.27.177.116"), ip("20.200.245.245")
    };
    g_domain_ips["raw.githubusercontent.com"] = {
        ip("185.199.108.133"), ip("185.199.109.133"),
        ip("185.199.110.133"), ip("185.199.111.133")
    };
    g_domain_ips["gist.github.com"] = {
        ip("20.205.243.166"), ip("140.82.112.3"), ip("140.82.112.4"),
        ip("140.82.113.3"), ip("140.82.113.4")
    };
    g_domain_ips["github.githubassets.com"] = {
        ip("185.199.108.154"), ip("185.199.109.154"),
        ip("185.199.110.154"), ip("185.199.111.154")
    };
    g_domain_ips["avatars.githubusercontent.com"] = {
        ip("185.199.108.133"), ip("185.199.109.133"),
        ip("185.199.110.133"), ip("185.199.111.133")
    };
    g_domain_ips["objects.githubusercontent.com"] = {
        ip("185.199.108.133"), ip("185.199.109.133"),
        ip("185.199.110.133"), ip("185.199.111.133")
    };
    g_domain_ips["github.io"] = {
        ip("185.199.108.153"), ip("185.199.109.153"),
        ip("185.199.110.153"), ip("185.199.111.153")
    };
    g_domain_ips["github.global.ssl.fastly.net"] = {
        ip("151.101.1.64"), ip("151.101.65.64"),
        ip("151.101.129.64"), ip("151.101.193.64")
    };
    g_domain_ips["collector.github.com"] = {
        ip("20.205.243.166"), ip("140.82.112.21"), ip("140.82.112.22"),
        ip("140.82.113.21"), ip("140.82.113.22")
    };
    g_domain_ips["central.github.com"] = {
        ip("140.82.112.21"), ip("140.82.112.22"),
        ip("140.82.113.21"), ip("140.82.113.22")
    };
}

static int build_client_hello(unsigned char* out, const char* sni) {
    int n = 0;
    out[n++] = 0x16; out[n++] = 0x03; out[n++] = 0x01;
    int rec_len_pos = n; n += 2;

    int hs_start = n;
    out[n++] = 0x01;
    n += 3;
    out[n++] = 0x03; out[n++] = 0x03;
    for (int i = 0; i < 32; i++) out[n++] = static_cast<unsigned char>(i * 7 + 1);
    out[n++] = 0x00;

    int cs_len_pos = n; n += 2;
    int cs_start = n;
    unsigned short cs[] = {0xC02F, 0xC02B, 0xC030, 0xC02C, 0x009C, 0x009D, 0x002F, 0x0035};
    for (unsigned i = 0; i < sizeof(cs) / sizeof(cs[0]); i++) {
        out[n++] = cs[i] >> 8; out[n++] = cs[i] & 0xFF;
    }
    int cs_len = n - cs_start;
    out[cs_len_pos] = (cs_len >> 8) & 0xFF; out[cs_len_pos + 1] = cs_len & 0xFF;

    out[n++] = 0x01; out[n++] = 0x00;

    int ext_len_pos = n; n += 2;
    int ext_start = n;

    size_t sni_len = strlen(sni);
    out[n++] = 0x00; out[n++] = 0x00;
    out[n++] = ((sni_len + 5) >> 8) & 0xFF; out[n++] = (sni_len + 5) & 0xFF;
    out[n++] = ((sni_len + 3) >> 8) & 0xFF; out[n++] = (sni_len + 3) & 0xFF;
    out[n++] = 0x00;
    out[n++] = (sni_len >> 8) & 0xFF; out[n++] = sni_len & 0xFF;
    memcpy(out + n, sni, sni_len); n += static_cast<int>(sni_len);

    out[n++] = 0x00; out[n++] = 0x0A;
    out[n++] = 0x00; out[n++] = 0x06;
    out[n++] = 0x00; out[n++] = 0x04;
    out[n++] = 0x00; out[n++] = 0x1D;
    out[n++] = 0x00; out[n++] = 0x17;

    out[n++] = 0x00; out[n++] = 0x0D;
    out[n++] = 0x00; out[n++] = 0x0A;
    out[n++] = 0x00; out[n++] = 0x08;
    out[n++] = 0x04; out[n++] = 0x03;
    out[n++] = 0x08; out[n++] = 0x04;
    out[n++] = 0x04; out[n++] = 0x01;
    out[n++] = 0x05; out[n++] = 0x01;

    int ext_len = n - ext_start;
    out[ext_len_pos] = (ext_len >> 8) & 0xFF; out[ext_len_pos + 1] = ext_len & 0xFF;

    int hs_len = n - hs_start - 4;
    out[hs_start + 1] = (hs_len >> 16) & 0xFF;
    out[hs_start + 2] = (hs_len >> 8) & 0xFF;
    out[hs_start + 3] = hs_len & 0xFF;

    int rec_len = n - rec_len_pos - 2;
    out[rec_len_pos] = (rec_len >> 8) & 0xFF; out[rec_len_pos + 1] = rec_len & 0xFF;
    return n;
}

static int tls_probe_ms(uint32_t addr, const std::string& sni) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    tun_protect(fd);
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(443);
    sa.sin_addr.s_addr = addr;

    auto start = std::chrono::steady_clock::now();
    int ret = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    if (ret != 0 && errno == EINPROGRESS) {
        pollfd pfd{fd, POLLOUT, 0};
        if (poll(&pfd, 1, TLS_TIMEOUT_MS) <= 0) { close(fd); return -1; }
        int err = 0;
        socklen_t elen = sizeof(err);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
        if (err != 0) { close(fd); return -1; }
    } else if (ret != 0) {
        close(fd);
        return -1;
    }

    unsigned char hello[512];
    int hello_len = build_client_hello(hello, sni.c_str());
    if (send(fd, hello, hello_len, 0) != hello_len) { close(fd); return -1; }

    unsigned char buf[1024];
    pollfd pfd{fd, POLLIN, 0};
    if (poll(&pfd, 1, TLS_TIMEOUT_MS) <= 0) { close(fd); return -1; }
    ssize_t got = recv(fd, buf, sizeof(buf), 0);
    close(fd);

    if (got < 6 || buf[0] != 0x16 || buf[5] != 0x02) {
        char ipbuf[INET_ADDRSTRLEN] = {0};
        in_addr a{};
        a.s_addr = addr;
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        int alert = (buf[0] == 0x15) ? static_cast<int>(buf[6]) : -1;
        OH_LOG_INFO(LOG_APP, "tls fail %{public}s got=%{public}d first=%{public}d alert=%{public}d",
                    ipbuf, static_cast<int>(got),
                    got > 0 ? static_cast<int>(buf[0]) : -1, alert);
        return -1;
    }

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    return static_cast<int>(elapsed);
}

ProbeResult prober_best_ip(const std::string& domain) {
    std::vector<uint32_t> candidates;
    {
        std::lock_guard<std::mutex> lock(g_mutex);
        auto cit = g_cache.find(domain);
        if (cit != g_cache.end()) {
            int ttl = cit->second.result.ip != 0 ? CACHE_OK_TTL_S : CACHE_FAIL_TTL_S;
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::steady_clock::now() - cit->second.at).count();
            if (age < ttl) return cit->second.result;
        }
        auto it = g_domain_ips.find(domain);
        if (it == g_domain_ips.end()) return {0, -1};
        candidates = it->second;
    }

    if (candidates.size() > MAX_PROBES) candidates.resize(MAX_PROBES);

    std::vector<int> results(candidates.size(), -1);
    std::vector<std::thread> threads;
    threads.reserve(candidates.size());
    for (size_t i = 0; i < candidates.size(); i++) {
        threads.emplace_back([&, i]() {
            results[i] = tls_probe_ms(candidates[i], domain);
        });
    }
    for (auto& t : threads) t.join();

    ProbeResult best{0, 99999};
    for (size_t i = 0; i < candidates.size(); i++) {
        if (results[i] >= 0 && results[i] < best.latency_ms) {
            best = {candidates[i], results[i]};
        }
    }

    {
        std::lock_guard<std::mutex> lock(g_mutex);
        g_cache[domain] = {best, std::chrono::steady_clock::now()};
    }
    return best;
}
