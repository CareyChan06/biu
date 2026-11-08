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
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>

static std::mutex g_mutex;
static std::map<std::string, std::vector<uint32_t>> g_domain_ips;
static std::map<std::string, ProbeResult> g_cache;

static uint32_t ip(const char* s) { return inet_addr(s); }

void prober_init() {
    std::lock_guard<std::mutex> lock(g_mutex);
    g_domain_ips["github.com"] = {
        ip("140.82.112.3"), ip("140.82.112.4"), ip("140.82.113.3"),
        ip("140.82.113.4"), ip("140.82.114.3"), ip("140.82.114.4"),
        ip("140.82.121.3"), ip("140.82.121.4")
    };
    g_domain_ips["api.github.com"] = {
        ip("140.82.112.5"), ip("140.82.112.6"), ip("140.82.113.5"),
        ip("140.82.113.6"), ip("140.82.114.5"), ip("140.82.114.6")
    };
    g_domain_ips["raw.githubusercontent.com"] = {
        ip("185.199.108.133"), ip("185.199.109.133"),
        ip("185.199.110.133"), ip("185.199.111.133")
    };
    g_domain_ips["gist.github.com"] = {
        ip("140.82.112.3"), ip("140.82.112.4"), ip("140.82.113.3"),
        ip("140.82.113.4")
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
        ip("140.82.112.21"), ip("140.82.112.22"),
        ip("140.82.113.21"), ip("140.82.113.22")
    };
    g_domain_ips["central.github.com"] = {
        ip("140.82.112.21"), ip("140.82.112.22"),
        ip("140.82.113.21"), ip("140.82.113.22")
    };
}

ProbeResult prober_best_ip(const std::string& domain) {
    std::lock_guard<std::mutex> lock(g_mutex);

    auto cache_it = g_cache.find(domain);
    if (cache_it != g_cache.end()) {
        return cache_it->second;
    }

    auto it = g_domain_ips.find(domain);
    if (it == g_domain_ips.end()) {
        return {0, -1};
    }

    ProbeResult best{0, 99999};
    for (uint32_t addr : it->second) {
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) continue;
        tun_protect(fd);

        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(443);
        sa.sin_addr.s_addr = addr;

        auto start = std::chrono::steady_clock::now();
        int ret = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        bool ok = false;
        if (ret == 0) {
            ok = true;
        } else if (errno == EINPROGRESS) {
            pollfd pfd{fd, POLLOUT, 0};
            if (poll(&pfd, 1, 2000) > 0) {
                int err = 0;
                socklen_t elen = sizeof(err);
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                ok = (err == 0);
            }
        }
        close(fd);

        if (ok) {
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now() - start).count();
            int latency = static_cast<int>(elapsed);
            if (latency < best.latency_ms) {
                best = {addr, latency};
            }
        }
    }

    if (best.ip != 0) {
        g_cache[domain] = best;
    }
    return best;
}
