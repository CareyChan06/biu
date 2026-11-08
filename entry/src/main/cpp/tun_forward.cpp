#include "tun_forward.h"
#include "tun_reader.h"

#include <arpa/inet.h>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <deque>
#include <fcntl.h>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <poll.h>
#include <random>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <hilog/log.h>

#undef LOG_TAG
#define LOG_TAG "BiuFwd"

static const uint16_t SERVER_MSS = 1200;
static const size_t MAX_INFLIGHT = 262144;
static const int CONNECT_TIMEOUT_S = 10;
static const int TCP_IDLE_TIMEOUT_S = 120;
static const int UDP_IDLE_TIMEOUT_S = 60;
static const size_t MAX_QUEUE = 1024;

static std::atomic<bool> g_running{false};
static std::atomic<int> g_tun_fd{-1};
static std::atomic<uint64_t> g_conn_count{0};
static std::atomic<uint64_t> g_tcp_packets{0};
static std::atomic<uint64_t> g_udp_packets{0};
static std::atomic<uint64_t> g_tcp_syns{0};

static std::thread g_tcp_thread;
static std::thread g_udp_thread;
static int g_tcp_pipe[2] = {-1, -1};
static int g_udp_pipe[2] = {-1, -1};

static std::mutex g_tcp_mutex;
static std::deque<std::vector<uint8_t>> g_tcp_queue;
static std::mutex g_udp_mutex;
static std::deque<std::vector<uint8_t>> g_udp_queue;

static uint16_t inet_checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    if (len & 1) sum += data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static uint16_t tcp_udp_checksum(uint32_t src_ip, uint32_t dst_ip,
                                 uint8_t proto, const uint8_t* seg, size_t len) {
    uint32_t sum = 0;
    const uint8_t* s = reinterpret_cast<const uint8_t*>(&src_ip);
    const uint8_t* d = reinterpret_cast<const uint8_t*>(&dst_ip);
    for (int i = 0; i < 4; i += 2) {
        sum += (s[i] << 8) | s[i + 1];
        sum += (d[i] << 8) | d[i + 1];
    }
    sum += proto;
    sum += static_cast<uint32_t>(len);
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (seg[i] << 8) | seg[i + 1];
    }
    if (len & 1) sum += seg[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static void ip_header(uint8_t* h, size_t total, uint8_t proto,
                      uint32_t src_ip, uint32_t dst_ip, uint8_t ttl) {
    h[0] = 0x45;
    h[1] = 0x00;
    h[2] = (total >> 8) & 0xFF;
    h[3] = total & 0xFF;
    h[4] = 0;
    h[5] = 0;
    h[6] = 0x40;
    h[7] = 0x00;
    h[8] = ttl;
    h[9] = proto;
    memcpy(h + 12, &src_ip, 4);
    memcpy(h + 16, &dst_ip, 4);
    uint16_t ck = inet_checksum(h, 20);
    h[10] = (ck >> 8) & 0xFF;
    h[11] = ck & 0xFF;
}

static std::vector<uint8_t> make_tcp(uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port,
                                     uint32_t seq, uint32_t ack, uint8_t flags,
                                     const uint8_t* payload, size_t paylen,
                                     bool with_mss) {
    size_t tcp_len = 20 + (with_mss ? 4 : 0);
    size_t total = 20 + tcp_len + paylen;
    std::vector<uint8_t> pkt(total, 0);
    ip_header(pkt.data(), total, 6, src_ip, dst_ip, 64);

    uint8_t* t = pkt.data() + 20;
    t[0] = (src_port >> 8) & 0xFF; t[1] = src_port & 0xFF;
    t[2] = (dst_port >> 8) & 0xFF; t[3] = dst_port & 0xFF;
    uint32_t nseq = htonl(seq);
    uint32_t nack = htonl(ack);
    memcpy(t + 4, &nseq, 4);
    memcpy(t + 8, &nack, 4);
    t[12] = ((tcp_len / 4) << 4) & 0xF0;
    t[13] = flags;
    t[14] = 0xFF; t[15] = 0xFF;
    uint16_t win = htons(65535);
    memcpy(t + 14, &win, 2);
    if (with_mss) {
        t[20] = 2; t[21] = 4;
        t[22] = (SERVER_MSS >> 8) & 0xFF; t[23] = SERVER_MSS & 0xFF;
    }
    if (paylen > 0 && payload) {
        memcpy(pkt.data() + 20 + tcp_len, payload, paylen);
    }
    uint16_t ck = tcp_udp_checksum(src_ip, dst_ip, 6, t, tcp_len + paylen);
    t[16] = (ck >> 8) & 0xFF;
    t[17] = ck & 0xFF;
    return pkt;
}

static std::vector<uint8_t> make_udp(uint32_t src_ip, uint16_t src_port,
                                     uint32_t dst_ip, uint16_t dst_port,
                                     const uint8_t* payload, size_t paylen) {
    size_t total = 20 + 8 + paylen;
    std::vector<uint8_t> pkt(total, 0);
    ip_header(pkt.data(), total, 17, src_ip, dst_ip, 64);
    uint8_t* u = pkt.data() + 20;
    u[0] = (src_port >> 8) & 0xFF; u[1] = src_port & 0xFF;
    u[2] = (dst_port >> 8) & 0xFF; u[3] = dst_port & 0xFF;
    size_t ulen = 8 + paylen;
    u[4] = (ulen >> 8) & 0xFF; u[5] = ulen & 0xFF;
    u[6] = 0; u[7] = 0;
    if (paylen > 0 && payload) memcpy(u + 8, payload, paylen);
    return pkt;
}

static void write_tun(const std::vector<uint8_t>& pkt) {
    int fd = g_tun_fd.load();
    if (fd < 0 || pkt.empty()) return;
    ssize_t n = write(fd, pkt.data(), pkt.size());
    if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
        OH_LOG_ERROR(LOG_APP, "tun write failed: %{public}s", strerror(errno));
    }
}

struct TcpKey {
    uint32_t cip;
    uint16_t cport;
    uint32_t sip;
    uint16_t sport;
    bool operator<(const TcpKey& o) const {
        if (cip != o.cip) return cip < o.cip;
        if (cport != o.cport) return cport < o.cport;
        if (sip != o.sip) return sip < o.sip;
        return sport < o.sport;
    }
};

enum TcpState { TCP_CONNECTING = 0, TCP_OPEN = 1, TCP_CLOSED = 2 };

struct TcpConn {
    TcpKey key;
    int sock{-1};
    TcpState state{TCP_CONNECTING};
    uint32_t ack{0};
    uint32_t seq{0};
    uint32_t client_acked{0};
    std::string to_server;
    bool client_fin{false};
    std::chrono::steady_clock::time_point last;
};

static std::map<TcpKey, TcpConn> g_conns;
static uint32_t g_random_seq = 0;

static void close_conn(TcpConn& c, bool send_rst) {
    if (send_rst && c.sock >= 0) {
        uint8_t flags = 0x04;
        write_tun(make_tcp(c.key.sip, c.key.sport, c.key.cip, c.key.cport,
                           c.seq, c.ack, flags, nullptr, 0, false));
    }
    if (c.sock >= 0) close(c.sock);
    c.sock = -1;
    c.state = TCP_CLOSED;
}

static void send_to_client(TcpConn& c, const uint8_t* payload, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > SERVER_MSS) chunk = SERVER_MSS;
        write_tun(make_tcp(c.key.sip, c.key.sport, c.key.cip, c.key.cport,
                           c.seq, c.ack, 0x18, payload + off, chunk, false));
        c.seq += static_cast<uint32_t>(chunk);
        off += chunk;
    }
}

static void handle_client_packet(const uint8_t* pkt, size_t len) {
    g_tcp_packets.fetch_add(1);
    if (len < 40) return;
    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < static_cast<size_t>(ihl) + 20) return;

    TcpKey key{};
    memcpy(&key.cip, pkt + 12, 4);
    memcpy(&key.sip, pkt + 16, 4);
    const uint8_t* t = pkt + ihl;
    key.cport = (t[0] << 8) | t[1];
    key.sport = (t[2] << 8) | t[3];

    uint32_t seq = ntohl(*(reinterpret_cast<const uint32_t*>(t + 4)));
    uint32_t acknum = ntohl(*(reinterpret_cast<const uint32_t*>(t + 8)));
    uint8_t doff = (t[12] >> 4) * 4;
    uint8_t flags = t[13];
    if (doff < 20 || len < static_cast<size_t>(ihl) + doff) return;
    const uint8_t* payload = t + doff;
    size_t paylen = len - ihl - doff;

    if (key.sport == 53) {
        if ((flags & 0x02) && !(flags & 0x10)) {
            write_tun(make_tcp(key.sip, key.sport, key.cip, key.cport, 0,
                               seq + 1, 0x14, nullptr, 0, false));
        }
        return;
    }

    auto it = g_conns.find(key);
    if (it == g_conns.end()) {
        if (!(flags & 0x02) || (flags & 0x10)) return;
        g_tcp_syns.fetch_add(1);

        struct in_addr sa_ip{}, ca_ip{};
        sa_ip.s_addr = key.sip;
        ca_ip.s_addr = key.cip;
        if (g_conn_count.load() < 60) {
            char sbuf[INET_ADDRSTRLEN] = {0};
            char cbuf[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &sa_ip, sbuf, sizeof(sbuf));
            inet_ntop(AF_INET, &ca_ip, cbuf, sizeof(cbuf));
            OH_LOG_INFO(LOG_APP, "tcp syn %{public}s:%{public}d from %{public}s:%{public}d",
                        sbuf, key.sport, cbuf, key.cport);
        }

        TcpConn c;
        c.key = key;
        c.seq = g_random_seq + (seq & 0xFFFF);
        c.client_acked = c.seq;
        c.ack = seq + 1;
        c.last = std::chrono::steady_clock::now();

        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) return;
        tun_protect(fd);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(key.sport);
        sa.sin_addr.s_addr = key.sip;
        int rc = connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
        if (rc != 0 && errno != EINPROGRESS) {
            OH_LOG_INFO(LOG_APP, "tcp connect err %{public}d", errno);
            close(fd);
            write_tun(make_tcp(key.sip, key.sport, key.cip, key.cport, 0,
                               seq + 1, 0x14, nullptr, 0, false));
            return;
        }
        c.sock = fd;
        g_conns[key] = std::move(c);
        g_conn_count.fetch_add(1);
        return;
    }

    TcpConn& c = it->second;
    c.last = std::chrono::steady_clock::now();

    if (flags & 0x04) {
        close_conn(c, false);
        g_conns.erase(it);
        return;
    }

    if (c.state == TCP_CONNECTING) {
        if (paylen > 0) {
            c.to_server.append(reinterpret_cast<const char*>(payload), paylen);
            c.ack = seq + paylen;
        }
        if (flags & 0x01) c.client_fin = true;
        return;
    }

    if (flags & 0x10) {
        uint32_t a = acknum;
        if (static_cast<int32_t>(a - c.client_acked) > 0) c.client_acked = a;
    }

    if (paylen > 0) {
        if (seq == c.ack) {
            c.to_server.append(reinterpret_cast<const char*>(payload), paylen);
            c.ack += static_cast<uint32_t>(paylen);
        }
        write_tun(make_tcp(key.sip, key.sport, key.cip, key.cport,
                           c.seq, c.ack, 0x10, nullptr, 0, false));
    }

    if (flags & 0x01) {
        c.client_fin = true;
        c.ack += 1;
        shutdown(c.sock, SHUT_WR);
        write_tun(make_tcp(key.sip, key.sport, key.cip, key.cport,
                           c.seq, c.ack, 0x10, nullptr, 0, false));
    }
}

static void tcp_thread_loop() {
    OH_LOG_INFO(LOG_APP, "tcp relay started");
    std::vector<pollfd> pfds;
    std::vector<TcpKey> keys;

    while (g_running.load()) {
        {
            std::lock_guard<std::mutex> lock(g_tcp_mutex);
            while (!g_tcp_queue.empty()) {
                std::vector<uint8_t> pkt = std::move(g_tcp_queue.front());
                g_tcp_queue.pop_front();
                handle_client_packet(pkt.data(), pkt.size());
            }
        }

        pfds.clear();
        keys.clear();
        pfds.push_back({g_tcp_pipe[0], POLLIN, 0});
        for (auto& kv : g_conns) {
            TcpConn& c = kv.second;
            if (c.sock < 0) continue;
            short ev = 0;
            if (c.state == TCP_CONNECTING) {
                ev = POLLOUT;
            } else {
                ev = static_cast<short>(POLLIN | (c.to_server.empty() ? 0 : POLLOUT));
            }
            pfds.push_back({c.sock, ev, 0});
            keys.push_back(kv.first);
        }

        int pr = poll(pfds.data(), pfds.size(), 100);
        if (pr < 0 && errno != EINTR) break;

        if (pfds[0].revents & POLLIN) {
            char buf[256];
            while (read(g_tcp_pipe[0], buf, sizeof(buf)) > 0) {}
        }

        if (pr > 0) {
            for (size_t i = 1; i < pfds.size(); i++) {
                if (pfds[i].revents == 0) continue;
                auto it = g_conns.find(keys[i - 1]);
                if (it == g_conns.end()) continue;
                TcpConn& c = it->second;
                if (c.sock != pfds[i].fd) continue;

                if (c.state == TCP_CONNECTING && (pfds[i].revents & (POLLOUT | POLLERR))) {
                    int err = 0;
                    socklen_t el = sizeof(err);
                    getsockopt(c.sock, SOL_SOCKET, SO_ERROR, &err, &el);
                    if (err != 0) {
                        close_conn(c, true);
                        g_conns.erase(it);
                        continue;
                    }
                    c.state = TCP_OPEN;
                    write_tun(make_tcp(c.key.sip, c.key.sport, c.key.cip, c.key.cport,
                                       c.seq, c.ack, 0x12, nullptr, 0, true));
                    c.seq += 1;
                    continue;
                }

                if (pfds[i].revents & POLLIN) {
                    uint8_t buf[16384];
                    ssize_t n = recv(c.sock, buf, sizeof(buf), 0);
                    if (n > 0) {
                        send_to_client(c, buf, static_cast<size_t>(n));
                    } else if (n == 0) {
                        write_tun(make_tcp(c.key.sip, c.key.sport, c.key.cip, c.key.cport,
                                           c.seq, c.ack, 0x11, nullptr, 0, false));
                        c.seq += 1;
                        close_conn(c, false);
                        g_conns.erase(it);
                        continue;
                    } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
                        close_conn(c, true);
                        g_conns.erase(it);
                        continue;
                    }
                }

                if (pfds[i].revents & POLLOUT) {
                    if (!c.to_server.empty()) {
                        size_t inflight = c.seq > c.client_acked ? c.seq - c.client_acked : 0;
                        if (inflight < MAX_INFLIGHT || c.state == TCP_CONNECTING) {
                            ssize_t n = send(c.sock, c.to_server.data(), c.to_server.size(),
                                             MSG_NOSIGNAL);
                            if (n > 0) c.to_server.erase(0, static_cast<size_t>(n));
                        }
                    }
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        for (auto it = g_conns.begin(); it != g_conns.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.last).count();
            if (it->second.state == TCP_CONNECTING && age > CONNECT_TIMEOUT_S) {
                close_conn(it->second, true);
                it = g_conns.erase(it);
            } else if (age > TCP_IDLE_TIMEOUT_S) {
                close_conn(it->second, true);
                it = g_conns.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& kv : g_conns) close_conn(kv.second, false);
    g_conns.clear();
    OH_LOG_INFO(LOG_APP, "tcp relay stopped");
}

struct UdpKey {
    uint32_t cip;
    uint16_t cport;
    uint32_t sip;
    uint16_t sport;
    bool operator<(const UdpKey& o) const {
        if (cip != o.cip) return cip < o.cip;
        if (cport != o.cport) return cport < o.cport;
        if (sip != o.sip) return sip < o.sip;
        return sport < o.sport;
    }
};

struct UdpFlow {
    int sock{-1};
    std::chrono::steady_clock::time_point last;
};

static std::map<UdpKey, UdpFlow> g_udp_flows;

static void handle_udp_packet(const uint8_t* pkt, size_t len) {
    g_udp_packets.fetch_add(1);
    if (len < 28) return;
    uint8_t ihl = (pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < static_cast<size_t>(ihl) + 8) return;

    UdpKey key{};
    memcpy(&key.cip, pkt + 12, 4);
    memcpy(&key.sip, pkt + 16, 4);
    const uint8_t* u = pkt + ihl;
    key.cport = (u[0] << 8) | u[1];
    key.sport = (u[2] << 8) | u[3];
    size_t paylen = len - ihl - 8;
    if (paylen == 0) return;

    auto it = g_udp_flows.find(key);
    if (it == g_udp_flows.end()) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return;
        tun_protect(fd);
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(key.sport);
        sa.sin_addr.s_addr = key.sip;
        if (connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
            close(fd);
            return;
        }
        UdpFlow f;
        f.sock = fd;
        f.last = std::chrono::steady_clock::now();
        it = g_udp_flows.emplace(key, f).first;
    }

    it->second.last = std::chrono::steady_clock::now();
    send(it->second.sock, u + 8, paylen, 0);
}

static void udp_thread_loop() {
    OH_LOG_INFO(LOG_APP, "udp relay started");
    std::vector<pollfd> pfds;
    std::vector<UdpKey> keys;

    while (g_running.load()) {
        {
            std::lock_guard<std::mutex> lock(g_udp_mutex);
            while (!g_udp_queue.empty()) {
                std::vector<uint8_t> pkt = std::move(g_udp_queue.front());
                g_udp_queue.pop_front();
                handle_udp_packet(pkt.data(), pkt.size());
            }
        }

        pfds.clear();
        keys.clear();
        pfds.push_back({g_udp_pipe[0], POLLIN, 0});
        for (auto& kv : g_udp_flows) {
            pfds.push_back({kv.second.sock, POLLIN, 0});
            keys.push_back(kv.first);
        }

        int pr = poll(pfds.data(), pfds.size(), 100);
        if (pr < 0 && errno != EINTR) break;

        if (pfds[0].revents & POLLIN) {
            char buf[256];
            while (read(g_udp_pipe[0], buf, sizeof(buf)) > 0) {}
        }

        if (pr > 0) {
            for (size_t i = 1; i < pfds.size(); i++) {
                if (!(pfds[i].revents & POLLIN)) continue;
                auto it = g_udp_flows.find(keys[i - 1]);
                if (it == g_udp_flows.end()) continue;
                UdpKey key = it->first;
                for (;;) {
                    uint8_t buf[4096];
                    ssize_t n = recv(it->second.sock, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    it->second.last = std::chrono::steady_clock::now();
                    write_tun(make_udp(key.sip, key.sport, key.cip, key.cport,
                                       buf, static_cast<size_t>(n)));
                }
            }
        }

        auto now = std::chrono::steady_clock::now();
        for (auto it = g_udp_flows.begin(); it != g_udp_flows.end();) {
            auto age = std::chrono::duration_cast<std::chrono::seconds>(
                now - it->second.last).count();
            if (age > UDP_IDLE_TIMEOUT_S) {
                close(it->second.sock);
                it = g_udp_flows.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& kv : g_udp_flows) close(kv.second.sock);
    g_udp_flows.clear();
    OH_LOG_INFO(LOG_APP, "udp relay stopped");
}

void fw_start(int tun_fd) {
    if (g_running.load()) return;
    g_tun_fd.store(tun_fd);
    g_conn_count.store(0);
    g_random_seq = static_cast<uint32_t>(std::random_device{}());
    {
        std::lock_guard<std::mutex> lock(g_tcp_mutex);
        g_tcp_queue.clear();
    }
    {
        std::lock_guard<std::mutex> lock(g_udp_mutex);
        g_udp_queue.clear();
    }
    if (pipe(g_tcp_pipe) != 0 || pipe(g_udp_pipe) != 0) {
        OH_LOG_ERROR(LOG_APP, "pipe failed: %{public}s", strerror(errno));
        return;
    }
    fcntl(g_tcp_pipe[0], F_SETFL, fcntl(g_tcp_pipe[0], F_GETFL, 0) | O_NONBLOCK);
    fcntl(g_udp_pipe[0], F_SETFL, fcntl(g_udp_pipe[0], F_GETFL, 0) | O_NONBLOCK);
    OH_LOG_INFO(LOG_APP, "fw_start fd=%{public}d pipes=%{public}d/%{public}d",
                tun_fd, g_tcp_pipe[0], g_udp_pipe[0]);
    g_running.store(true);
    g_tcp_thread = std::thread(tcp_thread_loop);
    g_udp_thread = std::thread(udp_thread_loop);
}

void fw_stop() {
    if (!g_running.load()) return;
    g_running.store(false);
    char b = 1;
    if (g_tcp_pipe[1] >= 0) write(g_tcp_pipe[1], &b, 1);
    if (g_udp_pipe[1] >= 0) write(g_udp_pipe[1], &b, 1);

    if (g_tcp_thread.joinable()) g_tcp_thread.join();
    if (g_udp_thread.joinable()) g_udp_thread.join();

    if (g_tcp_pipe[0] >= 0) close(g_tcp_pipe[0]);
    if (g_tcp_pipe[1] >= 0) close(g_tcp_pipe[1]);
    if (g_udp_pipe[0] >= 0) close(g_udp_pipe[0]);
    if (g_udp_pipe[1] >= 0) close(g_udp_pipe[1]);
    g_tcp_pipe[0] = g_tcp_pipe[1] = -1;
    g_udp_pipe[0] = g_udp_pipe[1] = -1;
    g_tun_fd.store(-1);
}

void fw_enqueue_tcp(const uint8_t* packet, size_t len) {
    {
        std::lock_guard<std::mutex> lock(g_tcp_mutex);
        if (g_tcp_queue.size() >= MAX_QUEUE) return;
        g_tcp_queue.emplace_back(packet, packet + len);
    }
    char b = 1;
    if (g_tcp_pipe[1] >= 0) write(g_tcp_pipe[1], &b, 1);
}

void fw_enqueue_udp(const uint8_t* packet, size_t len) {
    {
        std::lock_guard<std::mutex> lock(g_udp_mutex);
        if (g_udp_queue.size() >= MAX_QUEUE) return;
        g_udp_queue.emplace_back(packet, packet + len);
    }
    char b = 1;
    if (g_udp_pipe[1] >= 0) write(g_udp_pipe[1], &b, 1);
}

uint64_t fw_tcp_connections() {
    return g_conn_count.load();
}

uint64_t fw_tcp_packets() {
    return g_tcp_packets.load();
}

uint64_t fw_udp_packets() {
    return g_udp_packets.load();
}

uint64_t fw_tcp_syns() {
    return g_tcp_syns.load();
}
