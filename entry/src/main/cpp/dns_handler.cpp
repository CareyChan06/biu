#include "dns_handler.h"
#include "ip_prober.h"
#include "tun_reader.h"

#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <set>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <hilog/log.h>

#undef LOG_TAG
#define LOG_TAG "BiuDns"

static std::atomic<uint32_t> g_log_count{0};

static std::mutex g_domain_mutex;
static std::set<std::string> g_whitelist = {
    "github.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "gist.github.com",
    "github.githubassets.com",
    "avatars.githubusercontent.com",
    "objects.githubusercontent.com",
    "github.io",
    "github.global.ssl.fastly.net",
    "collector.github.com",
    "central.github.com",
    "github.community",
    "github.blog",
    "githubusercontent.com",
};

static const char* UPSTREAM_DNS = "223.5.5.5";
static const int DNS_TIMEOUT_MS = 3000;

void dns_set_domains(const std::vector<std::string>& domains) {
    std::lock_guard<std::mutex> lock(g_domain_mutex);
    g_whitelist.clear();
    for (const auto& d : domains) {
        g_whitelist.insert(d);
    }
}

static bool is_whitelisted(const std::string& domain) {
    std::lock_guard<std::mutex> lock(g_domain_mutex);
    if (g_whitelist.count(domain)) return true;
    for (const auto& w : g_whitelist) {
        if (domain.size() > w.size() &&
            domain.compare(domain.size() - w.size(), w.size(), w) == 0 &&
            domain[domain.size() - w.size() - 1] == '.') {
            return true;
        }
    }
    return false;
}

static std::string parse_dns_name(const uint8_t* dns, size_t dns_len, size_t offset) {
    std::string name;
    size_t pos = offset;
    int jumps = 0;
    size_t end_pos = 0;
    bool jumped = false;

    while (pos < dns_len && jumps < 16) {
        uint8_t label_len = dns[pos];
        if (label_len == 0) {
            if (!jumped) end_pos = pos + 1;
            break;
        }
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= dns_len) break;
            if (!jumped) end_pos = pos + 2;
            uint16_t ptr = ((label_len & 0x3F) << 8) | dns[pos + 1];
            pos = ptr;
            jumped = true;
            jumps++;
            continue;
        }
        pos++;
        if (pos + label_len > dns_len) break;
        if (!name.empty()) name += '.';
        name.append(reinterpret_cast<const char*>(dns + pos), label_len);
        pos += label_len;
    }
    return name;
}

static uint16_t checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (data[i] << 8) | data[i + 1];
    }
    if (len & 1) sum += data[len - 1] << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

static std::vector<uint8_t> build_dns_response(
    const uint8_t* query, size_t query_len, uint32_t answer_ip)
{
    if (query_len < 12) return {};

    size_t pos = 12;
    while (pos < query_len && query[pos] != 0) pos += query[pos] + 1;
    if (pos + 5 > query_len) return {};
    size_t question_end = pos + 5;

    std::vector<uint8_t> resp(query, query + question_end);
    resp[2] = 0x81;
    resp[3] = 0x80;
    resp[6] = 0x00;
    resp[7] = 0x01;
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    uint8_t answer[] = {
        0xC0, 0x0C,
        0x00, 0x01,
        0x00, 0x01,
        0x00, 0x00, 0x00, 0x3C,
        0x00, 0x04,
        0, 0, 0, 0
    };
    memcpy(answer + 12, &answer_ip, 4);
    resp.insert(resp.end(), answer, answer + sizeof(answer));
    return resp;
}

static std::vector<uint8_t> forward_dns_upstream(
    const uint8_t* dns_query, size_t dns_len)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return {};
    tun_protect(fd);

    timeval tv{};
    tv.tv_sec = DNS_TIMEOUT_MS / 1000;
    tv.tv_usec = (DNS_TIMEOUT_MS % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in upstream{};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    upstream.sin_addr.s_addr = inet_addr(UPSTREAM_DNS);

    sendto(fd, dns_query, dns_len, 0,
           reinterpret_cast<sockaddr*>(&upstream), sizeof(upstream));

    uint8_t buf[4096];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    close(fd);

    if (n <= 0) return {};
    return std::vector<uint8_t>(buf, buf + n);
}

static std::vector<uint8_t> wrap_ip_udp(
    const uint8_t* orig_packet, size_t orig_len,
    const uint8_t* dns_resp, size_t dns_resp_len)
{
    if (orig_len < 28) return {};

    uint8_t ip_hdr_len = (orig_packet[0] & 0x0F) * 4;
    if (orig_len < ip_hdr_len + 8) return {};

    size_t total = 20 + 8 + dns_resp_len;
    std::vector<uint8_t> pkt(total, 0);

    pkt[0] = 0x45;
    pkt[1] = 0x00;
    pkt[2] = (total >> 8) & 0xFF;
    pkt[3] = total & 0xFF;
    pkt[4] = orig_packet[4];
    pkt[5] = orig_packet[5];
    pkt[6] = 0x40;
    pkt[7] = 0x00;
    pkt[8] = 64;
    pkt[9] = 17;

    memcpy(pkt.data() + 12, orig_packet + 16, 4);
    memcpy(pkt.data() + 16, orig_packet + 12, 4);

    uint16_t ip_cksum = checksum(pkt.data(), 20);
    pkt[10] = (ip_cksum >> 8) & 0xFF;
    pkt[11] = ip_cksum & 0xFF;

    size_t udp_off = 20;
    memcpy(pkt.data() + udp_off, orig_packet + ip_hdr_len + 2, 2);
    memcpy(pkt.data() + udp_off + 2, orig_packet + ip_hdr_len, 2);
    uint16_t udp_len = static_cast<uint16_t>(8 + dns_resp_len);
    pkt[udp_off + 4] = (udp_len >> 8) & 0xFF;
    pkt[udp_off + 5] = udp_len & 0xFF;
    pkt[udp_off + 6] = 0;
    pkt[udp_off + 7] = 0;

    memcpy(pkt.data() + udp_off + 8, dns_resp, dns_resp_len);
    return pkt;
}

DnsResult dns_handle(const uint8_t* packet, size_t len, int tun_fd) {
    DnsResult result{false, {}};

    if (len < 28) return result;
    uint8_t ip_hdr_len = (packet[0] & 0x0F) * 4;
    if (len < static_cast<size_t>(ip_hdr_len) + 8) return result;

    const uint8_t* udp = packet + ip_hdr_len;
    uint16_t dst_port = (udp[2] << 8) | udp[3];
    if (dst_port != 53) return result;

    const uint8_t* dns = udp + 8;
    size_t dns_len = len - ip_hdr_len - 8;
    if (dns_len < 12) return result;

    uint16_t flags = (dns[2] << 8) | dns[3];
    if (flags & 0x8000) return result;

    uint16_t qdcount = (dns[4] << 8) | dns[5];
    if (qdcount < 1) return result;

    std::string domain = parse_dns_name(dns, dns_len, 12);
    if (domain.empty()) return result;

    uint16_t qtype = 0;
    size_t pos = 12;
    while (pos < dns_len && dns[pos] != 0) pos += dns[pos] + 1;
    pos += 1;
    if (pos + 4 <= dns_len) {
        qtype = (dns[pos] << 8) | dns[pos + 1];
    }

    std::vector<uint8_t> dns_resp;
    bool wl = is_whitelisted(domain);
    uint32_t probe_ip = 0;
    int probe_ms = -1;

    if (qtype == 1 && wl) {
        ProbeResult best = prober_best_ip(domain);
        probe_ip = best.ip;
        probe_ms = best.latency_ms;
        if (best.ip != 0) {
            dns_resp = build_dns_response(dns, dns_len, best.ip);
            result.accelerated = true;
        }
    }

    if (dns_resp.empty()) {
        dns_resp = forward_dns_upstream(dns, dns_len);
    }

    if (!dns_resp.empty()) {
        result.response = wrap_ip_udp(packet, len, dns_resp.data(), dns_resp.size());
    }

    if (wl || g_log_count.fetch_add(1) < 5) {
        struct in_addr a{};
        a.s_addr = probe_ip;
        char ipbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &a, ipbuf, sizeof(ipbuf));
        OH_LOG_INFO(LOG_APP, "q=%{public}s t=%{public}d wl=%{public}d accel=%{public}d ip=%{public}s ms=%{public}d rsp=%{public}d",
                    domain.c_str(), qtype, wl ? 1 : 0, result.accelerated ? 1 : 0,
                    ipbuf, probe_ms, result.response.empty() ? 0 : 1);
    }

    return result;
}
