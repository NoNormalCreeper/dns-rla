#include "net_loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "common.h"
#include "dns_packet.h"

#include "hosts_table.h"
#include "logger.h"

// 整个事件循环长期持有的资源
typedef struct {
    const relay_config_t* config;
    const hosts_table_t* hosts;
    relay_state_t* relay_state;
    dns_cache_t* cache;
    dns_stats_t* stats;

    int local_sock;
    int upstream_sock;
} net_loop_context_t;

// 单次的 client 请求
typedef struct {
    ubyte packet[DNS_MAX_PACKET_SIZE];
    size_t packet_len;

    struct sockaddr_storage client_addr;
    socklen_t client_addr_len;

    dns_query_t query;
} client_query_t;

/* 1=hit, 0=miss */
static int try_send_cached_response(net_loop_context_t* loop,
                               const client_query_t* request) {
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len = sizeof(response);

    dns_cache_key_t key = {
        .qtype = request->query.qtype,
        .qclass = request->query.qclass,
    };
    strncpy(key.qname, request->query.qname, DNS_MAX_DOMAIN_LEN);

    int cache_result = dns_cache_get(loop->cache, &key, time(NULL), response,
                                     response_len, &response_len);
    if (cache_result == 0) {
        // cache hit
        if (dns_packet_set_id(response, response_len, request->query.id) != 0) {
            logger_error("Failed to set client ID in cached response");
            return 1;
        }
        if (sendto(loop->local_sock, response, response_len, 0,
                   (const struct sockaddr*)&request->client_addr,
                   request->client_addr_len) < 0) {
            logger_error("sendto() cached response to client failed: %s",
                         strerror(errno));
            return 1;  // hit，但回客户端失败，退回上游路径也解决不了这个失败
        }
        return 1;  // indicate cache hit
    }
    if (cache_result == -1) {
        logger_debug("Cache miss for domain %s", request->query.qname);
    }
    if (cache_result == -2) {
        logger_warning("Cache entry for domain %s is too large to send",
                       request->query.qname);
    }

    return 0;  // default to cache miss
}

static void handle_client_query_miss(net_loop_context_t* loop,
                                     client_query_t* request) {
    // 生成 forward_id，改写 DNS ID
    uint16_t client_id = request->query.id;
    uint16_t forward_id;
    if (relay_state_next_id(loop->relay_state, &forward_id) != 0) {
        logger_error("Failed to generate forward ID");
        return;
    }
    if (dns_packet_set_id(request->packet, request->packet_len, forward_id) !=
        0) {
        logger_error("Failed to set forward ID");
        return;
    }

    // 记录 state，保存原客户端地址和 ID
    if (relay_state_add(loop->relay_state, forward_id, client_id,
                        (const struct sockaddr*)&request->client_addr,
                        request->client_addr_len, request->query.qname,
                        request->query.qtype, request->query.qclass) != 0) {
        logger_error("Failed to add relay state");
        return;
    }

    // 发送上游
    if (send(loop->upstream_sock, request->packet, request->packet_len, 0) <
        0) {
        logger_error("send() to upstream failed: %s", strerror(errno));
        relay_state_remove(loop->relay_state, forward_id);
        return;
    }
    logger_debug(
        "Forwarded query with forward ID %u (client ID %u) to upstream",
        forward_id, client_id);
}

static void handle_upstream_response(net_loop_context_t* loop) {
    ubyte response[DNS_MAX_PACKET_SIZE];
    ssize_t response_size =
        recv(loop->upstream_sock, response, sizeof(response), 0);
    if (response_size < 0) {
        logger_error("recv() from upstream failed: %s", strerror(errno));
        return;
    }

    uint16_t forward_id = dns_packet_get_id(response, (size_t)response_size);

    // 用 forward_id 查 state 找回原客户端
    pending_query_t* pending = relay_state_find(loop->relay_state, forward_id);
    if (pending == NULL) {
        // 可能是迟到响应、未知响应、已经超时清理
        logger_warning("Received response with unknown forward ID: %u",
                       forward_id);
        return;
    }

    // 把响应 ID 改回 client_id，发回客户端
    if (dns_packet_set_id(response, (size_t)response_size,
                          pending->client_id) != 0) {
        logger_error("Failed to set client ID in response");
        relay_state_remove(loop->relay_state,
                           forward_id);  // 上游响应也已经被消费了
        return;
    }

    if (sendto(loop->local_sock, response, (size_t)response_size, 0,
               (const struct sockaddr*)&pending->client_addr,
               pending->client_addr_len) < 0) {
        logger_error("sendto() to client failed: %s", strerror(errno));
    }

    logger_debug(
        "Relayed response with forward ID %u (client ID %u) back to client",
        forward_id, pending->client_id);

    // 请求完成，删除 state
    relay_state_remove(loop->relay_state, forward_id);
}

static void send_local_response(net_loop_context_t* loop,
                                client_query_t* request,
                                hosts_lookup_result_t lookup_result) {
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len = 0;

    if (lookup_result.kind == HOSTS_LOOKUP_BLOCKED) {
        if (dns_packet_build_nxdomain_response(
                request->packet, request->packet_len, response,
                DNS_MAX_PACKET_SIZE, &response_len) != 0) {
            logger_error("Failed to build NXDOMAIN response");
            return;
        }
    } else if (lookup_result.kind == HOSTS_LOOKUP_ADDRESS) {
        if (dns_packet_build_a_response(request->packet, request->packet_len,
                                        lookup_result.ipv4_network_order,
                                        response, DNS_MAX_PACKET_SIZE,
                                        &response_len) != 0) {
            logger_error("Failed to build A response");
            return;
        }
    };

    if (sendto(loop->local_sock, response, response_len, 0,
               (const struct sockaddr*)&request->client_addr,
               request->client_addr_len) < 0) {
        logger_error("sendto() failed: %s", strerror(errno));
    }

    logger_debug("Sent local response to client for domain %s (kind: %d)",
                 request->query.qname, lookup_result.kind);
}

static void handle_client_query(net_loop_context_t* loop) {
    client_query_t request;
    request.client_addr_len = sizeof(request.client_addr);

    ssize_t query_size = recvfrom(
        loop->local_sock, request.packet, sizeof(request.packet), 0,
        (struct sockaddr*)&request.client_addr, &request.client_addr_len);
    if (query_size < 0) {
        logger_error("recvfrom() failed: %s", strerror(errno));
        return;
    }
    request.packet_len = (size_t)query_size;

    if (dns_packet_parse_query(request.packet, request.packet_len,
                               &request.query) != 0) {
        logger_error("Invalid DNS query");
        return;
    }

    hosts_lookup_result_t lookup_result =
        hosts_table_lookup(loop->hosts, request.query.qname);

    if (lookup_result.kind != HOSTS_LOOKUP_MISS &&
        request.query.qtype == DNS_TYPE_A &&
        request.query.qclass == DNS_CLASS_IN) {
        send_local_response(loop, &request, lookup_result);
        return;
    }

    if (try_send_cached_response(loop, &request) == 1) {
        return;
    }

    handle_client_query_miss(loop, &request);
}

int net_loop_run(const relay_config_t* config,
                 const hosts_table_t* hosts,
                 relay_state_t* relay_state,
                 dns_cache_t* cache,
                 dns_stats_t* stats) {
    /*
     * 后续这里要实现真正的 UDP/select 主循环。
     *
     * 推荐设计：
     * 1. 创建本地监听 socket，绑定 config->listen_port，标准 DNS 是 UDP 53。
     * 2. 创建上游 socket，负责和 config->upstream_dns:53 通信。
     * 3. 用 select() 同时监听两个 socket，避免阻塞等待某个外部 DNS 响应。
     * 4. 收到客户端查询：
     *    - dns_packet_parse_query() 解析域名和类型。
     *    - hosts_table_lookup() 查静态表。
     *    - 命中普通 IP：构造 A 响应并 sendto() 回客户端。
     *    - 命中 0.0.0.0：构造 NXDOMAIN 响应并 sendto() 回客户端。
     *    - 未命中：生成 forward_id，改写 DNS ID，记录 relay_state，转发上游。
     * 5. 收到上游响应：
     *    - 读取响应 ID。
     *    - relay_state_find() 找原客户端。
     *    - 找到后把 ID 改回 client_id，再 sendto() 回客户端。
     *    - 找不到说明可能是迟到响应或未知包，直接丢弃。
     * 6. 每轮循环调用 relay_state_expire() 清理超时请求。
     *
     * 开发 trick：
     * - 初期可先绑定 5353 端口测试，最后再切回 53。
     * - recvfrom() 会同时给出发送者 IP/端口，必须保存它才能回包。
     * - UDP 没有连接状态，所有“这个响应该发给谁”的信息都靠 relay_state。
     */

    logger_info("dnsrelay skeleton is running");
    logger_info("listen port: %u", config->listen_port);
    logger_info("upstream DNS: %s", config->upstream_dns);
    logger_info("upstream port: %u", config->upstream_port);
    logger_info("table entries available: %zu", hosts->count);
    // logger_debug("network loop is not implemented yet");

    // init socket
    int local_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (local_sock < 0) {
        logger_error("socket() failed: %s", strerror(errno));
        return -1;
    }

    int upstream_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (upstream_sock < 0) {
        logger_error("socket() failed: %s", strerror(errno));
        close(local_sock);
        return -1;
    }

    net_loop_context_t loop = {
        .config = config,
        .hosts = hosts,
        .relay_state = relay_state,
        .cache = cache,
        .stats = stats,
        .local_sock = local_sock,
        .upstream_sock = upstream_sock,
    };

    // bind
    struct sockaddr_in local_addr = {.sin_family = AF_INET,
                                     .sin_port = htons(config->listen_port)};
    inet_aton("0.0.0.0", &local_addr.sin_addr);

    if (bind(local_sock, (struct sockaddr*)&local_addr, sizeof(local_addr)) <
        0) {
        logger_error("bind() failed: %s", strerror(errno));
        close(local_sock);
        close(upstream_sock);
        return -1;
    }

    struct sockaddr_in upstream_addr = {
        .sin_family = AF_INET, .sin_port = htons(config->upstream_port)};
    if (inet_aton(config->upstream_dns, &upstream_addr.sin_addr) == 0) {
        logger_error("inet_aton() failed for upstream DNS: %s",
                     config->upstream_dns);
        close(local_sock);
        close(upstream_sock);
        return -1;
    }

    if (connect(upstream_sock, (struct sockaddr*)&upstream_addr,
                sizeof(upstream_addr)) < 0) {
        logger_error("connect() failed: %s", strerror(errno));
        close(local_sock);
        close(upstream_sock);
        return -1;
    }

    while (1) {
        fd_set read_fds;
        int max_fd = local_sock > upstream_sock ? local_sock : upstream_sock;
        struct timeval timeout = {.tv_sec = 1,
                                  .tv_usec = 0};  // 1 second timeout for select

        FD_ZERO(&read_fds);
        FD_SET(local_sock, &read_fds);
        FD_SET(upstream_sock, &read_fds);

        if (select(max_fd + 1, &read_fds, NULL, NULL, &timeout) < 0) {
            logger_error("select() failed: %s", strerror(errno));
            if (errno == EINTR) {
                continue;  // Interrupted by signal, retry
            }

            close(local_sock);
            close(upstream_sock);
            return -1;
        }

        if (FD_ISSET(local_sock, &read_fds)) {
            logger_debug("Received a packet from a client");
            handle_client_query(&loop);
        }

        if (FD_ISSET(upstream_sock, &read_fds)) {
            logger_debug("Received a packet from the upstream DNS");
            handle_upstream_response(&loop);
        }

        relay_state_expire(relay_state, time(NULL));
    }

    return 0;
}
