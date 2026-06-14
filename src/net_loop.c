#include "net_loop.h"
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>

#include "logger.h"

int net_loop_run(const relay_config_t* config,
                 const hosts_table_t* hosts,
                 relay_state_t* relay_state) {
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
    (void)relay_state;

    logger_info("dnsrelay skeleton is running");
    logger_info("listen port: %u", config->listen_port);
    logger_info("upstream DNS: %s", config->upstream_dns);
    logger_info("upstream port: %u", config->upstream_port);
    logger_info("table entries available: %zu", hosts->count);
    logger_debug("network loop is not implemented yet");

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
    inet_aton(config->upstream_dns, &upstream_addr.sin_addr);

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
            close(local_sock);
            close(upstream_sock);
            return -1;
        }

        if (FD_ISSET(local_sock, &read_fds)) {
            logger_debug("Received a packet from a client (not processed)");
            recvfrom(local_sock, NULL, 0, 0, NULL, NULL);  // just drain the packet
        }

        if (FD_ISSET(upstream_sock, &read_fds)) {
            logger_debug("Received a packet from the upstream DNS (not processed)");
            recvfrom(upstream_sock, NULL, 0, 0, NULL, NULL);  // just drain the packet
        }

        // TODO: 清理超时 pending 请求
    }

    return 0;
}
