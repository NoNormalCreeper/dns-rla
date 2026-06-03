#include "dns_packet.h"

#include <arpa/inet.h>

#include <string.h>

/*
 * 网络字节序是大端序，但既然可以使用 arpa/inet.h，
 * 那么可以直接使用其中的字节序转换函数，以免手动拼拆字节。
 */

static uint16_t dns_packet_read_u16(const ubyte* start) {
    /*
     * 使用 memcpy，
     * 避免其他操作（如使用 union、指针 cast）可能引发的未定义行为。
     */
    uint16_t buf;
    memcpy(&buf, start, sizeof buf);
    return ntohs(buf);
}

static uint32_t dns_packet_read_u32(const ubyte* start) {
    uint32_t buf;
    memcpy(&buf, start, sizeof buf);
    return ntohl(buf);
}

static void dns_packet_write_u16(ubyte* start, uint16_t val) {
    uint16_t buf;
    buf = htons(val);
    memcpy(start, &buf, sizeof buf);
}

static void dns_packet_write_u32(ubyte* start, uint32_t val) {
    uint32_t buf;
    buf = htonl(val);
    memcpy(start, &buf, sizeof buf);
}

uint16_t dns_packet_get_id(const ubyte* packet, size_t packet_len) {
    uint16_t id;

    /*
     * DNS ID 在报文开头两个字节。
     * 长度不够说明这不是合法 DNS Header，骨架里返回 0 作为安全默认值。
     */
    if (packet_len < 2) {
        return 0;
    }

    /* 使用了专门的、能够正确处理字节序的 u16 读取函数 */
    return dns_packet_read_u16(packet);
}

int dns_packet_set_id(ubyte* packet, size_t packet_len, uint16_t id) {
    /* 改写 ID 前也必须检查长度，避免收到短包时越界写。 */
    if (packet_len < 2) {
        return -1;
    }

    /* 使用了专门的、能够正确处理字节序的 u16 写入函数 */
    dns_packet_write_u16(packet, id);
    return 0;
}

int dns_packet_parse_question(const ubyte* packet,
                              size_t packet_len,
                              dns_question_t* question) {
    /*
     * 后续实现步骤：
     * 1. 检查 packet_len >= DNS_HEADER_SIZE。
     * 2. 读取 QDCOUNT。DNS Header 中 QDCOUNT 位于偏移 4、5。
     * 3. 从偏移 12 开始解析 QNAME。
     * 4. QNAME 每段是“长度字节 + 标签内容”，以 0 结尾。
     * 5. QNAME 后面紧跟 2 字节 QTYPE 和 2 字节 QCLASS。
     *
     * 协议细节：
     * - 查询报文的 Question 里的 QNAME 通常不使用压缩指针。
     * - 响应报文里的 NAME 经常使用 0xC00C 压缩指针。
     * - 为了安全，解析时遇到长度越界、域名超过 255 字节、缺少结尾 0
     * 都应返回错误。
     */
    (void)packet;
    (void)packet_len;
    (void)question;
    return -1;
}

int dns_packet_build_a_response(const ubyte* query,
                                size_t query_len,
                                uint32_t ipv4_network_order,
                                ubyte* response,
                                size_t response_capacity,
                                size_t* response_len) {
    /*
     * 后续实现步骤：
     * 1. 复制原查询的 Header + Question 到 response。
     * 2. 设置 Flags：QR=1 表示响应，RA=1 表示递归可用，RCODE=0。
     * 3. 设置 QDCOUNT=1，ANCOUNT=1，NSCOUNT=0，ARCOUNT=0。
     * 4. 追加一条 Answer：
     *    - NAME 使用压缩指针 0xC00C，指向原 Question 的 QNAME。
     *    - TYPE=A，CLASS=IN。
     *    - TTL 可先写 60 或 300 秒。
     *    - RDLENGTH=4。
     *    - RDATA 写 ipv4_network_order 的 4 字节。
     *
     * trick：
     * - 不要把 ipv4_network_order 再 htonl() 一次；inet_pton()
     * 已经给网络字节序。
     * - response_capacity 必须在每次写入前检查，避免构造超长响应。
     */
    (void)query;
    (void)query_len;
    (void)ipv4_network_order;
    (void)response;
    (void)response_capacity;
    (void)response_len;
    return -1;
}

int dns_packet_build_nxdomain_response(const ubyte* query,
                                       size_t query_len,
                                       ubyte* response,
                                       size_t response_capacity,
                                       size_t* response_len) {
    /*
     * 后续实现步骤：
     * 1. 复制原查询的 Header + Question 到 response。
     * 2. 设置 QR=1，RA=1。
     * 3. 设置 RCODE=DNS_RCODE_NXDOMAIN。
     * 4. 保留 QDCOUNT=1，设置 ANCOUNT/NSCOUNT/ARCOUNT 为 0。
     *
     * 注意：
     * - PPT 要求 0.0.0.0 表项表示“域名不存在”，不是返回 0.0.0.0。
     * - 返回 NXDOMAIN 后，客户端通常会把它当成解析失败。
     */
    (void)query;
    (void)query_len;
    (void)response;
    (void)response_capacity;
    (void)response_len;
    return -1;
}
