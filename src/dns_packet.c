#include "dns_packet.h"

#include <arpa/inet.h>

uint16_t dns_packet_get_id(const unsigned char* packet, size_t packet_len) {
    uint16_t id;

    /*
     * DNS ID 在报文开头两个字节。
     * 长度不够说明这不是合法 DNS Header，骨架里返回 0 作为安全默认值。
     */
    if (packet_len < 2) {
        return 0;
    }

    
    /* 提醒：后续如果要解析 QDCOUNT、QTYPE、QCLASS、TTL、RDLENGTH，建议用 socket
     * 相关的字节序函数统一改成 read_u16/write_u16/read_u32/write_u32 这种
     * helper，而不是手写转换 */
     
    /* 网络字节序是大端：高 8 位在前，低 8 位在后。 */
    id = ((uint16_t)packet[0] << 8) | packet[1];
    return id;
}

int dns_packet_set_id(unsigned char* packet, size_t packet_len, uint16_t id) {
    /* 改写 ID 前也必须检查长度，避免收到短包时越界写。 */
    if (packet_len < 2) {
        return -1;
    }

    /* 手动拆成两个字节，避免依赖主机端序。 */
    packet[0] = (unsigned char)((id >> 8) & 0xff);
    packet[1] = (unsigned char)(id & 0xff);
    return 0;
}

int dns_packet_parse_question(const unsigned char* packet,
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

int dns_packet_build_a_response(const unsigned char* query,
                                size_t query_len,
                                uint32_t ipv4_network_order,
                                unsigned char* response,
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

int dns_packet_build_nxdomain_response(const unsigned char* query,
                                       size_t query_len,
                                       unsigned char* response,
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
