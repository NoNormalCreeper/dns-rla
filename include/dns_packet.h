#ifndef DNS_RELAY_DNS_PACKET_H
#define DNS_RELAY_DNS_PACKET_H

#include <stddef.h>
#include <stdint.h>

/* 类型别名避免代码过于冗长 */
typedef unsigned char ubyte;

/* DNS Header 固定 12 字节：ID、Flags、QDCOUNT、ANCOUNT、NSCOUNT、ARCOUNT。 */
#define DNS_HEADER_SIZE 12

/*
 * 传统 UDP DNS 报文常见上限是 512 字节。
 * 现代 DNS 可通过 EDNS0 扩展更大报文，但课程设计最小版本先按 512 处理。
 */
#define DNS_MAX_PACKET_SIZE 512

/*
 * DNS 完整域名最长 255 字节。这里多留 1 字节放 C 字符串结尾 '\0'。
 * 注意：报文里的 QNAME 不是点分字符串，而是长度标签格式。
 */
#define DNS_MAX_DOMAIN_LEN 255

/* 常用查询类型和类：A=IPv4 地址，IN=Internet。 */
#define DNS_TYPE_A 1
#define DNS_CLASS_IN 1

/* 常用响应码：0=无错误，3=域名不存在，即 NXDOMAIN。 */
#define DNS_RCODE_NOERROR 0
#define DNS_RCODE_NXDOMAIN 3

typedef struct {
    /* DNS Header 里的事务 ID。响应必须带回客户端原 ID。 */
    uint16_t id;

    /* 解码后的点分域名，例如 www.bupt.edu.cn。 */
    char qname[DNS_MAX_DOMAIN_LEN + 1];

    /* 查询类型，例如 A=1、AAAA=28、MX=15。最小版本优先处理 A。 */
    uint16_t qtype;

    /* 查询类，绝大多数普通互联网查询是 IN=1。 */
    uint16_t qclass;
} dns_question_t;

/*
 * 读取 DNS Header 的 ID 字段。
 *
 * DNS 报文字段是网络字节序，也就是大端序。ID 位于报文第 0、1 字节。
 * 这里手动拼接两个字节，比直接强转结构体更安全，避免对齐和端序问题。
 */
uint16_t dns_packet_get_id(const ubyte* packet, size_t packet_len);

/*
 * 改写 DNS Header 的 ID 字段。
 *
 * 中继场景必须改写 ID：
 *   客户端原 ID -> 本程序生成的新 forward_id -> 外部 DNS
 * 外部响应回来后，再改回客户端原 ID。
 */
int dns_packet_set_id(ubyte* packet, size_t packet_len, uint16_t id);

/*
 * 解析 DNS 查询报文中的第一个 Question。
 *
 * 后续实现时建议只接受最小范围：
 *   - 标准查询 OPCODE=0
 *   - QDCOUNT >= 1
 *   - 至少能解析第一个 QNAME/QTYPE/QCLASS
 *
 * QNAME 编码示例：
 *   www.bupt.edu.cn
 *   -> 03 'w' 'w' 'w' 04 'b' 'u' 'p' 't' 03 'e' 'd' 'u' 02 'c' 'n' 00
 *
 * 解析时必须做边界检查，防止错误报文导致越界读。
 */
int dns_packet_parse_question(const ubyte* packet,
                              size_t packet_len,
                              dns_question_t* question);

/*
 * 构造本地命中普通 IP 时的 A 记录响应。
 *
 * ipv4_network_order 必须已经是网络字节序，通常来自 inet_pton()。
 * 典型响应结构：
 *   Header + 原 Question + 1 条 Answer RR
 *
 * Answer 的 NAME 可使用压缩指针 0xC00C，指向报文偏移 12 处的原 QNAME。
 * 这是 DNS 实现里常见 trick：不用重复写一遍域名，响应更短。
 */
int dns_packet_build_a_response(const ubyte* query,
                                size_t query_len,
                                uint32_t ipv4_network_order,
                                ubyte* response,
                                size_t response_capacity,
                                size_t* response_len);

/*
 * 构造拦截响应。
 *
 * PPT 要求表中命中 0.0.0.0 时返回“域名不存在”，不要返回 0.0.0.0 的 A 记录。
 * 因此这里应设置 QR=1、RCODE=3、ANCOUNT=0，并保留原 Question。
 */
int dns_packet_build_nxdomain_response(const ubyte* query,
                                       size_t query_len,
                                       ubyte* response,
                                       size_t response_capacity,
                                       size_t* response_len);

#endif
