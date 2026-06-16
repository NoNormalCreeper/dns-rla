#include "dns_packet.h"
#include "common.h"
#include "logger.h"

#include <arpa/inet.h>

#include <ctype.h>
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

__attribute__((unused)) static uint32_t dns_packet_read_u32(
    const ubyte* start) {
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

/*
 * 从 packet[start_offset] 开始安全遍历 DNS QNAME 标签，直到遇到 0x00 终止符。
 *
 * 同时执行：
 *   - 报文边界检查（每一步都确保读指针不越 packet 边界）
 *   - 标签长度合法性检查（≤ 63，拒绝压缩指针 0xC0xx 和保留值）
 *   - 终止符检查（必须有 0x00，不会无限循环）
 *
 * 若 qname_buf 非 NULL：
 *   将标签解码为点分字符串写入 qname_buf，例如 "www.bupt.cn"。
 *   注意：不在此函数内做大小写转换或域名合法性校验——这些由调用方负责。
 *
 * 若 qname_buf 为 NULL：
 *   只做验证和定位，不输出字符串。
 *
 * 成功时：*end_offset 指向 0x00 终止符之后第一个字节（即 QTYPE 起始位置），返回
 * 0。 失败时：返回 -1。
 */
static int dns_skip_qname(const ubyte* packet,
                          size_t packet_len,
                          size_t start_offset,
                          char* qname_buf,
                          size_t qname_buf_size,
                          size_t* end_offset) {
    size_t pos = start_offset;
    char* dst = qname_buf;
    const char* const dst_end =
        qname_buf ? qname_buf + qname_buf_size - 1 : NULL;
    int first = 1;

    while (1) {
        ubyte label_len;

        if (pos >= packet_len) {
            logger_error("[%s]: Expecting length byte or 0x00 for label",
                         __func__);
            return -1;
        }

        label_len = packet[pos];

        if (label_len == 0x00) {
            if (dst) {
                *dst = '\0';
            }
            *end_offset = pos + 1;
            return 0;
        }

        if (64 <= label_len) {
            logger_error("[%s]: Label length too long: %u", __func__,
                         label_len);
            return -1;
        }

        /* 跳过长度字节 */
        pos += 1;

        /* 标签内容不能超出报文边界 */
        if (pos + label_len > packet_len) {
            logger_error("[%s]: Label content longer than packet", __func__);
            return -1;
        }

        /* 写出点分形式 */
        if (dst) {
            if (!(first)) {
                if (dst < dst_end) {
                    *dst++ = '.';
                } else {
                    logger_error("[%s]: Output domain buffer overflow",
                                 __func__);
                    return -1;
                }
            }
            first = 0;

            if ((size_t)(dst_end - dst) < label_len) {
                logger_error("[%s]: Output domain buffer overflow", __func__);
                return -1;
            }
            memcpy(dst, packet + pos, label_len);
            dst += label_len;
        }

        pos += label_len;
    }
}

/* 例如 count = 5 时返回的数值是 0b0000'0000'0001'1111 */
static uint16_t dns_packet_ones_16(size_t count) {
    return ~((uint16_t)(~0) << count);
}

static uint16_t dns_packet_flags_modify(uint16_t flags,
                                        size_t bit_index,
                                        size_t bit_length,
                                        uint16_t val) {
    uint16_t src_keep;
    uint16_t dest_keep;

    src_keep = dns_packet_ones_16(bit_length);
    dest_keep = ~(src_keep << bit_index);

    return (flags & dest_keep) | ((val & src_keep) << bit_index);
}

__attribute__((unused)) static uint16_t
dns_packet_flags_get(uint16_t flags, size_t bit_index, size_t bit_length) {
    return (flags >> bit_index) & dns_packet_ones_16(bit_length);
}

uint16_t dns_packet_get_id(const ubyte* packet, size_t packet_len) {
    /*
     * DNS ID 在报文开头两个字节。
     * 长度不够说明这不是合法 DNS Header，骨架里返回 0 作为安全默认值。
     */
    if (packet_len < DNS_ID_INDEX + 2) {
        logger_warning("[%s]: Packet too short (length = %zu) to get id",
                       __func__, packet_len);
        return 0;
    }

    /* 使用了专门的、能够正确处理字节序的 u16 读取函数 */
    return dns_packet_read_u16(packet + DNS_ID_INDEX);
}

int dns_packet_set_id(ubyte* packet, size_t packet_len, uint16_t id) {
    /* 改写 ID 前也必须检查长度，避免收到短包时越界写。 */
    if (packet_len < DNS_ID_INDEX + 2) {
        logger_warning("[%s]: Packet too short (length = %zu) to set id",
                       __func__, packet_len);
        return -1;
    }

    /* 使用了专门的、能够正确处理字节序的 u16 写入函数 */
    dns_packet_write_u16(packet + DNS_ID_INDEX, id);
    return 0;
}

int dns_packet_parse_query(const ubyte* packet,
                           size_t packet_len,
                           dns_query_t* query) {
    uint16_t qdcount;
    size_t qtype_pos;

    /* Header */
    if (packet_len < DNS_HEADER_SIZE) {
        logger_error("[%s]: Packet length shorter than a header (length = %zu)",
                     __func__, packet_len);
        return -1;
    }
    query->id = dns_packet_get_id(packet, packet_len);

    /* QDCOUNT */
    qdcount = dns_packet_read_u16(packet + DNS_QDCOUNT_INDEX);
    if (qdcount != 1) {
        logger_error("[%s]: Question count not 1 (qdcount = %hu)", __func__,
                     qdcount);
        return -1;
    }

    /* QNAME */
    if (dns_skip_qname(packet, packet_len, DNS_HEADER_SIZE, query->qname,
                       sizeof query->qname, &qtype_pos) != 0) {
        logger_error("[%s]: Invalid qname", __func__);
        return -1;
    }

    /* 域名规范化 */
    normalize_domain(query->qname);

    logger_debug("[%s]: Normalized qname: %s", __func__, query->qname);

    /* QTYPE, QCLASS */
    if (qtype_pos + 4 > packet_len) {
        logger_error(
            "[%s]: Packet too short (length = %zu) to get qtype and qclass",
            __func__, packet_len);
        return -1;
    }
    query->qtype = dns_packet_read_u16(packet + qtype_pos);
    query->qclass = dns_packet_read_u16(packet + qtype_pos + 2);

    return 0;
}

int dns_packet_build_a_response(const ubyte* query,
                                size_t query_len,
                                uint32_t ipv4_network_order,
                                ubyte* response,
                                size_t response_capacity,
                                size_t* response_len) {
    /*
     * 构造本地 A 记录响应。
     *
     * 响应结构：Header(12) + Question(变长) + AnswerRR(16)
     *
     * Answer RR 各字段：
     *   NAME     2B  压缩指针 0xC00C，指向偏移 12 处的原 QNAME
     *   TYPE     2B  DNS_TYPE_A (1)
     *   CLASS    2B  DNS_CLASS_IN (1)
     *   TTL      4B  300 秒
     *   RDLENGTH 2B  4
     *   RDATA    4B  IPv4 地址（网络字节序）
     */

    /* Answer RR 固定大小：NAME(2) + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) +
     * RDATA(4) */
    const size_t answer_a_size = 16;

    size_t qtype_pos;
    size_t question_end;
    uint16_t flags;
    ubyte* wp;

    /* 直接定位到 Question 结束，顺带检查 Question 合法性 */
    if (dns_skip_qname(query, query_len, DNS_HEADER_SIZE, NULL, 0,
                       &qtype_pos) != 0) {
        logger_error("[%s]: Invalid query qname", __func__);
        return -1;
    }
    question_end = qtype_pos + 4; /* QTYPE(2) + QCLASS(2) */

    if (question_end > query_len) {
        logger_error(
            "[%s]: Query too short for QTYPE/QCLASS "
            "(need %zu, have %zu)",
            __func__, question_end, query_len);
        return -1;
    }

    if (response_capacity < question_end + answer_a_size) {
        logger_error(
            "[%s]: Response buffer too small "
            "(need %zu, capacity %zu)",
            __func__, question_end + answer_a_size, response_capacity);
        return -1;
    }

    /* 复制 Header 和 Question 部分 */
    memcpy(response, query, question_end);
    wp = response + question_end;

    /* 修改 Header */
    flags = dns_packet_read_u16(response + DNS_FLAGS_INDEX);
    flags = dns_packet_flags_modify(flags, DNS_FLAGS_QR_BIT_INDEX,
                                    DNS_FLAGS_QR_BIT_SIZE, 1);
    flags = dns_packet_flags_modify(flags, DNS_FLAGS_RA_BIT_INDEX,
                                    DNS_FLAGS_RA_BIT_SIZE, 1);
    flags =
        dns_packet_flags_modify(flags, DNS_FLAGS_RCODE_BIT_INDEX,
                                DNS_FLAGS_RCODE_BIT_SIZE, DNS_RCODE_NOERROR);
    dns_packet_write_u16(response + DNS_FLAGS_INDEX, flags);
    dns_packet_write_u16(response + DNS_QDCOUNT_INDEX, 1);
    dns_packet_write_u16(response + DNS_ANCOUNT_INDEX, 1);
    dns_packet_write_u16(response + DNS_NSCOUNT_INDEX, 0);
    dns_packet_write_u16(response + DNS_ARCOUNT_INDEX, 0);

    /*
     * == 添加 Answer ==
     * NAME = 压缩指针;
     * TYPE = A;
     * CLASS = IN;
     * TTL = 300 秒;
     * RDLENGTH = 4;
     * RDATA = 参数里那个地址
     */
    dns_packet_write_u16(wp, 0xC00C);
    wp += 2;
    dns_packet_write_u16(wp, DNS_TYPE_A);
    wp += 2;
    dns_packet_write_u16(wp, DNS_CLASS_IN);
    wp += 2;
    dns_packet_write_u32(wp, 300);
    wp += 4;
    dns_packet_write_u16(wp, 4);
    wp += 2;
    /* 参数传入的已经是网络字节序了。所以直接 memcpy 不用中间的
     * dns_packet_write_u16 */
    memcpy(wp, &ipv4_network_order, 4);
    wp += 4;

    *response_len = (size_t)(wp - response);

    logger_debug("[%s]: Built A response (%zu bytes), id=%u", __func__,
                 *response_len, dns_packet_get_id(response, *response_len));

    return 0;
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
    size_t qtype_pos;
    size_t question_end;
    uint16_t flags;

    /* 依旧直接定位到 Question 结束，顺带检查 Question 合法性 */
    if (dns_skip_qname(query, query_len, DNS_HEADER_SIZE, NULL, 0,
                       &qtype_pos) != 0) {
        logger_error("[%s]: Invalid query qname", __func__);
        return -1;
    }
    question_end = qtype_pos + 4; /* QTYPE(2) + QCLASS(2) */

    if (question_end > query_len) {
        logger_error(
            "[%s]: Query too short for QTYPE/QCLASS "
            "(need %zu, have %zu)",
            __func__, question_end, query_len);
        return -1;
    }

    if (response_capacity < question_end) {
        logger_error(
            "[%s]: Response buffer too small "
            "(need %zu, capacity %zu)",
            __func__, question_end, response_capacity);
        return -1;
    }

    /* 依旧复制 Header 和 Question 部分 */
    memcpy(response, query, question_end);

    /* 依旧修改 Header */
    flags = dns_packet_read_u16(response + DNS_FLAGS_INDEX);
    flags = dns_packet_flags_modify(flags, DNS_FLAGS_QR_BIT_INDEX,
                                    DNS_FLAGS_QR_BIT_SIZE, 1);
    flags = dns_packet_flags_modify(flags, DNS_FLAGS_RA_BIT_INDEX,
                                    DNS_FLAGS_RA_BIT_SIZE, 1);
    flags =
        dns_packet_flags_modify(flags, DNS_FLAGS_RCODE_BIT_INDEX,
                                DNS_FLAGS_RCODE_BIT_SIZE, DNS_RCODE_NXDOMAIN);
    dns_packet_write_u16(response + DNS_FLAGS_INDEX, flags);
    dns_packet_write_u16(response + DNS_QDCOUNT_INDEX, 1);
    dns_packet_write_u16(response + DNS_ANCOUNT_INDEX, 0);
    dns_packet_write_u16(response + DNS_NSCOUNT_INDEX, 0);
    dns_packet_write_u16(response + DNS_ARCOUNT_INDEX, 0);

    *response_len = question_end;

    logger_debug("[%s]: Built NXDOMAIN response (%zu bytes), id=%u", __func__,
                 *response_len, dns_packet_get_id(response, *response_len));

    return 0;
}
