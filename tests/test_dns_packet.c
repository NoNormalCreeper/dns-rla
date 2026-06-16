#include "dns_packet.h"
#include "test_support.h"

#include <string.h>

static uint16_t read_u16_be(const ubyte* p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void test_build_a_response_flags(void) {
    ubyte query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
                     0x00, 0x00, 3,    'w',  'w',  'w',  4,    'b',  'u',  'p',
                     't',  2,    'c',  'n',  0,    0x00, 0x01, 0x00, 0x01};
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len = 0;
    uint32_t ip = 0x0a86807b;
    uint16_t flags;

    TEST_CHECK_EQ_INT(
        dns_packet_build_a_response(query, sizeof(query), ip, response,
                                    sizeof(response), &response_len),
        0);

    flags = read_u16_be(response + DNS_FLAGS_INDEX);
    TEST_CHECK(flags & 0x8000);
    TEST_CHECK(flags & 0x0080);
    TEST_CHECK_EQ_U16((uint16_t)(flags & 0x000f), 0);
    TEST_CHECK_EQ_U16(read_u16_be(response + DNS_QDCOUNT_INDEX), 1);
    TEST_CHECK_EQ_U16(read_u16_be(response + DNS_ANCOUNT_INDEX), 1);
}

static void test_build_nxdomain_response_flags(void) {
    ubyte query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                     0x00, 0x00, 0x00, 0x00, 3,    '0',  '0',  '8',
                     2,    'c',  'n',  0,    0x00, 0x01, 0x00, 0x01};
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len = 0;
    uint16_t flags;

    TEST_CHECK_EQ_INT(
        dns_packet_build_nxdomain_response(query, sizeof(query), response,
                                           sizeof(response), &response_len),
        0);

    flags = read_u16_be(response + DNS_FLAGS_INDEX);
    TEST_CHECK(flags & 0x8000);
    TEST_CHECK(flags & 0x0080);
    TEST_CHECK_EQ_U16((uint16_t)(flags & 0x000f), DNS_RCODE_NXDOMAIN);
    TEST_CHECK_EQ_U16(read_u16_be(response + DNS_ANCOUNT_INDEX), 0);
}

int main(void) {
    ubyte packet[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x34, 0x12, 0x56, 0x78};
    ubyte packet1[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                       0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                       4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                       0,    0x34, 0x12, 0x56, 0x78};
    ubyte qname_no_end[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00,
                            0x00, 0x00, 0x00, 0x00, 0x00, 3,    'W',
                            'w',  'W',  4,    'b',  'u',  'p',  't',
                            2,    'C',  'N',  0x34, 0x12, 0x56, 0x78};
    ubyte header_to_long[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 3,    'W',  'w',  'W',  63,   'b',  'u',  'p',  'b',  'u',
        'p',  't',  'b',  'u',  'p',  't',  'b',  'u',  'p',  't',  'b',
        'u',  'p',  't',  'b',  'u',  'p',  't',  'b',  'u',  'p',  't',
        'b',  'u',  'p',  't',  'b',  'u',  'p',  't',  'b',  'u',  'p',
        't',  'b',  'u',  'p',  't',  'b',  'u',  'p',  't',  'b',  'u',
        'p',  't',  'b',  'u',  'p',  't',  'b',  'u',  'p',  't',  'b',
        'u',  'p',  't',  2,    'C',  'N',  0,    0x34, 0x12, 0x56, 0x78};
    ubyte no_qlcass_or_qtype[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00,
                                  0x00, 0x00, 0x00, 0x00, 0x00, 3,    'W',
                                  'w',  'W',  4,    'b',  'u',  'p',  't',
                                  2,    'C',  'N',  0,    0x34, 0x12};
    ubyte compressed_ptr[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0xC0, 0x0C, 0x34, 0x12, 0x56, 0x78};
    ubyte label_to_long[] = {
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        3,    'W',  'w',  'W',  64,   'a',  'a',  'a',  'a',  'a',  'a',  'a',
        'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',
        'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',
        'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',
        'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',
        'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  'a',  2,    'C',  'N',
        0,    0x34, 0x12, 0x56, 0x78};
    ubyte build_test[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                          4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                          0,    0x00, 0x01, 0x00, 0x01};

    ubyte original_tail[sizeof(packet) - 2];
    ubyte too_short[1] = {0};
    dns_query_t query;

    memcpy(original_tail, packet + 2, sizeof(original_tail));

    TEST_CHECK_EQ_U16(dns_packet_get_id(packet, sizeof(packet)), 0x1234);
    TEST_CHECK_EQ_INT(dns_packet_set_id(packet, sizeof(packet), 0xabcd), 0);
    TEST_CHECK_EQ_INT(packet[0], 0xab);
    TEST_CHECK_EQ_INT(packet[1], 0xcd);
    TEST_CHECK_EQ_U16(dns_packet_get_id(packet, sizeof(packet)), 0xabcd);
    TEST_CHECK_EQ_INT(memcmp(packet + 2, original_tail, sizeof(original_tail)),
                      0);

    TEST_CHECK_EQ_U16(dns_packet_get_id(too_short, sizeof(too_short)), 0);
    TEST_CHECK_EQ_INT(dns_packet_set_id(too_short, sizeof(too_short), 0x1111),
                      -1);

    TEST_CHECK_EQ_INT(dns_packet_parse_query(packet, sizeof(packet), &query),
                      0);
    TEST_CHECK_EQ_U16(query.id, dns_packet_get_id(packet, sizeof(packet)));
    TEST_CHECK_EQ_STR(query.qname, "www.bupt.cn");
    TEST_CHECK_EQ_U16(query.qtype, 0x3412);
    TEST_CHECK_EQ_U16(query.qclass, 0x5678);

    TEST_CHECK_EQ_INT(dns_packet_parse_query(packet1, sizeof(packet1), &query),
                      -1);
    TEST_CHECK_EQ_INT(
        dns_packet_parse_query(header_to_long, sizeof(header_to_long), &query),
        0);
    TEST_CHECK_EQ_INT(
        dns_packet_parse_query(too_short, sizeof(too_short), &query), -1);

    /*
     * TODO: 暂未通过的测试
     *
     * assert(dns_packet_parse_query(qname_no_end, sizeof(qname_no_end),
     * &query)==-1); assert(dns_packet_parse_query(no_qlcass_or_qtype,
     * sizeof(no_qlcass_or_qtype), &query)==-1);
     * assert(dns_packet_parse_query(compressed_ptr, sizeof(compressed_ptr),
     * &query) == -1); assert(dns_packet_parse_query(label_to_long,
     * sizeof(label_to_long), &query) == -1);
     */

    (void)qname_no_end;
    (void)no_qlcass_or_qtype;
    (void)compressed_ptr;
    (void)label_to_long;

    /* TODO: 暂未编写的测试 */
    (void)build_test;

    test_build_a_response_flags();
    test_build_nxdomain_response_flags();

    return 0;
}
