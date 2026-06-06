#include "dns_packet.h"

#include <assert.h>
#include <string.h>

int main(void) {
    ubyte packet[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x34, 0x12, 0x56, 0x78};
    ubyte packet1[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x34, 0x12, 0x56, 0x78};        
    ubyte qname_no_end[]={0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                            0x34, 0x12, 0x56, 0x78};
    ubyte header_to_long[]={0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      63,  'b',  'u',  'p','b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,     0x34, 0x12, 0x56, 0x78};    
    ubyte no_qlcass_or_qtype[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x34, 0x12};    
    ubyte compressed_ptr[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0xC0, 0x0C,       
        0x34, 0x12, 0x56, 0x78};
    ubyte label_to_long[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                          64, 'a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a','a',   
                          2, 'C',  'N',
                          0, 0x34, 0x12, 0x56, 0x78};
    ubyte build_test[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x00, 0x01, 0x00, 0x01};        
    
    ubyte original_tail[sizeof(packet) - 2];
    ubyte too_short[1] = {0};
    dns_query_t query;

    memcpy(original_tail, packet + 2, sizeof(original_tail));

    assert(dns_packet_get_id(packet, sizeof(packet)) == 0x1234);
    assert(dns_packet_set_id(packet, sizeof(packet), 0xabcd) == 0);
    assert(packet[0] == 0xab);
    assert(packet[1] == 0xcd);
    assert(dns_packet_get_id(packet, sizeof(packet)) == 0xabcd);
    assert(memcmp(packet + 2, original_tail, sizeof(original_tail)) == 0);

    assert(dns_packet_get_id(too_short, sizeof(too_short)) == 0);
    assert(dns_packet_set_id(too_short, sizeof(too_short), 0x1111) == -1);

    assert(dns_packet_parse_query(packet, sizeof(packet), &query)==0);
    assert(query.id == dns_packet_get_id(packet, sizeof(packet)));
    assert(strcmp(query.qname, "www.bupt.cn") == 0);
    assert(query.qtype == 0x3412);
    assert(query.qclass == 0x5678);

    assert(dns_packet_parse_query(packet1, sizeof(packet1), &query)==-1);
    assert(dns_packet_parse_query(qname_no_end, sizeof(qname_no_end), &query)==-1);
    assert(dns_packet_parse_query(header_to_long, sizeof(header_to_long), &query)==0);
    assert(dns_packet_parse_query(no_qlcass_or_qtype, sizeof(no_qlcass_or_qtype), &query)==-1);
    assert(dns_packet_parse_query(too_short, sizeof(too_short), &query) == -1);
    assert(dns_packet_parse_query(compressed_ptr, sizeof(compressed_ptr), &query) == -1);
    assert(dns_packet_parse_query(label_to_long, sizeof(label_to_long), &query) == -1);
    return 0;
}
