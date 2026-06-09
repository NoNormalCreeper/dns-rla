#include "dns_packet.h"

#include <assert.h>
#include <string.h>
#include <arpa/inet.h>

void test_dns_packet_build_a_response();
void test_dns_packet_build_nxdomain_response();

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
    
    test_dns_packet_build_a_response();
    assert(dns_packet_get_id(packet, sizeof(packet)) == 0x1234);
    assert(dns_packet_set_id(packet, sizeof(packet), 0xabcd) == 0);
    assert(packet[0] == 0xab);
    assert(packet[1] == 0xcd);
    assert(dns_packet_get_id(packet, sizeof(packet)) == 0xabcd);
    assert(memcmp(packet + 2, original_tail, sizeof(original_tail)) == 0);

    assert(dns_packet_get_id(too_short, sizeof(too_short)) == 0);
    assert(dns_packet_set_id(too_short, sizeof(too_short), 0x1111) == -1);

    assert(dns_packet_parse_query(packet, sizeof(packet), &query) == 0);
    assert(query.id == dns_packet_get_id(packet, sizeof(packet)));
    assert(strcmp(query.qname, "www.bupt.cn") == 0);
    assert(query.qtype == 0x3412);
    assert(query.qclass == 0x5678);

    assert(dns_packet_parse_query(packet1, sizeof(packet1), &query) == -1);
    assert(dns_packet_parse_query(header_to_long, sizeof(header_to_long),
                                  &query) == 0);
    assert(dns_packet_parse_query(too_short, sizeof(too_short), &query) == -1);
    assert(dns_packet_parse_query(compressed_ptr, sizeof(compressed_ptr), &query) == -1);
    assert(dns_packet_parse_query(label_to_long, sizeof(label_to_long), &query) == -1);
    return 0;
}

void test_dns_packet_build_a_response(){
    ubyte build_test[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x00, 0x01, 0x00, 0x01};  
    ubyte response[512];
    size_t response_len=0;
    uint32_t ip =inet_addr("192.0.2.1");
    ubyte tiny_buf[10];
    size_t tiny_len = 0;
   
    int rc = dns_packet_build_a_response(build_test , sizeof(build_test) , ip, response, 512, &response_len);
    assert(rc==0);
    assert(response_len==45);

    uint16_t id, flags, qdcount, ancount, nscount, arcount;

    memcpy(&id,  response + 0,  2);  id = ntohs(id);
    memcpy(&flags,   response + 2,  2);  flags   = ntohs(flags);
    memcpy(&qdcount, response + 4,  2);  qdcount = ntohs(qdcount);
    memcpy(&ancount, response + 6,  2);  ancount = ntohs(ancount);
    memcpy(&nscount, response + 8,  2);  nscount = ntohs(nscount);
    memcpy(&arcount, response + 10, 2);  arcount = ntohs(arcount);
    
    assert(id == 0x1234);
    assert(((flags>>15)&0x1)==0);//QR==0
    assert((flags&0x1)==1);//rcode==1
    assert(qdcount==1);
    assert(ancount==1);
    assert(nscount==0);
    assert(arcount==0);
    
    //question段
    size_t question_len=sizeof(build_test)-DNS_HEADER_SIZE;
    assert(memcmp(response+DNS_HEADER_SIZE,build_test+DNS_HEADER_SIZE,question_len)==0);//IP无误

    //answer字段
    size_t answer_size=DNS_HEADER_SIZE + question_len;
    assert(response[answer_size+0]==0xC0);
    assert(response[answer_size+1]==0x0C);
    assert(response[answer_size+2]==0x00);
    assert(response[answer_size+3]==0x01);
    assert(response[answer_size+4]==0x00);
    assert(response[answer_size+5]==0x01);
    assert(response[answer_size+6]==0x00);
    assert(response[answer_size+7]==0x00);
    assert(response[answer_size+8]==0x00);
    assert(response[answer_size+9]==0x3C);
    assert(response[answer_size+10]==0x00);
    assert(response[answer_size+11]==0x04);
    assert(memcmp(response+answer_size+12,&ip,4)==0);

    assert(dns_packet_build_a_response(build_test,sizeof(build_test), ip, tiny_buf, 10, &tiny_len)==-1);

}
void test_dns_packet_build_nxdomain_response(){
    ubyte build_test[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
                      0x00, 0x00, 0x00, 0x00, 3,    'W',  'w',  'W',
                      4,    'b',  'u',  'p',  't',  2,    'C',  'N',
                      0,    0x00, 0x01, 0x00, 0x01};
    ubyte response[512];
    size_t response_len=0;
    ubyte tiny_buf[10];
    size_t tiny_len = 0;

    int rc = dns_packet_build_nxdomain_response(build_test , sizeof(build_test) , response, 512, &response_len);
    assert(rc==0);
    assert(response_len==29);

    uint16_t id, flags, qdcount, ancount, nscount, arcount;

    memcpy(&id,  response + 0,  2);  id = ntohs(id);
    memcpy(&flags,   response + 2,  2);  flags   = ntohs(flags);
    memcpy(&qdcount, response + 4,  2);  qdcount = ntohs(qdcount);
    memcpy(&ancount, response + 6,  2);  ancount = ntohs(ancount);
    memcpy(&nscount, response + 8,  2);  nscount = ntohs(nscount);
    memcpy(&arcount, response + 10, 2);  arcount = ntohs(arcount);

    assert(id == 0x1234);
    assert(((flags>>15)&0x1)==1);//QR==1
    assert((flags&0xF)==3);//rcode==3(NXDOMAIN)
    assert(qdcount==1);
    assert(ancount==0);
    assert(nscount==0);
    assert(arcount==0);

    //question段
    size_t question_len=sizeof(build_test)-DNS_HEADER_SIZE;
    assert(memcmp(response+DNS_HEADER_SIZE,build_test+DNS_HEADER_SIZE,question_len)==0);

    assert(dns_packet_build_nxdomain_response(build_test,sizeof(build_test), tiny_buf, 10, &tiny_len)==-1);

}
