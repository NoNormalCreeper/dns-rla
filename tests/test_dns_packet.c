#include "dns_packet.h"

#include <assert.h>
#include <string.h>

int main(void) {
    ubyte packet[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00};
    ubyte original_tail[sizeof(packet) - 2];
    ubyte too_short[1] = {0};

    memcpy(original_tail, packet + 2, sizeof(original_tail));

    assert(dns_packet_get_id(packet, sizeof(packet)) == 0x1234);
    assert(dns_packet_set_id(packet, sizeof(packet), 0xabcd) == 0);
    assert(packet[0] == 0xab);
    assert(packet[1] == 0xcd);
    assert(dns_packet_get_id(packet, sizeof(packet)) == 0xabcd);
    assert(memcmp(packet + 2, original_tail, sizeof(original_tail)) == 0);

    assert(dns_packet_get_id(too_short, sizeof(too_short)) == 0);
    assert(dns_packet_set_id(too_short, sizeof(too_short), 0x1111) == -1);

    return 0;
}
