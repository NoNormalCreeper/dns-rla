#include "dns_cache.h"
#include "test_support.h"

#include <string.h>
#include <time.h>

static dns_cache_key_t make_key(const char* qname,
                                uint16_t qtype,
                                uint16_t qclass) {
    dns_cache_key_t key;

    memset(&key, 0, sizeof(key));
    strncpy(key.qname, qname, sizeof(key.qname) - 1);
    key.qtype = qtype;
    key.qclass = qclass;
    return key;
}

static void fill_response(ubyte* response, size_t response_len, ubyte seed) {
    size_t i;

    for (i = 0; i < response_len; i++) {
        response[i] = (ubyte)(seed + i);
    }
}

static void test_init_clears_all_entries(void) {
    dns_cache_t cache;
    size_t i;

    memset(&cache, 0x7f, sizeof(cache));
    dns_cache_init(&cache);

    TEST_CHECK_EQ_SIZE(cache.next_replace, 0);
    for (i = 0; i < DNS_CACHE_CAPACITY; i++) {
        TEST_CHECK_EQ_INT(cache.entries[i].in_use, 0);
        TEST_CHECK_EQ_SIZE(cache.entries[i].response_len, 0);
        TEST_CHECK_EQ_INT((int)cache.entries[i].expires_at, 0);
    }
}

static void test_get_misses_on_empty_cache(void) {
    dns_cache_t cache;
    dns_cache_key_t key = make_key("www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len = 0;

    dns_cache_init(&cache);

    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &key, 100, response,
                                    sizeof(response), &response_len),
                      -1);
}

static void test_put_then_get_round_trips_response(void) {
    dns_cache_t cache;
    dns_cache_key_t key = make_key("www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte stored[32];
    ubyte fetched[32];
    size_t fetched_len = 0;

    dns_cache_init(&cache);
    fill_response(stored, sizeof(stored), 0x20);

    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &key, stored, sizeof(stored), 200),
                      0);
    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &key, 100, fetched, sizeof(fetched),
                                    &fetched_len),
                      0);
    TEST_CHECK_EQ_SIZE(fetched_len, sizeof(stored));
    TEST_CHECK_EQ_INT(memcmp(fetched, stored, sizeof(stored)), 0);
}

static void test_get_distinguishes_qname_qtype_and_qclass(void) {
    dns_cache_t cache;
    dns_cache_key_t base =
        make_key("www.example.com", DNS_TYPE_A, DNS_CLASS_IN);
    dns_cache_key_t other_name =
        make_key("www.example.org", DNS_TYPE_A, DNS_CLASS_IN);
    dns_cache_key_t other_type = make_key("www.example.com", 28, DNS_CLASS_IN);
    dns_cache_key_t other_class = make_key("www.example.com", DNS_TYPE_A, 3);
    ubyte stored[16];
    ubyte fetched[16];
    size_t fetched_len = 0;

    dns_cache_init(&cache);
    fill_response(stored, sizeof(stored), 0x41);

    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &base, stored, sizeof(stored), 300),
                      0);

    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &other_name, 100, fetched,
                                    sizeof(fetched), &fetched_len),
                      -1);
    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &other_type, 100, fetched,
                                    sizeof(fetched), &fetched_len),
                      -1);
    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &other_class, 100, fetched,
                                    sizeof(fetched), &fetched_len),
                      -1);
}

static void test_expired_entry_is_treated_as_miss(void) {
    dns_cache_t cache;
    dns_cache_key_t key = make_key("expired.test", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte stored[16];
    ubyte fetched[16];
    size_t fetched_len = 0;

    dns_cache_init(&cache);
    fill_response(stored, sizeof(stored), 0x11);

    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &key, stored, sizeof(stored), 50),
                      0);
    TEST_CHECK_EQ_INT(
        dns_cache_get(&cache, &key, 50, fetched, sizeof(fetched), &fetched_len),
        -1);
    TEST_CHECK_EQ_INT(
        dns_cache_get(&cache, &key, 51, fetched, sizeof(fetched), &fetched_len),
        -1);
}

static void test_get_reports_needed_length_when_buffer_is_too_small(void) {
    dns_cache_t cache;
    dns_cache_key_t key = make_key("buffer.test", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte stored[24];
    ubyte fetched[8];
    size_t fetched_len = 0;

    dns_cache_init(&cache);
    fill_response(stored, sizeof(stored), 0x60);

    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &key, stored, sizeof(stored), 200),
                      0);
    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &key, 100, fetched, sizeof(fetched),
                                    &fetched_len),
                      -2);
    TEST_CHECK_EQ_SIZE(fetched_len, sizeof(stored));
}

static void test_put_rejects_packets_larger_than_dns_limit(void) {
    dns_cache_t cache;
    dns_cache_key_t key = make_key("too-large.test", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte stored[DNS_MAX_PACKET_SIZE + 1];

    dns_cache_init(&cache);
    fill_response(stored, sizeof(stored), 0x33);

    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &key, stored, sizeof(stored), 200),
                      -1);
}

static void test_round_robin_replaces_oldest_after_cache_is_full(void) {
    dns_cache_t cache;
    dns_cache_key_t first = make_key("name-0.test", DNS_TYPE_A, DNS_CLASS_IN);
    dns_cache_key_t last = make_key("overflow.test", DNS_TYPE_A, DNS_CLASS_IN);
    ubyte stored[4];
    ubyte fetched[4];
    size_t fetched_len = 0;
    size_t i;
    char name[32];

    dns_cache_init(&cache);

    for (i = 0; i < DNS_CACHE_CAPACITY; i++) {
        dns_cache_key_t key;

        memset(name, 0, sizeof(name));
        snprintf(name, sizeof(name), "name-%zu.test", i);
        key = make_key(name, DNS_TYPE_A, DNS_CLASS_IN);
        fill_response(stored, sizeof(stored), (ubyte)i);
        TEST_CHECK_EQ_INT(
            dns_cache_put(&cache, &key, stored, sizeof(stored), 500), 0);
    }

    fill_response(stored, sizeof(stored), 0xf0);
    TEST_CHECK_EQ_INT(dns_cache_put(&cache, &last, stored, sizeof(stored), 600),
                      0);

    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &first, 100, fetched,
                                    sizeof(fetched), &fetched_len),
                      -1);
    TEST_CHECK_EQ_INT(dns_cache_get(&cache, &last, 100, fetched,
                                    sizeof(fetched), &fetched_len),
                      0);
    TEST_CHECK_EQ_SIZE(fetched_len, sizeof(stored));
    TEST_CHECK_EQ_INT(memcmp(fetched, stored, sizeof(stored)), 0);
}

int main(void) {
    test_init_clears_all_entries();
    test_get_misses_on_empty_cache();
    test_put_then_get_round_trips_response();
    test_get_distinguishes_qname_qtype_and_qclass();
    test_expired_entry_is_treated_as_miss();
    test_get_reports_needed_length_when_buffer_is_too_small();
    test_put_rejects_packets_larger_than_dns_limit();
    test_round_robin_replaces_oldest_after_cache_is_full();

    return 0;
}
