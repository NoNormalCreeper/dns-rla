#include "relay_state.h"
#include "test_support.h"

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>

static struct sockaddr_in make_ipv4_client(const char* ip, uint16_t port) {
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    TEST_CHECK_EQ_INT(inet_pton(AF_INET, ip, &addr.sin_addr), 1);

    return addr;
}

static void check_ipv4_client(const pending_query_t* query,
                              const struct sockaddr_in* expected) {
    const struct sockaddr_in* actual =
        (const struct sockaddr_in*)&query->client_addr;

    TEST_CHECK_EQ_SIZE(query->client_addr_len, sizeof(*expected));
    TEST_CHECK_EQ_INT(actual->sin_family, expected->sin_family);
    TEST_CHECK_EQ_U16(ntohs(actual->sin_port), ntohs(expected->sin_port));
    TEST_CHECK_EQ_U32(actual->sin_addr.s_addr, expected->sin_addr.s_addr);
}

static void check_query_identity(const pending_query_t* query,
                                 const char* expected_qname,
                                 uint16_t expected_qtype,
                                 uint16_t expected_qclass) {
    TEST_CHECK_EQ_STR(query->qname, expected_qname);
    TEST_CHECK_EQ_U16(query->qtype, expected_qtype);
    TEST_CHECK_EQ_U16(query->qclass, expected_qclass);
}

static void test_next_id_skips_in_use_ids(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("192.0.2.10", 53000);
    uint16_t forward_id = 0;

    relay_state_init(&state);
    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 1, 0x1234, (const struct sockaddr*)&client,
                        sizeof(client), "first.test", DNS_TYPE_A, DNS_CLASS_IN),
        0);

    TEST_CHECK_EQ_INT(relay_state_next_id(&state, &forward_id), 0);
    TEST_CHECK_EQ_U16(forward_id, 2);
}

static void test_next_id_wraps_without_returning_zero(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("192.0.2.11", 53001);
    uint16_t forward_id = 0;

    relay_state_init(&state);
    TEST_CHECK_EQ_INT(
        relay_state_add(&state, UINT16_MAX, 0x1234,
                        (const struct sockaddr*)&client, sizeof(client),
                        "wrap.test", DNS_TYPE_A, DNS_CLASS_IN),
        0);
    state.next_id = UINT16_MAX;

    TEST_CHECK_EQ_INT(relay_state_next_id(&state, &forward_id), 0);
    TEST_CHECK_EQ_U16(forward_id, 1);
}

static void test_add_find_and_remove_preserve_client_info(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("203.0.113.7", 53530);
    pending_query_t* query;

    relay_state_init(&state);

    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 0x2222, 0x1234, (const struct sockaddr*)&client,
                        sizeof(client), "www.example.com", DNS_TYPE_A,
                        DNS_CLASS_IN),
        0);

    query = relay_state_find(&state, 0x2222);
    TEST_CHECK(query != NULL);
    TEST_CHECK_EQ_INT(query->in_use, 1);
    TEST_CHECK_EQ_U16(query->forward_id, 0x2222);
    TEST_CHECK_EQ_U16(query->client_id, 0x1234);
    check_ipv4_client(query, &client);
    check_query_identity(query, "www.example.com", DNS_TYPE_A, DNS_CLASS_IN);

    relay_state_remove(&state, 0x2222);
    TEST_CHECK(relay_state_find(&state, 0x2222) == NULL);
}

static void test_expire_removes_only_timed_out_entries(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("198.51.100.8", 53002);
    pending_query_t* expired;
    pending_query_t* active;
    time_t now = 1000;
    size_t expired_count = 0;

    relay_state_init(&state);

    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 0x3333, 0x0101, (const struct sockaddr*)&client,
                        sizeof(client), "expired.test", DNS_TYPE_A,
                        DNS_CLASS_IN),
        0);
    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 0x4444, 0x0202, (const struct sockaddr*)&client,
                        sizeof(client), "active.test", 28, DNS_CLASS_IN),
        0);

    expired = relay_state_find(&state, 0x3333);
    active = relay_state_find(&state, 0x4444);
    TEST_CHECK(expired != NULL);
    TEST_CHECK(active != NULL);
    check_query_identity(expired, "expired.test", DNS_TYPE_A, DNS_CLASS_IN);
    check_query_identity(active, "active.test", 28, DNS_CLASS_IN);
    expired->created_at = now - DNS_RELAY_PENDING_TIMEOUT_SEC - 1;
    active->created_at = now;

    expired_count = relay_state_expire(&state, now);

    TEST_CHECK_EQ_SIZE(expired_count, 1);
    TEST_CHECK(relay_state_find(&state, 0x3333) == NULL);
    TEST_CHECK(relay_state_find(&state, 0x4444) != NULL);
}

static void test_add_rejects_qname_longer_than_dns_limit(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("192.0.2.19", 53019);
    char qname[DNS_MAX_DOMAIN_LEN + 2];

    memset(qname, 'a', sizeof(qname) - 1);
    qname[sizeof(qname) - 1] = '\0';
    relay_state_init(&state);

    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 0x5555, 0x0303, (const struct sockaddr*)&client,
                        sizeof(client), qname, DNS_TYPE_A, DNS_CLASS_IN),
        -1);
    TEST_CHECK(relay_state_find(&state, 0x5555) == NULL);
}

static void test_add_fails_when_pending_table_is_full(void) {
    relay_state_t state;
    struct sockaddr_in client = make_ipv4_client("192.0.2.20", 53020);
    size_t i;

    relay_state_init(&state);

    for (i = 0; i < DNS_RELAY_MAX_PENDING; i++) {
        TEST_CHECK_EQ_INT(
            relay_state_add(&state, (uint16_t)(i + 1), (uint16_t)(0x4000 + i),
                            (const struct sockaddr*)&client, sizeof(client),
                            "full.test", DNS_TYPE_A, DNS_CLASS_IN),
            0);
    }

    TEST_CHECK_EQ_INT(
        relay_state_add(&state, 0xffff, 0x9999, (const struct sockaddr*)&client,
                        sizeof(client), "overflow.test", DNS_TYPE_A,
                        DNS_CLASS_IN),
        -1);
}

int main(void) {
    test_next_id_skips_in_use_ids();
    test_next_id_wraps_without_returning_zero();
    test_add_find_and_remove_preserve_client_info();
    test_expire_removes_only_timed_out_entries();
    test_add_rejects_qname_longer_than_dns_limit();
    test_add_fails_when_pending_table_is_full();

    return 0;
}
