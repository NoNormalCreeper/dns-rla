#include "hosts_table.h"
#include "test_support.h"

#include <arpa/inet.h>
#include <stdio.h>

static void write_fixture(const char* path) {
    FILE* fp = fopen(path, "w");
    int close_result;

    TEST_CHECK(fp != NULL);

    fputs("192.0.2.10 Example.COM\n", fp);
    fputs("0.0.0.0 blocked.test\n", fp);
    fputs("not-an-ip ignored.test\n", fp);

    close_result = fclose(fp);
    TEST_CHECK_EQ_INT(close_result, 0);
}

int main(void) {
    const char* fixture_path = "build/test-hosts-table.txt";
    hosts_table_t table;
    hosts_lookup_result_t result;
    struct in_addr expected_addr;

    write_fixture(fixture_path);

    TEST_CHECK_EQ_INT(hosts_table_init(&table), 0);
    TEST_CHECK_EQ_INT(hosts_table_load(&table, fixture_path), 0);
    TEST_CHECK_EQ_SIZE(table.count, 2);

    TEST_CHECK_EQ_INT(inet_pton(AF_INET, "192.0.2.10", &expected_addr), 1);
    result = hosts_table_lookup(&table, "example.com");
    TEST_CHECK_EQ_INT(result.kind, HOSTS_LOOKUP_ADDRESS);
    TEST_CHECK_EQ_U32(result.ipv4_network_order, expected_addr.s_addr);

    result = hosts_table_lookup(&table, "EXAMPLE.COM");
    TEST_CHECK_EQ_INT(result.kind, HOSTS_LOOKUP_ADDRESS);
    TEST_CHECK_EQ_U32(result.ipv4_network_order, expected_addr.s_addr);

    result = hosts_table_lookup(&table, "blocked.test");
    TEST_CHECK_EQ_INT(result.kind, HOSTS_LOOKUP_BLOCKED);

    result = hosts_table_lookup(&table, "missing.test");
    TEST_CHECK_EQ_INT(result.kind, HOSTS_LOOKUP_MISS);

    hosts_table_free(&table);
    return 0;
}
