#include "dns_stats.h"
#include "logger.h"
#include "test_support.h"

static void test_init_clears_all_counters(void) {
    dns_stats_t stats = {
        .queries_total = 1,
        .local_address_hits = 2,
        .blocked_hits = 3,
        .cache_hits = 4,
        .cache_misses = 5,
        .forwarded_queries = 6,
        .upstream_responses = 7,
        .responses_sent = 8,
        .invalid_queries = 9,
        .unknown_or_late_responses = 10,
        .expired_pending = 11,
    };

    dns_stats_init(&stats);

    TEST_CHECK_EQ_U32((uint32_t)stats.queries_total, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.local_address_hits, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.blocked_hits, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.cache_hits, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.cache_misses, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.forwarded_queries, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.upstream_responses, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.responses_sent, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.invalid_queries, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.unknown_or_late_responses, 0);
    TEST_CHECK_EQ_U32((uint32_t)stats.expired_pending, 0);
}

static void test_log_summary_accepts_populated_stats(void) {
    dns_stats_t stats;

    dns_stats_init(&stats);
    stats.queries_total = 12;
    stats.local_address_hits = 2;
    stats.blocked_hits = 1;
    stats.cache_hits = 4;
    stats.cache_misses = 8;
    stats.forwarded_queries = 5;
    stats.upstream_responses = 5;
    stats.responses_sent = 7;
    stats.invalid_queries = 1;
    stats.unknown_or_late_responses = 2;
    stats.expired_pending = 3;

    logger_init(DEBUG_NONE);
    logger_set_forbidden(1);
    dns_stats_log_summary(&stats);
    logger_set_forbidden(0);
}

int main(void) {
    test_init_clears_all_counters();
    test_log_summary_accepts_populated_stats();

    return 0;
}
