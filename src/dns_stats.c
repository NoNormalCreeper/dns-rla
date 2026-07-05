#include "dns_stats.h"

#include <inttypes.h>
#include <string.h>

#include "logger.h"

void dns_stats_init(dns_stats_t* stats) {
    if (stats == NULL) {
        return;
    }

    memset(stats, 0, sizeof(*stats));
}

void dns_stats_log_summary(const dns_stats_t* stats) {
    if (stats == NULL) {
        return;
    }

    logger_info("stats: total=%" PRIu64 " local=%" PRIu64 " blocked=%" PRIu64
                " cache_hit=%" PRIu64 " cache_miss=%" PRIu64,
                stats->queries_total, stats->local_address_hits,
                stats->blocked_hits, stats->cache_hits, stats->cache_misses);

    logger_info("stats: forwarded=%" PRIu64 " upstream=%" PRIu64
                " sent=%" PRIu64 " invalid=%" PRIu64 " late=%" PRIu64
                " expired=%" PRIu64,
                stats->forwarded_queries, stats->upstream_responses,
                stats->responses_sent, stats->invalid_queries,
                stats->unknown_or_late_responses, stats->expired_pending);
}
