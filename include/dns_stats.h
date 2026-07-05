#ifndef DNS_RELAY_DNS_STATS_H
#define DNS_RELAY_DNS_STATS_H

#include <stdint.h>

/*
 * 运行时统计。
 * 第一版先做简单计数，方便验收时解释查询路径和 cache 行为。
 */
typedef struct {
    /* 进入主处理路径的客户端查询总数。 */
    uint64_t queries_total;

    /* 静态表命中普通 IPv4 地址的次数。 */
    uint64_t local_address_hits;

    /* 静态表命中 0.0.0.0，返回 NXDOMAIN 的次数。 */
    uint64_t blocked_hits;

    /* 命中运行时缓存、无需访问上游 DNS 的次数。 */
    uint64_t cache_hits;

    /* 没命中缓存，需要继续走静态表或上游路径的次数。 */
    uint64_t cache_misses;

    /* 实际转发到上游 DNS 的次数。 */
    uint64_t forwarded_queries;

    /* 收到上游 DNS 响应的次数。 */
    uint64_t upstream_responses;

    /* 成功发回客户端的响应次数。 */
    uint64_t responses_sent;

    /* 非法或无法解析的客户端查询次数。 */
    uint64_t invalid_queries;

    /* 收到未知、迟到或已过期 pending 对应响应的次数。 */
    uint64_t unknown_or_late_responses;

    /* 超时清理掉的 pending 数量。 */
    uint64_t expired_pending;
} dns_stats_t;

/* 初始化统计结构体，全部计数清零。 */
void dns_stats_init(dns_stats_t* stats);

/*
 * 打印一份摘要，便于 -d / -dd 演示时快速查看整体行为。
 * 该函数只负责展示，不在这里做计数逻辑判断。
 */
void dns_stats_log_summary(const dns_stats_t* stats);

#endif
