#ifndef DNS_RELAY_DNS_CACHE_H
#define DNS_RELAY_DNS_CACHE_H

#include <time.h>

#include "dns_packet.h"

/*
 * 第一版缓存使用固定容量。
 * 课程设计场景里几十条热门域名已经足够演示“首次 miss、再次 hit、过期失效”。
 */
#define DNS_CACHE_CAPACITY 64

typedef struct {
    /* 查询域名，使用归一化后的小写点分格式。 */
    char qname[DNS_MAX_DOMAIN_LEN + 1];

    /* 只缓存同一个 qtype/qclass 下的结果，避免不同查询串包。 */
    uint16_t qtype;
    uint16_t qclass;
} dns_cache_key_t;

typedef struct {
    /* 该槽位是否已写入有效缓存。 */
    int in_use;

    /* 这一条缓存对应哪个查询键。 */
    dns_cache_key_t key;

    /*
     * 直接保存完整 DNS response 字节包。
     * cache hit 时由调用方复制出来，再把 ID 改成本次客户端请求 ID。
     */
    ubyte response[DNS_MAX_PACKET_SIZE];
    size_t response_len;

    /* 绝对过期时间，由上游响应里的 TTL 决定。 */
    time_t expires_at;
} dns_cache_entry_t;

typedef struct {
    /* 固定数组实现简单、容易讲解，也不需要额外内存管理。 */
    dns_cache_entry_t entries[DNS_CACHE_CAPACITY];

    /* 满表后的下一个替换位置，第一版使用简单轮转策略。 */
    size_t next_replace;
} dns_cache_t;

/* 初始化空缓存。 */
void dns_cache_init(dns_cache_t* cache);

/*
 * 查询缓存。
 *
 * 返回值约定：
 *   0 命中，并把 response 复制到调用方缓冲区，response_len 是实际拷贝长度
 *  -1 未命中、已过期，或输出缓冲区不足
 *  -2 输出缓冲区不足，同时把所需长度写到 *response_len
 */
int dns_cache_get(const dns_cache_t* cache,
                  const dns_cache_key_t* key,
                  time_t now,
                  ubyte* response,
                  size_t response_capacity,
                  size_t* response_len);

/*
 * 写入缓存。
 *
 * expires_at 由调用方根据上游响应里的 TTL 计算得到。
 * 第一版不在这里解析 DNS 报文，只负责保存字节包和过期时间。
 */
int dns_cache_put(dns_cache_t* cache,
                  const dns_cache_key_t* key,
                  const ubyte* response,
                  size_t response_len,
                  time_t expires_at);

#endif
