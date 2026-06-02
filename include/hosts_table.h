#ifndef DNS_RELAY_HOSTS_TABLE_H
#define DNS_RELAY_HOSTS_TABLE_H

#include <stddef.h>
#include <stdint.h>

#include "dns_packet.h"

typedef enum {
    /* 静态表中没有该域名，后续应走外部 DNS 中继。 */
    HOSTS_LOOKUP_MISS = 0,

    /* 静态表命中 0.0.0.0，后续应返回 NXDOMAIN。 */
    HOSTS_LOOKUP_BLOCKED,

    /* 静态表命中普通 IPv4 地址，后续可直接构造 A 响应。 */
    HOSTS_LOOKUP_ADDRESS
} hosts_lookup_kind_t;

typedef struct {
    /* 查找结果类型。 */
    hosts_lookup_kind_t kind;

    /* IPv4 地址，保持网络字节序，便于直接写入 DNS A 记录 RDATA。 */
    uint32_t ipv4_network_order;
} hosts_lookup_result_t;

typedef struct {
    /* 归一化后的小写点分域名。DNS 名字匹配通常不区分大小写。 */
    char domain[DNS_MAX_DOMAIN_LEN + 1];

    /* inet_pton() 产出的网络字节序 IPv4 地址。0 表示 0.0.0.0。 */
    uint32_t ipv4_network_order;
} hosts_entry_t;

typedef struct {
    /*
     * 当前用动态数组保存表项。
     * 线性查找足够支撑课程设计最小版本；性能优化可后续替换为自写哈希表。
     */
    hosts_entry_t* entries;
    size_t count;
    size_t capacity;
} hosts_table_t;

/* 初始化空表。 */
int hosts_table_init(hosts_table_t* table);

/*
 * 从文件加载 IP 域名表。
 *
 * 文件格式示例：
 *   0.0.0.0 bad.example.com
 *   123.127.134.10 www.bupt.cn
 *
 * 当前策略：非法行跳过，重复域名保留，查询时返回第一条命中。
 */
int hosts_table_load(hosts_table_t* table, const char* filename);

/* 查找域名，调用方根据 kind 决定本地响应或中继。 */
hosts_lookup_result_t hosts_table_lookup(const hosts_table_t* table,
                                         const char* domain);

/* 释放动态数组。 */
void hosts_table_free(hosts_table_t* table);

#endif
