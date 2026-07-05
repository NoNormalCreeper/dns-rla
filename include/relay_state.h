#ifndef DNS_RELAY_RELAY_STATE_H
#define DNS_RELAY_RELAY_STATE_H

#include <stdint.h>
#include <time.h>

#include <sys/socket.h>
#include "dns_packet.h"

/*
 * 最多同时等待多少个外部 DNS 响应。
 * 课程设计场景 1024 足够；如果压测出现满表，可先记录日志而不是崩溃。
 */
#define DNS_RELAY_MAX_PENDING 1024

/*
 * pending 请求超时时间。
 * UDP 不保证送达，外部 DNS 可能不回包；超时后必须清理，避免表无限增长。
 */
#define DNS_RELAY_PENDING_TIMEOUT_SEC 5

typedef struct {
    /* 该槽位是否正在使用。固定数组用这个字段区分空闲/占用。 */
    int in_use;

    /*
     * 本程序转发给外部 DNS 时使用的新 ID。
     * 外部响应回来时会带这个 ID，用它查回原客户端。
     */
    uint16_t forward_id;

    /* 客户端原始 DNS ID。发回客户端前必须把响应 ID 改回它。 */
    uint16_t client_id;

    /*
     * 客户端地址，使用 sockaddr_storage 兼容 IPv4/IPv6。
     * 本课程主要做 IPv4，但这个类型能避免地址结构大小不够。
     */
    struct sockaddr_storage client_addr;

    /* client_addr 实际长度，sendto() 发回客户端时需要。 */
    socklen_t client_addr_len;

    /* 写 cache 需要的参数 */
    char qname[DNS_MAX_DOMAIN_LEN + 1];
    uint16_t qtype;
    uint16_t qclass;

    /* 记录创建时间，用于超时清理和迟到响应处理。 */
    time_t created_at;
} pending_query_t;

typedef struct {
    /* 固定大小 pending 表，避免一开始引入复杂内存管理。 */
    pending_query_t pending[DNS_RELAY_MAX_PENDING];

    /*
     * 下一个候选 forward_id。
     * 真正实现中继前应检查该 ID 是否已被占用，避免 ID 冲突。
     */
    uint16_t next_id;
} relay_state_t;

/* 清空 pending 表，并把 ID 生成器从 1 开始。 */
void relay_state_init(relay_state_t* state);

/*
 * 生成一个候选 forward_id。
 *
 * 递增生成 + 检查冲突
 * 返回值表示是否成功生成 ID；成功时通过 out_id 输出且返回 0。
 * 失败时可能是表满了，调用方应记录日志或丢弃请求。
 * 注意：ID 是 uint16_t，递增到 65535 后会回到 0；0 是我们跳过的非法 ID。
 */
int relay_state_next_id(relay_state_t* state, uint16_t* out_id);

/* 添加一条“forward_id -> 原客户端”的映射。 */
int relay_state_add(relay_state_t* state,
                    uint16_t forward_id,
                    uint16_t client_id,
                    const struct sockaddr* client_addr,
                    socklen_t client_addr_len,
                    const char* qname,
                    uint16_t qtype,
                    uint16_t qclass);

/* 根据外部 DNS 响应里的 forward_id 查找 pending 记录。 */
pending_query_t* relay_state_find(relay_state_t* state, uint16_t forward_id);

/* 请求完成或需要丢弃时删除映射。 */
void relay_state_remove(relay_state_t* state, uint16_t forward_id);

/*
 * 清理超时 pending。
 * 超时后如果外部响应迟到，relay_state_find() 会找不到记录，net_loop
 * 应直接丢弃。
 */
void relay_state_expire(relay_state_t* state, time_t now);

#endif
