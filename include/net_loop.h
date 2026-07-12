#ifndef DNS_RELAY_NET_LOOP_H
#define DNS_RELAY_NET_LOOP_H

#include "config.h"
#include "dns_cache.h"
#include "dns_stats.h"
#include "hosts_table.h"
#include "relay_state.h"

/*
 * 未来 UDP/select 主循环的入口。
 *
 * 当前骨架只打印配置并立即返回，不真正监听端口。
 * 后续这里应负责：
 *   1. 创建 UDP socket。
 *   2. 绑定本地监听端口。
 *   3. 用 select() 同时处理客户端请求和外部 DNS 响应。
 *   4. 表内命中时调用 dns_packet 构造本地响应。
 *   5. 表内未命中时改写 ID、记录 relay_state、转发到上游 DNS。
 */
int net_loop_run(const relay_config_t* config,
                 const hosts_table_t* hosts,
                 relay_state_t* relay_state,
                 dns_cache_t* cache,
                 dns_stats_t* stats);

/* 可从 SIGINT 处理函数调用；事件循环会在当前轮结束后正常退出。 */
void net_loop_request_stop(void);

#endif
