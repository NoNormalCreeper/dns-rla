#ifndef DNS_RELAY_CONFIG_H
#define DNS_RELAY_CONFIG_H

#include <stdint.h>
typedef enum {
    /* 不输出调试日志，只保留错误和必要启动信息。 */
    DEBUG_NONE = 0,
    /* 对应命令行 -d：输出请求路径、客户端、域名等基础调试信息。 */
    DEBUG_BASIC = 1,
    /* 对应命令行 -dd：额外输出 DNS ID、pending 表、超时等细节。 */
    DEBUG_VERBOSE = 2
} debug_level_t;

typedef struct {
    /* 当前调试等级，由 -d / -dd 控制。 */
    debug_level_t debug_level;

    /*
     * 上游 DNS 服务器 IP 字符串。
     * 表内未命中的请求会转发给它，例如 202.106.0.20 或 8.8.8.8。
     */
    const char* upstream_dns;
    uint8_t upstream_port;

    /* 域名-IP 静态表文件路径，默认是当前目录下的 dnsrelay.txt。 */
    const char* table_file;

    /*
     * 本地监听端口。DNS 标准端口是 UDP 53。
     * 开发阶段可以临时改成 5353 等高端口，避免管理员权限问题。
     */
    uint8_t listen_port;
} relay_config_t;

/* PPT 参考实现使用的默认外部 DNS。 */
#define DNS_RELAY_DEFAULT_DNS "202.106.0.20"

/* 默认静态域名表文件名。make run 当前会显式传 docs/dnsrelay.txt。 */
#define DNS_RELAY_DEFAULT_TABLE "dnsrelay.txt"

/* DNS 标准服务端口。Linux/Unix 下绑定 53 端口通常需要 root 权限。 */
#define DNS_RELAY_DEFAULT_PORT 53

#define DNS_RELAY_UPSTREAM_DEFAULT_PORT 53

/* 用默认值填充配置结构，必须在解析命令行前调用。 */
void config_init_defaults(relay_config_t* config);

/*
 * 解析命令行参数。
 *
 * 支持格式：
 *   dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]
 *
 * 返回值：
 *   0  参数解析成功
 *   1  已打印帮助信息，调用方可正常退出
 *  -1  参数非法，调用方应打印 usage 并返回错误
 */
int config_parse_args(relay_config_t* config, int argc, char** argv);

/* 打印命令行用法。 */
void config_print_usage(const char* program_name);

#endif
