#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint16_t local_port = 5353;   // 默认本地监听端口
uint16_t upstream_port = 53;  // 默认上游端口参数

int parse_port(const char* str, uint16_t* port) {
    char* endptr;
    long val = strtol(str, &endptr, 10);
    if (*endptr != '\0' || val < 1 || val > 65535) {
        fprintf(stderr, "Invalid port: %s\n", str);
        return -1;
    }
    *port = (uint16_t)val;
    return 0;
}

void config_init_defaults(relay_config_t* config) {
    /* 先给所有字段设置 PPT 参考实现里的默认值。 */
    config->debug_level = DEBUG_NONE;
    config->upstream_dns = DNS_RELAY_DEFAULT_DNS;
    config->table_file = DNS_RELAY_DEFAULT_TABLE;
    config->listen_port = DNS_RELAY_DEFAULT_PORT;
    config->upstream_port = DNS_RELAY_UPSTREAM_DEFAULT_PORT;
}

int config_parse_args(relay_config_t* config, int argc, char** argv) {
    int argi = 1;

    /* 帮助参数优先处理，避免后续把 --help 当成 DNS 服务器地址。 */
    if (argc > 1 &&
        (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        config_print_usage(argv[0]);
        return 1;
    }

    /*
     * 参考命令格式把调试选项放在第一个位置。
     * 如果后续要支持任意顺序参数，建议重写成循环解析。
     */
    for (argi = 1; argi < argc; argi++) {
        if (strcmp(argv[argi], "-d") == 0) {
            config->debug_level = DEBUG_BASIC;
        } else if (strcmp(argv[argi], "-dd") == 0) {
            config->debug_level = DEBUG_VERBOSE;
        } else if (strcmp(argv[argi], "-p") == 0) {
            if (argi + 1 < argc) {
                if (parse_port(argv[++argi], &config->listen_port) != 0) {
                    return -1;
                }

                local_port = config->listen_port;

            } else {
                fprintf(stderr, "missing parameter for -p\n");
                return -1;
            }
        } else if (strcmp(argv[argi], "--upstream-port") == 0) {
            if (argi + 1 < argc) {
                if (parse_port(argv[++argi], &config->upstream_port) != 0) {
                    return -1;
                }

                upstream_port = config->upstream_port;

            } else {
                fprintf(stderr, "missing parameter for --upstream-port\n");
                return -1;
            }
        } else {
            break;
        }
    }
    /* 调试选项之后的第一个非选项参数视为外部 DNS 地址。 */
    if (argi < argc) {
        config->upstream_dns = argv[argi++];
    }

    /* 再后一个参数视为域名表文件路径。 */
    if (argi < argc) {
        config->table_file = argv[argi++];
    }
    /* 仍有多余参数说明命令行格式不符合当前骨架。 */
    if (argi < argc) {
        return -1;
    }
    return 0;
}

void config_print_usage(const char* program_name) {
    fprintf(stderr,
            "Usage: %s [-d|-dd] [-p port] [--upstream-port port] "
            "[dns-server-ipaddr] [filename]\n"
            "Defaults: upstream DNS %s, table file %s, listen port %u\n",
            program_name, DNS_RELAY_DEFAULT_DNS, DNS_RELAY_DEFAULT_TABLE,
            local_port);
}
