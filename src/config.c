#include "config.h"

#include <stdio.h>
#include <string.h>

void config_init_defaults(relay_config_t* config) {
    /* 先给所有字段设置 PPT 参考实现里的默认值。 */
    config->debug_level = DEBUG_NONE;
    config->upstream_dns = DNS_RELAY_DEFAULT_DNS;
    config->table_file = DNS_RELAY_DEFAULT_TABLE;
    config->listen_port = DNS_RELAY_DEFAULT_PORT;
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
    if (argi < argc && strcmp(argv[argi], "-d") == 0) {
        config->debug_level = DEBUG_BASIC;
        argi++;
    } else if (argi < argc && strcmp(argv[argi], "-dd") == 0) {
        config->debug_level = DEBUG_VERBOSE;
        argi++;
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
            "Usage: %s [-d|-dd] [dns-server-ipaddr] [filename]\n"
            "Defaults: upstream DNS %s, table file %s, listen port %u\n",
            program_name, DNS_RELAY_DEFAULT_DNS, DNS_RELAY_DEFAULT_TABLE,
            DNS_RELAY_DEFAULT_PORT);
}
