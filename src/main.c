#include "config.h"
#include "hosts_table.h"
#include "logger.h"
#include "net_loop.h"
#include "relay_state.h"

int main(int argc, char** argv) {
    relay_config_t config;
    hosts_table_t hosts;
    relay_state_t relay_state;
    dns_cache_t cache;
    dns_stats_t stats;
    int parse_result;
    int result;

    /* main 只负责编排启动流程，具体功能放到各模块中实现。 */
    config_init_defaults(&config);
    parse_result = config_parse_args(&config, argc, argv);
    if (parse_result > 0) {
        return 0;
    }
    if (parse_result < 0) {
        config_print_usage(argv[0]);
        return 2;
    }

    logger_init(config.debug_level);

    /*
     * 域名表是本地服务器功能和拦截功能的基础。
     * 如果表文件加载失败，程序无法满足 PPT 要求，直接退出。
     */
    hosts_table_init(&hosts);
    if (hosts_table_load(&hosts, config.table_file) != 0) {
        logger_error("failed to load hosts table: %s", config.table_file);
        return 1;
    }

    /* pending 表只服务于“表外查询转发到外部 DNS”的中继路径。 */
    relay_state_init(&relay_state);

    logger_info("loaded %zu host table entries", hosts.count);

    dns_cache_init(&cache);
    dns_stats_init(&stats);

    /* 当前 net_loop 还是骨架；后续真正的 UDP/select 主循环会在这里阻塞运行。 */
    result = net_loop_run(&config, &hosts, &relay_state, &cache, &stats);
    dns_stats_log_summary(&stats);

    hosts_table_free(&hosts);
    return result == 0 ? 0 : 1;
}
