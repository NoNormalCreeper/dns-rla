#include "hosts_table.h"
#include "common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int ensure_capacity(hosts_table_t* table) {
    hosts_entry_t* new_entries;
    size_t new_capacity;

    /* 动态数组还有空位时直接复用。 */
    if (table->count < table->capacity) {
        return 0;
    }

    /*
     * 首次分配 128 条，之后倍增。
     * 这比每读一行 realloc 一次稳定，也足够容易理解。
     */
    new_capacity = table->capacity == 0 ? 128 : table->capacity * 2;
    new_entries = (hosts_entry_t*)realloc(table->entries,
                                          new_capacity * sizeof(*new_entries));
    // realloc用于扩充表
    if (new_entries == NULL) {
        return -1;
    }

    table->entries = new_entries;
    table->capacity = new_capacity;
    return 0;
}

int hosts_table_init(hosts_table_t* table) {
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
    return 0;
}

int hosts_table_load(hosts_table_t* table, const char* filename) {
    FILE* fp;
    char line[512];

    /* 只读方式打开静态域名表。 */
    fp = fopen(filename, "r");
    if (fp == NULL) {
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        char ip_text[64];
        char domain[DNS_MAX_DOMAIN_LEN + 1];
        struct in_addr addr;
        hosts_entry_t* entry;

        /*
         * 当前只支持每行两个字段：IPv4 和域名。
         * 空行、格式不完整的行直接跳过。
         */
        if (sscanf(line, "%63s %255s", ip_text, domain) != 2) {
            continue;
        }

        /*
         * inet_pton() 会校验 IPv4 文本并输出网络字节序。
         * 后续构造 A 响应时可以直接写入 RDATA。
         */
        if (inet_pton(AF_INET, ip_text, &addr) != 1) {
            continue;
        }

        if (ensure_capacity(table) != 0) {
            fclose(fp);
            return -1;
        }

        normalize_domain(domain);

        /* 追加到动态数组末尾。重复域名暂不去重，lookup 返回第一条命中。 */
        entry = &table->entries[table->count++];
        strncpy(entry->domain, domain, sizeof(entry->domain) - 1);
        entry->domain[sizeof(entry->domain) - 1] = '\0';
        entry->ipv4_network_order = addr.s_addr;
    }

    fclose(fp);
    return 0;
}

hosts_lookup_result_t hosts_table_lookup(const hosts_table_t* table,
                                         const char* domain) {
    hosts_lookup_result_t result;
    char normalized[DNS_MAX_DOMAIN_LEN + 1];
    size_t i;

    result.kind = HOSTS_LOOKUP_MISS;
    result.ipv4_network_order = 0;

    /* 查询域名也统一小写，和加载阶段保持同一比较规则。 */
    strncpy(normalized, domain, sizeof(normalized) - 1);
    normalized[sizeof(normalized) - 1] = '\0';
    normalize_domain(normalized);

    /*
     * 当前使用线性查找。
     * 如果后续表很大、查询很频繁，再把 hosts_table_t 内部替换为哈希表。
     */
    for (i = 0; i < table->count; i++) {
        if (strcmp(table->entries[i].domain, normalized) == 0) {
            result.ipv4_network_order = table->entries[i].ipv4_network_order;
            /* 0.0.0.0 的网络字节序值为 0，用它表示拦截。 */
            result.kind = result.ipv4_network_order == 0 ? HOSTS_LOOKUP_BLOCKED
                                                         : HOSTS_LOOKUP_ADDRESS;
            return result;
        }
    }

    return result;
}

void hosts_table_free(hosts_table_t* table) {
    free(table->entries);
    table->entries = NULL;
    table->count = 0;
    table->capacity = 0;
}
