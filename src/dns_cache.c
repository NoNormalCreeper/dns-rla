#include "dns_cache.h"
#include "logger.h"

#include <string.h>

void dns_cache_init(dns_cache_t* cache) {
    size_t i;

    for (i = 0; i < DNS_CACHE_CAPACITY; i++) {
        cache->entries[i].in_use = 0;
        cache->entries[i].response_len = 0;
        cache->entries[i].expires_at = 0;
    }
    cache->next_replace = 0;
}

int dns_cache_get(const dns_cache_t* cache,
                  const dns_cache_key_t* key,
                  time_t now,
                  ubyte* response,
                  size_t response_capacity,
                  size_t* response_len) {
    size_t i;

    for (i = 0; i < DNS_CACHE_CAPACITY; ++i) {
        const dns_cache_entry_t* entry;

        entry = cache->entries + i;
        if (!(entry->in_use)) {
            continue;
        }
        if (entry->expires_at <= now) {
            continue;
        }
        if (strcmp(entry->key.qname, key->qname) != 0) {
            continue;
        }
        if (entry->key.qtype != key->qtype) {
            continue;
        }
        if (entry->key.qclass != key->qclass) {
            continue;
        }

        /* 命中 */

        if (response_capacity < entry->response_len) {
            logger_error(
                "%s(): Cached response too long to copy: %zu bytes, while "
                "capacity = %zu bytes",
                __func__, entry->response_len, response_capacity);
            /* 此时还是要将缓存的长度给出去 */
            *response_len = entry->response_len;
            return -2;
        }

        memcpy(response, entry->response, entry->response_len);
        *response_len = entry->response_len;
        logger_info("%s(): Cache hit", __func__);
        return 0;
    }

    logger_warning("%s(): Cache miss", __func__);
    return -1;
}

int dns_cache_put(dns_cache_t* cache,
                  const dns_cache_key_t* key,
                  const ubyte* response,
                  size_t response_len,
                  time_t expires_at) {
    dns_cache_entry_t* entry;

    /* 太长不写 */
    if (response_len > DNS_MAX_PACKET_SIZE) {
        logger_error("%s(): Response too long: %zu bytes", __func__,
                     response_len);
        return -1;
    }

    entry = cache->entries + cache->next_replace;
    cache->next_replace = (cache->next_replace + 1) % DNS_CACHE_CAPACITY;

    memcpy(&entry->key, key, sizeof(dns_cache_key_t));
    memcpy(entry->response, response, response_len);
    entry->response_len = response_len;
    entry->expires_at = expires_at;
    entry->in_use = 1;

    return 0;
}
