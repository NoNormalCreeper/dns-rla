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

static dns_cache_entry_t* dns_cache_find_entry(dns_cache_t* cache,
                                               const dns_cache_key_t* key) {
    size_t i;

    for (i = 0; i < DNS_CACHE_CAPACITY; ++i) {
        dns_cache_entry_t* entry;

        entry = cache->entries + i;
        if (!entry->in_use) {
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

        return entry;
    }

    return NULL;
}

int dns_cache_get(const dns_cache_t* cache,
                  const dns_cache_key_t* key,
                  time_t now,
                  ubyte* response,
                  size_t response_capacity,
                  size_t* response_len) {
    dns_cache_entry_t* entry;

    entry = dns_cache_find_entry((dns_cache_t*)cache, key);

    if (entry == NULL) {
        logger_debug("%s(): Cache miss", __func__);
        return -1;
    }

    if (entry->expires_at <= now) {
        logger_debug("%s(): Cache miss (expired)", __func__);
        return -1;
    }

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
    logger_debug("%s(): Cache hit", __func__);
    return 0;
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

    /* 如果已经存在则原地更新 */
    entry = dns_cache_find_entry(cache, key);
    if (entry != NULL) {
        memcpy(entry->response, response, response_len);
        entry->response_len = response_len;
        entry->expires_at = expires_at;
        return 0;
    }

    /* 不存在就插入 */
    entry = cache->entries + cache->next_replace;
    cache->next_replace = (cache->next_replace + 1) % DNS_CACHE_CAPACITY;

    memcpy(&entry->key, key, sizeof(dns_cache_key_t));
    memcpy(entry->response, response, response_len);
    entry->response_len = response_len;
    entry->expires_at = expires_at;
    entry->in_use = 1;

    return 0;
}
