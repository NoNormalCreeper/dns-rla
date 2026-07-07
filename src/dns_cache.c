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
    (void)cache;
    (void)key;
    (void)now;
    (void)response;
    (void)response_capacity;
    (void)response_len;
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
