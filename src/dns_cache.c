#include "dns_cache.h"

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
    (void)cache;
    (void)key;
    (void)response;
    (void)response_len;
    (void)expires_at;
    return -1;
}
