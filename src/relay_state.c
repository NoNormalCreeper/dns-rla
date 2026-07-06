#include "relay_state.h"
#include "common.h"
#include "logger.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

void relay_state_init(relay_state_t* state) {
    /* 固定数组全部清零即可表示没有任何 pending 请求。 */
    memset(state, 0, sizeof(*state));

    /* DNS ID 0 也合法，但从 1 开始便于调试和日志阅读。 */
    state->next_id = 1;
}

static bool relay_state_id_in_use(const relay_state_t* state, uint16_t id) {
    size_t i;

    for (i = 0; i < DNS_RELAY_MAX_PENDING; i++) {
        if (state->pending[i].in_use && state->pending[i].forward_id == id) {
            return true;
        }
    }

    return false;
}

int relay_state_next_id(relay_state_t* state, uint16_t* out_id) {
    size_t attempts;

    for (attempts = 0; attempts < UINT16_MAX; attempts++) {
        uint16_t id = state->next_id++;

        if (state->next_id == 0) {
            state->next_id = 1;
        }

        if (id == 0) {
            continue;
        }

        if (!relay_state_id_in_use(state, id)) {
            *out_id = id;
            return 0;
        }
    }

    return -1;
}

int relay_state_add(relay_state_t* state,
                    uint16_t forward_id,
                    uint16_t client_id,
                    const struct sockaddr* client_addr,
                    socklen_t client_addr_len,
                    const char* qname,
                    uint16_t qtype,
                    uint16_t qclass) {
    if (client_addr_len > sizeof(((pending_query_t*)0)->client_addr)) {
        return -1;
    }

    size_t i;

    /*
     * 使用固定数组的好处是逻辑简单、无需额外释放。
     * 缺点是满表时只能返回错误，调用方应记录日志或丢弃请求。
     */
    for (i = 0; i < DNS_RELAY_MAX_PENDING; i++) {
        pending_query_t* slot = &state->pending[i];

        if (!slot->in_use) {
            /*
             * 保存原客户端地址和原始 ID。
             * 外部 DNS 响应回来时，只会带 forward_id，不会知道客户端是谁。
             */
            slot->in_use = 1;
            slot->forward_id = forward_id;
            slot->client_id = client_id;
            slot->client_addr_len = client_addr_len;
            slot->qname[0] = '\0';
            slot->qtype = qtype;
            slot->qclass = qclass;
            slot->created_at = time(NULL);
            memcpy(&slot->client_addr, client_addr, client_addr_len);
            memcpy(slot->qname, qname, DNS_MAX_DOMAIN_LEN + 1);
            char client_addr_buf[48];

            if (socketaddr_to_string((const struct sockaddr*)&slot->client_addr,
                                     client_addr_buf,
                                     sizeof(client_addr_buf)) == 0) {
                logger_verbose(
                    "[PENDING] ADD: client_id: %u ,forward_id: %u, "
                    "client_addr_len: %u, client_addr: %s",
                    client_id, forward_id, client_addr_len, client_addr_buf);
            }
            return 0;
        }
    }

    return -1;
}

pending_query_t* relay_state_find(relay_state_t* state, uint16_t forward_id) {
    size_t i;

    /* 外部 DNS 回包 ID 等于 forward_id，用它找回原客户端。 */
    for (i = 0; i < DNS_RELAY_MAX_PENDING; i++) {
        if (state->pending[i].in_use &&
            state->pending[i].forward_id == forward_id) {
            return &state->pending[i];
        }
    }

    return NULL;
}

void relay_state_remove(relay_state_t* state, uint16_t forward_id) {
    pending_query_t* query = relay_state_find(state, forward_id);

    /* 清零后该槽位可被下一条请求复用。 */
    if (query != NULL) {
        char client_addr_buf[48];

        if (socketaddr_to_string((const struct sockaddr*)&query->client_addr,
                                 client_addr_buf,
                                 sizeof(client_addr_buf)) == 0) {
            logger_verbose(
                "[PENDING]: forward_id: %u, client_id: %u, client_addr_len: %u "
                ",client_addr: %s",
                query->forward_id, query->client_id, query->client_addr_len,
                client_addr_buf);
        }

        memset(query, 0, sizeof(*query));
    }
}

void relay_state_expire(relay_state_t* state, time_t now) {
    size_t i;

    /*
     * UDP 可能丢包，上游 DNS 也可能不响应。
     * 超时清理能避免 pending 表永久占用。
     */
    for (i = 0; i < DNS_RELAY_MAX_PENDING; i++) {
        pending_query_t* query = &state->pending[i];

        if (query->in_use &&
            now - query->created_at > DNS_RELAY_PENDING_TIMEOUT_SEC) {
            /* 迟到响应回来后会查不到该记录，net_loop 应丢弃它。 */
            char client_addr_buf[48];

            if (socketaddr_to_string(
                    (const struct sockaddr*)&query->client_addr,
                    client_addr_buf, sizeof(client_addr_buf)) == 0) {
                logger_verbose(
                    "[PENDING]: forward_id: %u, client_id: %u, "
                    "client_addr_len: %u ,client_addr: %s",
                    query->forward_id, query->client_id, query->client_addr_len,
                    client_addr_buf);
            }

            memset(query, 0, sizeof(*query));
        }
    }
}
