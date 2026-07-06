#include "common.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void normalize_domain(char* domain) {
    for (; *domain != '\0'; domain++) {
        *domain = (char)tolower((unsigned char)*domain);
    }
}

static bool is_valid_domain_label_char(char c) {
    return isalnum((unsigned char)c) || c == '-';
}

static bool is_valid_label_len(size_t len) {
    return 1 <= len && len < 64;
}

bool is_valid_domain(const char* domain) {
    if (!(domain)) {
        return false;
    }

    const size_t len = strlen(domain);

    /* 域名长度不对 */
    if (!(1 <= len && len < 256)) {
        return false;
    }

    size_t label_len = 0;
    bool prev_dot = true;

    for (size_t i = 0; i < len; i++) {
        char c = domain[i];

        if (c == '.') {
            /* 出现二连点号 */
            if (prev_dot) {
                return false;
            }
            /* 标签长度不对 */
            if (!(is_valid_label_len(label_len))) {
                return false;
            }
            /* 标签以连字符结尾 */
            if (i > 0 && domain[i - 1] == '-') {
                return false;
            }
            label_len = 0;
            prev_dot = true;
        } else {
            /* 不是合法字符 */
            if (!(is_valid_domain_label_char(c))) {
                return false;
            }
            /* 标签以连字符开头 */
            if (prev_dot && c == '-') {
                return false;
            }

            label_len++;
            prev_dot = false;
        }
    }

    /* 出现二连点号 */
    if (prev_dot) {
        return false;
    }
    /* 标签长度不对 */
    if (!(is_valid_label_len(label_len))) {
        return false;
    }
    /* 标签以连字符结尾…… */
    if (domain[len - 1] == '-') {
        return false;
    }

    return true;
}

int socketaddr_to_string(const struct sockaddr *addr,
                        char *out_buf,
                        size_t out_buf_size){
    struct sockaddr_in * addr_in;//强转后的IPV4地址结构体
    char ip_str[INET_ADDRSTRLEN];
    uint16_t port;

    //检测是否合法
    if (addr == NULL || out_buf == NULL || out_buf_size == 0){
        return -1;
    }

    //只处理IPV4
    if (addr->sa_family != AF_INET){
        return -1;
    }

    addr_in = (struct sockaddr_in*)addr;
    //把网络字节序转为主机字节序
    port = ntohs(addr_in->sin_port);
    //把32为网络字节序IP转为点分十进制字符串
    if (inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        return -1;
    }

    snprintf(out_buf, out_buf_size, "%s:%u", ip_str, port);
    return 0;
}
