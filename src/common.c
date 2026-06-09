#include "common.h"

#include <ctype.h>
#include <stddef.h>
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
