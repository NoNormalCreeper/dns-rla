#include "common.h"

#include <stdbool.h>
#include <assert.h>
#include <string.h>

int main(void) {
    const char * const test_domains[] = {
        "www.example.com",
        "a.b.c",
        "www.bupt.edu.cn",
        "sub-domain.example.co.uk",
        /* 连字符开头 */
        "-invalid.com",
        "www.-invalid.com",
        /* 连字符结尾 */
        "invalid-.com",
        "www.invalid-.com",
        /* 二连点号 */
        "invalid..com",
        /* 标签太长 */
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.com",
        /* 域名太长 */
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.com",
        /* 非法字符 */
        "www.&.com"
    };

    const bool test_domains_results[] = {
        true, true, true, true, false, false, false, false, false, false, false, false
    };

    assert(ARRAY_SIZE(test_domains) == ARRAY_SIZE(test_domains_results));

    char non_normal[] = "WwW.bupt.EDU.cn";
    normalize_domain(non_normal);
    assert(strcmp(non_normal, "www.bupt.edu.cn") == 0);

    return 0;
}
