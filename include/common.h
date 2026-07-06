#ifndef DNS_RELAY_COMMON_H
#define DNS_RELAY_COMMON_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
/* C 标准并未保证 CHAR_BIT 等于 8 */
#if CHAR_BIT != 8
#error "CHAR_BIT != 8"
#endif

/* 类型别名避免代码过于冗长 */
typedef unsigned char ubyte;

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * 例：输入 WwW.bupt.EDU.cn 改成 www.bupt.edu.cn
 *
 * DNS 域名匹配通常不区分大小写。
 * 静态表里存在 www.X.com / WWW.X.com 这类大小写混合项，统一小写后再比较。
 *
 * 其他地方也会用到这一函数。
 */
void normalize_domain(char* domain);

/*
 * 校验一个域名是否合法。
 */
bool is_valid_domain(const char* domain);
/*

*/
int socketaddr_to_string(const struct sockaddr *addr,
                        char *out_buf,
                        size_t out_buf_size);
#endif /* DNS_RELAY_COMMON_H */
