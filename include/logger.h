#ifndef DNS_RELAY_LOGGER_H
#define DNS_RELAY_LOGGER_H

#include "config.h"

/* 初始化全局日志等级。 */
void logger_init(debug_level_t level);

/* 错误日志总是输出到 stderr。 */
void logger_error(const char* fmt, ...);

/* 普通信息总是输出到 stdout，用于启动配置、表项数量等。 */
void logger_info(const char* fmt, ...);

/* DEBUG_BASIC 及以上输出。 */
void logger_debug(const char* fmt, ...);

/* DEBUG_VERBOSE 才输出，适合报文 ID、pending 表、超时等细节。 */
void logger_verbose(const char* fmt, ...);

#endif
