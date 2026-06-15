#include "logger.h"

#include <stdarg.h>
#include <stdio.h>

static debug_level_t current_level = DEBUG_NONE;

static void logger_vprint(FILE* stream,
                          const char* prefix,
                          const char* fmt,
                          va_list args) {
    /* 日志统一在这里拼前缀和换行，避免每个调用点重复写格式。 */
    fprintf(stream, "%s", prefix);
    vfprintf(stream, fmt, args);
    fprintf(stream, "\n");
}

void logger_init(debug_level_t level) {
    /* 简单全局等级，课程设计单线程事件循环下够用。 */
    current_level = level;
}

void logger_error(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stderr, "error: ", fmt, args);
    va_end(args);
}

void logger_info(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stdout, "info: ", fmt, args);
    va_end(args);
}

void logger_warning(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stdout, "warning: ", fmt, args);
    va_end(args);
}

void logger_debug(const char* fmt, ...) {
    va_list args;

    /* -d 和 -dd 都会显示 debug 日志。 */
    if (current_level < DEBUG_BASIC) {
        return;
    }

    va_start(args, fmt);
    logger_vprint(stdout, "debug: ", fmt, args);
    va_end(args);
}

void logger_verbose(const char* fmt, ...) {
    va_list args;

    /* verbose 只给 -dd 使用，适合输出较吵的报文细节。 */
    if (current_level < DEBUG_VERBOSE) {
        return;
    }

    va_start(args, fmt);
    logger_vprint(stdout, "verbose: ", fmt, args);
    va_end(args);
}
