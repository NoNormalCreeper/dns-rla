#include "logger.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

static debug_level_t current_level = DEBUG_NONE;

static void logger_vprint(FILE* stream,
                          const char* prefix,
                          const char* fmt,
                          va_list args) {
    /* 日志统一在这里拼前缀和换行，避免每个调用点重复写格式。 */
    time_t rawtime;
    struct tm* timeinfo;
    char buffer[80];
    time(&rawtime);
    timeinfo = localtime(&rawtime);  // 转换成电脑时区时间
    strftime(buffer, sizeof(buffer), "[%Y-%m-%d %H:%M:%S]",
             timeinfo);  // 格式化字符串
    fprintf(stream, "%s ", buffer);

    fprintf(stream, "%s", prefix);
    vfprintf(stream, fmt, args);
    fprintf(stream, "\n");
    fflush(stream);
}

void logger_init(debug_level_t level) {
    /* 简单全局等级，课程设计单线程事件循环下够用。 */
    if (level >= DEBUG_NONE && level <= DEBUG_VERBOSE) {
        current_level = level;
    } else {  // 如果等级不在范围内则打印警告然后不输出日志
        fprintf(stderr,
                "logger_init: invalid level %d, fallback to DEBUG_NONE\n",
                level);
        current_level = DEBUG_NONE;
    }
}

void logger_error(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stderr, "[ERROR] ", fmt, args);
    va_end(args);
}

void logger_info(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stdout, "[INFO] ", fmt, args);
    va_end(args);
}

void logger_warning(const char* fmt, ...) {
    va_list args;

    va_start(args, fmt);
    logger_vprint(stdout, "[WARNING] ", fmt, args);
    va_end(args);
}

void logger_debug(const char* fmt, ...) {
    va_list args;

    /* -d 和 -dd 都会显示 debug 日志。 */
    if (current_level < DEBUG_BASIC) {
        return;
    }

    va_start(args, fmt);
    logger_vprint(stdout, "[DEBUG] ", fmt, args);
    va_end(args);
}

void logger_verbose(const char* fmt, ...) {
    va_list args;

    /* verbose 只给 -dd 使用，适合输出较吵的报文细节。 */
    if (current_level < DEBUG_VERBOSE) {
        return;
    }

    va_start(args, fmt);
    logger_vprint(stdout, "[VERBOSE] ", fmt, args);
    va_end(args);
}
