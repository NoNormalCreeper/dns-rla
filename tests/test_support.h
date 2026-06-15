#ifndef DNS_RELAY_TEST_SUPPORT_H
#define DNS_RELAY_TEST_SUPPORT_H

#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_FAIL_AT(file, line, fmt, ...)                            \
    do {                                                              \
        fprintf(stderr, "%s:%d: " fmt "\n", file, line, __VA_ARGS__); \
        exit(1);                                                      \
    } while (0)

#define TEST_CHECK(expr)                                                 \
    do {                                                                 \
        if (!(expr)) {                                                   \
            TEST_FAIL_AT(__FILE__, __LINE__, "check failed: %s", #expr); \
        }                                                                \
    } while (0)

#define TEST_CHECK_EQ_INT(actual, expected)                                 \
    do {                                                                    \
        int actual_value = (actual);                                        \
        int expected_value = (expected);                                    \
        if (actual_value != expected_value) {                               \
            TEST_FAIL_AT(__FILE__, __LINE__,                                \
                         "check failed: %s == %s (actual=%d expected=%d)",  \
                         #actual, #expected, actual_value, expected_value); \
        }                                                                   \
    } while (0)

#define TEST_CHECK_EQ_SIZE(actual, expected)                                 \
    do {                                                                     \
        size_t actual_value = (actual);                                      \
        size_t expected_value = (expected);                                  \
        if (actual_value != expected_value) {                                \
            TEST_FAIL_AT(__FILE__, __LINE__,                                 \
                         "check failed: %s == %s (actual=%zu expected=%zu)", \
                         #actual, #expected, actual_value, expected_value);  \
        }                                                                    \
    } while (0)

#define TEST_CHECK_EQ_U16(actual, expected)                                 \
    do {                                                                    \
        uint16_t actual_value = (actual);                                   \
        uint16_t expected_value = (expected);                               \
        if (actual_value != expected_value) {                               \
            TEST_FAIL_AT(__FILE__, __LINE__,                                \
                         "check failed: %s == %s (actual=%" PRIu16          \
                         " expected=%" PRIu16 ")",                          \
                         #actual, #expected, actual_value, expected_value); \
        }                                                                   \
    } while (0)

#define TEST_CHECK_EQ_U32(actual, expected)                                 \
    do {                                                                    \
        uint32_t actual_value = (actual);                                   \
        uint32_t expected_value = (expected);                               \
        if (actual_value != expected_value) {                               \
            TEST_FAIL_AT(__FILE__, __LINE__,                                \
                         "check failed: %s == %s (actual=%" PRIu32          \
                         " expected=%" PRIu32 ")",                          \
                         #actual, #expected, actual_value, expected_value); \
        }                                                                   \
    } while (0)

#define TEST_CHECK_EQ_STR(actual, expected)                               \
    do {                                                                  \
        const char* actual_value = (actual);                              \
        const char* expected_value = (expected);                          \
        if (strcmp(actual_value, expected_value) != 0) {                  \
            TEST_FAIL_AT(                                                 \
                __FILE__, __LINE__,                                       \
                "check failed: %s == %s (actual=\"%s\" expected=\"%s\")", \
                #actual, #expected, actual_value, expected_value);        \
        }                                                                 \
    } while (0)

#endif
