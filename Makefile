ifeq ($(origin CC),default)
CC := gcc
endif

EXEEXT ?=
ifeq ($(OS),Windows_NT)
EXEEXT := .exe
endif

# -std=c11：使用 C11；-Wall/-Wextra/-pedantic：尽早暴露潜在问题。
# 修改：用 -std=gnu17 以支持 GNU 扩展（如 inet_aton），避免一些平台上的兼容性问题。https://stackoverflow.com/a/71801111/19891658
# 修改：添加 -Wno-missing-braces 来抑制某些编译器在初始化结构体时的警告，GCC Bug 53119，https://stackoverflow.com/questions/13746033/how-to-repair-warning-missing-braces-around-initializer#comment52433486_13758286
CFLAGS ?= -std=gnu17 -Wall -Wextra -pedantic -Iinclude -Wno-missing-braces -g
LDFLAGS ?=

TARGET := dnsrelay$(EXEEXT)

# 自动收集 src 下所有 .c 文件，新增模块后通常不用改 Makefile。
SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,build/%.o,$(SRC))
TEST_TARGETS := build/test_hosts_table build/test_dns_packet build/test_common \
	build/test_relay_state build/test_dns_cache build/test_dns_stats
TEST_RUN_TARGETS := run-test-hosts-table run-test-dns-packet run-test-common \
	run-test-relay-state run-test-dns-cache run-test-dns-stats

.PHONY: all clean run test $(TEST_RUN_TARGETS)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDFLAGS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c $< -o $@

build:
	mkdir -p build

run: $(TARGET)
	# 骨架运行：读取 docs/dnsrelay.txt 并打印配置，不会真正监听 53 端口。
	./$(TARGET) -d 202.106.0.20 docs/dnsrelay.txt

test: $(TEST_RUN_TARGETS)

run-test-hosts-table: build/test_hosts_table
	./build/test_hosts_table

run-test-dns-packet: build/test_dns_packet
	./build/test_dns_packet

run-test-common: build/test_common
	./build/test_common

run-test-relay-state: build/test_relay_state
	./build/test_relay_state

run-test-dns-cache: build/test_dns_cache
	./build/test_dns_cache

run-test-dns-stats: build/test_dns_stats
	./build/test_dns_stats

build/test_hosts_table: tests/test_hosts_table.c tests/test_support.h \
	src/hosts_table.c src/common.c | build
	$(CC) $(CFLAGS) tests/test_hosts_table.c src/hosts_table.c src/common.c -o $@ $(LDFLAGS)

build/test_dns_packet: tests/test_dns_packet.c tests/test_support.h \
	src/dns_packet.c src/common.c src/logger.c | build
	$(CC) $(CFLAGS) tests/test_dns_packet.c src/dns_packet.c src/common.c src/logger.c -o $@ $(LDFLAGS)

build/test_common: tests/test_common.c tests/test_support.h src/common.c | build
	$(CC) $(CFLAGS) tests/test_common.c src/common.c -o $@ $(LDFLAGS)

build/test_relay_state: tests/test_relay_state.c tests/test_support.h \
	src/relay_state.c src/common.c src/logger.c | build
	$(CC) $(CFLAGS) tests/test_relay_state.c src/relay_state.c src/common.c src/logger.c -o $@ $(LDFLAGS)

build/test_dns_cache: tests/test_dns_cache.c tests/test_support.h \
	src/dns_cache.c src/logger.c | build
	$(CC) $(CFLAGS) tests/test_dns_cache.c src/dns_cache.c src/logger.c -o $@ $(LDFLAGS)

build/test_dns_stats: tests/test_dns_stats.c tests/test_support.h \
	src/dns_stats.c src/logger.c | build
	$(CC) $(CFLAGS) tests/test_dns_stats.c src/dns_stats.c src/logger.c -o $@ $(LDFLAGS)

clean:
	rm -rf build $(TARGET)
