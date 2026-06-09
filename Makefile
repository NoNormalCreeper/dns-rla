ifeq ($(origin CC),default)
CC := gcc
endif

EXEEXT ?=
ifeq ($(OS),Windows_NT)
EXEEXT := .exe
endif

# -std=c11：使用 C11；-Wall/-Wextra/-pedantic：尽早暴露潜在问题。
CFLAGS ?= -std=c11 -Wall -Wextra -pedantic -Iinclude
LDFLAGS ?=

TARGET := dnsrelay$(EXEEXT)

# 自动收集 src 下所有 .c 文件，新增模块后通常不用改 Makefile。
SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,build/%.o,$(SRC))
TEST_TARGETS := build/test_hosts_table build/test_dns_packet build/test_common

.PHONY: all clean run test

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

test: $(TEST_TARGETS)
	./build/test_hosts_table
	./build/test_dns_packet
	./build/test_common

build/test_hosts_table: tests/test_hosts_table.c src/hosts_table.c src/common.c | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/test_dns_packet: tests/test_dns_packet.c src/dns_packet.c src/common.c | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

build/test_common: tests/test_common.c src/common.c | build
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -rf build $(TARGET)
