# Tests

Run the current automated checks with:

```sh
make test
```

The first tests are intentionally small:

- `test_hosts_table` checks loading, invalid-line skipping, case-insensitive lookup,
  ordinary address hits, blocked-domain hits, and misses.
- `test_dns_packet` checks DNS packet ID reading and rewriting without changing the
  rest of the packet.
- `test_relay_state` checks pending ID allocation, client mapping, removal,
  timeout cleanup, and full-table failure behavior.

## 测试工具约定

测试仍然保持“每个 `tests/test_*.c` 编译成一个小可执行文件”的轻量结构，
不引入第三方测试框架。公共断言宏放在 `tests/test_support.h`：

- `TEST_CHECK(expr)` 用于普通布尔条件。
- `TEST_CHECK_EQ_INT/SIZE/U16/U32/STR(actual, expected)` 用于常见值比较。

这些宏失败时会打印文件、行号、表达式以及实际值/期望值，比裸 `assert()`
更便于定位 CI 或本地失败。复杂结构体比较不要放进公共工具层，优先在具体测试
文件里写小 helper，避免测试基础设施过度抽象。

Next useful extensions:

1. Add `dns_packet_parse_question()` (now `dns_packet_parse_query()`) tests using a fixed binary query for
   `www.example.com A IN`, plus malformed packets that must fail safely.
2. Add `dns_packet_build_a_response()` tests that assert `QR=1`, `RCODE=0`,
   `QDCOUNT=1`, `ANCOUNT=1`, the original ID, and the expected IPv4 RDATA.
3. Add `dns_packet_build_nxdomain_response()` tests that assert `QR=1`,
   `RCODE=3`, and `ANCOUNT=0`.
4. After `net_loop` supports a non-privileged test port, add a small UDP client
   integration test that sends DNS queries to `127.0.0.1:5353`.
