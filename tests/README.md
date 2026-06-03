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

Next useful extensions:

1. Add `dns_packet_parse_question()` (now `dns_packet_parse_query()`) tests using a fixed binary query for
   `www.example.com A IN`, plus malformed packets that must fail safely.
2. Add `dns_packet_build_a_response()` tests that assert `QR=1`, `RCODE=0`,
   `QDCOUNT=1`, `ANCOUNT=1`, the original ID, and the expected IPv4 RDATA.
3. Add `dns_packet_build_nxdomain_response()` tests that assert `QR=1`,
   `RCODE=3`, and `ANCOUNT=0`.
4. After `net_loop` supports a non-privileged test port, add a small UDP client
   integration test that sends DNS queries to `127.0.0.1:5353`.
