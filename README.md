# DNS RLA

这是我们在计算机网络课程设计中完成的 DNS 中继服务器。程序使用 C 和 UDP Socket 编写，可以读取本地域名表，对查询直接回答、返回 NXDOMAIN，或者转发给上游 DNS。`RLA` 来自三位小组成员姓名的首字母，也正好接近 Relay 的拼写。

这个仓库保留了课程结束时的实现、测试和演示脚本。后面的同学可以用它了解一个小型 DNS relay 怎样处理报文、匹配并发请求，以及我们为什么把缓存和测试做到现在的范围。

## 我们做了什么

程序收到查询后会先解析 DNS Header 和第一个 Question，再根据本地域名表选择处理路径。

| 查询情况 | 程序的处理方式 |
| --- | --- |
| `A/IN` 查询的域名对应普通 IPv4 地址 | 本地构造 `A` 响应并返回 |
| `A/IN` 查询的域名对应 `0.0.0.0` | 本地返回 `NXDOMAIN` |
| 域名不在表中 | 改写 DNS ID，转发给上游 DNS，收到响应后恢复客户端原 ID |

我们使用单线程 `select()` 事件循环同时监听客户端和上游 Socket。等待上游响应时，请求会保存在 pending 表中，因此程序仍能接收其他客户端的查询。pending 记录超过 5 秒会被清理，之后到达的响应会作为迟到响应丢弃。

课程要求完成后，我们又加入了一个小型内存缓存。它只保存 `A/IN` 上游响应，按照响应中最小的有效 TTL 过期。缓存固定为 64 项，满后轮转替换。我们没有继续实现 LRU，因为固定容量和轮转策略对课程中的重复查询已经够用，也更容易通过单元测试检查。

程序会统计本地命中、拦截、缓存命中、上游转发、超时和异常查询。运行时按 `Ctrl-C`，事件循环会关闭 Socket，并在退出前打印统计结果。

## 编译和运行

目前的代码在 Linux 上使用 GCC 构建。需要安装 `gcc`、`make`，手动查询时还需要 `dig`。

```bash
make
./dnsrelay -dd -p 1053 223.5.5.5 dnsrelay.txt
```

这里使用 `1053`，避免绑定 UDP 53 所需的额外权限。`223.5.5.5` 是示例上游地址，可以换成当前网络可访问的 DNS 服务器。`-d` 输出基本查询信息，`-dd` 还会输出 ID 转换、pending 状态和缓存日志。

完整命令格式如下：

```text
./dnsrelay [-d|-dd] [-p port] [--upstream-port port] [dns-server-ipaddr] [filename]
```

启动后可以在另一个终端检查三条主要路径：

```bash
# 本地域名表命中，预期返回 123.127.134.10
dig @127.0.0.1 -p 1053 www.bupt.cn A +noall +answer

# 本地拦截，预期返回 NXDOMAIN
dig @127.0.0.1 -p 1053 008.cn A +time=2 +tries=1

# 表外查询，预期由上游返回；重复执行可观察缓存命中
dig @127.0.0.1 -p 1053 example.com A +nocookie +time=3 +tries=1
```

如果已经安装 `dig`，也可以让客户端脚本依次执行本地回答、拦截、上游转发、缓存和并发查询：

```bash
bash tools/demo_all.sh
```

脚本不会启动或停止服务端，需要先在另一个终端运行 `dnsrelay`。更完整的命令和 timeout 演示见 [验收命令清单](docs/acceptance-demo.md)。

## 测试

```bash
make test
```

测试没有引入第三方框架，每个 `tests/test_*.c` 都会编译成一个小程序。目前覆盖域名表、DNS 报文解析与构造、ID 映射、pending 超时、缓存过期和运行统计。测试范围和扩展建议见 [tests/README.md](tests/README.md)。

GitHub Actions 还会执行 GCC 构建、`clang-format`、`cppcheck` 以及 ASan、UBSan 检查。真实网络路径需要可访问的上游 DNS，因此保留为 `dig` 演示，没有放进单元测试。

## 代码结构

| 路径 | 内容 |
| --- | --- |
| `src/net_loop.c` | UDP Socket、`select()` 事件循环和三条查询路径 |
| `src/dns_packet.c` | DNS 查询解析、ID 读写、A 与 NXDOMAIN 响应构造、TTL 提取 |
| `src/hosts_table.c` | 加载并查询本地域名表 |
| `src/relay_state.c` | forward ID 分配、客户端映射和超时清理 |
| `src/dns_cache.c` | 固定容量的 TTL 缓存 |
| `src/config.c`、`src/logger.c`、`src/dns_stats.c` | 参数、日志和运行统计 |
| `tests/` | 各模块的单元测试 |
| `tools/` | 手动验收和压力测试脚本 |

第一次阅读时，可以先看 [课程要求与实现思路](docs/dnsrelay-experiment-guide.md)，再从 `src/main.c` 和 `src/net_loop.c` 顺着主流程阅读。更细的模块接口说明在 [代码骨架说明](docs/code-skeleton-guide.md)，课程结束时的设计、测试结果和调试记录在 [实验报告初稿](docs/实验报告初稿.md)。

## 当前边界

- 本地构造响应和缓存只处理 `A/IN`。其他查询类型会直接转发给上游。
- 单个 DNS UDP 报文上限按 512 字节处理，没有实现 TCP fallback，也没有支持更大的 EDNS 报文。
- 缓存不保存 NXDOMAIN，也没有实现通用的 CNAME、AAAA 或 MX 缓存。
- 缓存 key 不包含 EDNS Cookie，缓存演示需要给 `dig` 加 `+nocookie`。
- 本地 NXDOMAIN 响应没有附加 Authority 区的 SOA 记录。
- Socket 代码按 Linux 接口编写，没有加入 Windows Winsock 适配。
- 域名表使用动态数组和线性查找。课程提供的数据规模下足够使用，但没有针对大型表做性能优化。

这些限制是我们给课程项目划定的范围。仓库中的压力脚本用于观察多客户端和 pending 表行为，不代表程序已经适合作为公开网络上的 DNS 服务。
