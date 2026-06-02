# DNS Relay 代码骨架说明与开发指引

本文介绍当前仓库里的 C 代码骨架。它是一个“最薄可运行框架”：能编译、能解析命令行、能读取 `dnsrelay.txt`，但还没有真正监听 UDP 53 端口，也没有实现 DNS 报文解析、响应构造和中继转发。

## 当前能做什么

当前程序可以：

- 通过 `Makefile` 编译生成 `dnsrelay`。
- 支持参考命令格式：`dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]`。
- 设置默认外部 DNS：`202.106.0.20`。
- 设置默认域名表文件：`dnsrelay.txt`。
- 读取 `IP 域名` 格式的表文件。
- 将表内域名统一转为小写，方便后续大小写无关查找。
- 提供静态表查询接口，区分三类结果：
  - 未命中
  - 命中 `0.0.0.0`，表示拦截
  - 命中普通 IPv4 地址
- 提供 DNS ID 读写函数。
- 提供中继 pending 表的基础接口。
- 运行时打印当前配置和表项数量。

当前程序还不能：

- 监听 UDP 端口。
- 接收客户端 DNS 查询。
- 解析 DNS Question。
- 构造 A 记录响应。
- 构造 NXDOMAIN 响应。
- 转发查询到外部 DNS。
- 接收外部 DNS 响应并转发回客户端。

## 编译与运行

编译：

```bash
make
```

运行骨架：

```bash
make run
```

等价于：

```bash
./dnsrelay -d 202.106.0.20 docs/dnsrelay.txt
```

清理编译产物：

```bash
make clean
```

说明：`Makefile` 当前固定使用 `/usr/bin/gcc`，是为了绕开当前环境里 `gcc` 被 ccache 包装后写只读缓存目录的问题。普通本机环境下也可以改回 `gcc`。

## 目录结构

```text
.
├── Makefile
├── include/
│   ├── config.h
│   ├── dns_packet.h
│   ├── hosts_table.h
│   ├── logger.h
│   ├── net_loop.h
│   └── relay_state.h
├── src/
│   ├── config.c
│   ├── dns_packet.c
│   ├── hosts_table.c
│   ├── logger.c
│   ├── main.c
│   ├── net_loop.c
│   └── relay_state.c
└── docs/
```

`include/` 放模块接口，`src/` 放实现。后续开发时尽量保持这个边界：其它模块只通过头文件调用，不直接依赖别的模块内部细节。

## 各模块说明

### `main`

文件：

- `src/main.c`

职责：

- 初始化默认配置。
- 解析命令行参数。
- 初始化日志等级。
- 加载域名表。
- 初始化中继 pending 状态。
- 调用 `net_loop_run()` 进入网络主循环。
- 程序退出前释放域名表内存。

它目前是程序主流程的骨架，不包含 DNS 业务逻辑。

### `config`

文件：

- `include/config.h`
- `src/config.c`

职责：

- 定义 `relay_config_t`。
- 处理默认配置。
- 解析 `-d`、`-dd`、外部 DNS IP、表文件路径。
- 打印 usage。

当前解析规则：

```text
dnsrelay [-d|-dd] [dns-server-ipaddr] [filename]
```

后续如果要增加参数，例如 `-p 5353` 指定监听端口，可以优先扩展这个模块。

### `logger`

文件：

- `include/logger.h`
- `src/logger.c`

职责：

- 按调试等级输出日志。
- `DEBUG_NONE`：只输出必要信息和错误。
- `DEBUG_BASIC`：输出基础调试信息。
- `DEBUG_VERBOSE`：输出更详细调试信息。

后续建议：

- `-d` 输出客户端 IP、端口、域名、处理路径。
- `-dd` 输出 DNS ID、QTYPE、QCLASS、pending 表变化、超时事件。

### `hosts_table`

文件：

- `include/hosts_table.h`
- `src/hosts_table.c`

职责：

- 读取 `dnsrelay.txt`。
- 解析每行 `IP 域名`。
- 使用 `inet_pton()` 校验 IPv4 地址。
- 把域名转小写。
- 保存到动态数组。
- 提供 `hosts_table_lookup()`。

当前查找是线性查找，适合最小可行版本。等核心 DNS 功能跑通后，如果想优化性能，再考虑自己实现哈希表。

注意：

- `0.0.0.0` 在网络字节序下保存为 0，因此当前用 `ipv4_network_order == 0` 判断拦截。
- 当前遇到非法行会跳过，不会报错退出。
- 当前重复域名会保留多条，查找时返回第一条命中的记录。

### `dns_packet`

文件：

- `include/dns_packet.h`
- `src/dns_packet.c`

职责：

- 处理 DNS 原始二进制报文。
- 读取和改写 DNS Header 里的 `ID`。
- 解析 Question。
- 构造本地 A 记录响应。
- 构造 NXDOMAIN 响应。

当前已经实现：

- `dns_packet_get_id()`
- `dns_packet_set_id()`

当前还是占位：

- `dns_packet_parse_question()`
- `dns_packet_build_a_response()`
- `dns_packet_build_nxdomain_response()`

这是下一阶段最应该优先补的模块。它不需要懂 Socket，只需要处理内存中的字节数组。

### `relay_state`

文件：

- `include/relay_state.h`
- `src/relay_state.c`

职责：

- 维护中继请求的 pending 表。
- 保存“转发 ID -> 原客户端信息”的映射。
- 生成新的转发 ID。
- 根据转发 ID 查找 pending 请求。
- 删除已完成请求。
- 清理超时请求。

每条 pending 记录包括：

- 是否占用。
- 转发给外部 DNS 使用的新 ID。
- 客户端原始 ID。
- 客户端地址和端口。
- 创建时间。

后续中继流程会依赖它：

```text
客户端原 ID -> 生成新转发 ID -> 记录 pending -> 发给外部 DNS
外部 DNS 返回新转发 ID -> 查 pending -> 改回客户端原 ID -> 发回客户端
```

当前 `relay_state_next_id()` 只是递增生成 ID，还没有检查 ID 是否已经被 pending 表占用。实现真正中继前应补上占用检查，避免复用仍在等待响应的 ID。

### `net_loop`

文件：

- `include/net_loop.h`
- `src/net_loop.c`

职责：

- 未来的 UDP 网络主循环。
- 创建 Socket。
- 绑定本地监听端口。
- 接收客户端查询。
- 接收外部 DNS 响应。
- 调用 `dns_packet`、`hosts_table`、`relay_state` 完成业务流程。

当前它只打印：

- 监听端口。
- 外部 DNS。
- 表项数量。
- 网络循环尚未实现。

这个模块最后再做更合适。先让 `dns_packet` 能解析报文、构造响应，再接入 Socket，调试会更稳。

## 推荐开发顺序

### 第一步：完成 DNS Question 解析

目标函数：

- `dns_packet_parse_question()`

要做的事：

- 检查报文长度至少 12 字节。
- 读取 Header 中的 `QDCOUNT`。
- 只处理 `QDCOUNT >= 1` 的情况。
- 从偏移 12 开始解析 QNAME。
- 把长度标签格式转成普通域名字符串。
- 读取 QTYPE 和 QCLASS。
- 填充 `dns_question_t`。

完成后可以写一个临时小测试，或者先在后续 Socket 收包后打印域名。

### 第二步：实现 UDP 收包，只打印查询

目标函数：

- `net_loop_run()`

先不要做中继和响应。只做：

- 创建 UDP socket。
- 绑定一个非 53 端口，例如 5353，避免权限问题。
- `recvfrom()` 收包。
- 调用 `dns_packet_parse_question()`。
- 打印客户端地址、DNS ID、域名、QTYPE、QCLASS。

验证方式可以用：

```bash
nslookup www.bupt.cn 127.0.0.1
```

如果绑定的是 5353，普通 `nslookup` 不一定方便指定端口，可以先写小测试程序或临时改到 53 端口用管理员权限跑。

### 第三步：实现本地 A 响应

目标函数：

- `dns_packet_build_a_response()`
- `net_loop_run()`

流程：

```text
收到客户端 DNS 查询
解析域名
查 hosts_table
如果命中普通 IP
构造 A 响应
sendto() 回客户端
```

这一阶段先只支持：

- 标准查询。
- `QTYPE=A`。
- `QCLASS=IN`。
- `QDCOUNT=1`。

### 第四步：实现拦截响应

目标函数：

- `dns_packet_build_nxdomain_response()`

流程：

```text
查表命中 0.0.0.0
返回 RCODE=3 的 DNS 响应
```

这里不要返回 `0.0.0.0` 的 A 记录。PPT 的要求是返回“域名不存在”的报错消息。

### 第五步：实现中继转发和 ID 转换

目标模块：

- `net_loop`
- `relay_state`
- `dns_packet_set_id()`

流程：

```text
表内未命中
生成新的 forward_id
把原查询 ID 改成 forward_id
把 forward_id、client_id、客户端地址存入 relay_state
sendto() 给外部 DNS
```

收到外部 DNS 响应：

```text
读取响应 ID
查 relay_state
找到后把响应 ID 改回 client_id
sendto() 回原客户端
删除 pending 记录
```

### 第六步：加入超时清理

目标函数：

- `relay_state_expire()`
- `net_loop_run()`

每轮 `select()` 超时或每次循环末尾调用一次：

```text
relay_state_expire(&state, time(NULL));
```

如果外部 DNS 响应迟到，pending 表已经没有对应记录，就丢弃响应。

## 建议的职责分工

三人开发时可以这样分：

- 成员 A：负责 `dns_packet`，把 DNS 报文解析和响应构造做正确。
- 成员 B：负责 `net_loop` 和 `relay_state`，把 UDP 收发、中继、ID 转换和超时处理串起来。
- 成员 C：负责 `hosts_table`、`config`、`logger`、测试用例和报告材料。

三个人都要能讲清楚 `main -> net_loop -> dns_packet/hosts_table/relay_state` 的整体路径。验收时老师可能让任意成员现场解释或修改代码。

## 当前最重要的边界

当前代码骨架故意没有把所有逻辑塞进 `main.c`。后续开发时建议保持：

- `main.c` 只管启动流程。
- `config` 只管参数。
- `hosts_table` 只管域名表。
- `dns_packet` 只管 DNS 二进制报文。
- `relay_state` 只管 pending 状态。
- `net_loop` 只管 Socket 和整体调度。
- `logger` 只管输出。

这样现场调试时能快速定位问题：域名解析错了看 `dns_packet`，表命中错了看 `hosts_table`，回包串了看 `relay_state`，收不到包看 `net_loop`。

## 常见坑

- DNS 报文不是字符串，不能用字符串函数直接处理整包。
- QNAME 不是 `www.example.com` 明文格式，而是长度标签格式。
- DNS Header 多字节字段是网络字节序。
- UDP 不保证送达，也不保证顺序。
- 不能阻塞等待一个外部 DNS 响应，否则无法处理并发请求。
- 多个客户端可能使用相同 DNS ID，中继时必须改写 ID。
- 超时后外部 DNS 仍可能迟到，找不到 pending 记录就应丢弃。
- 53 端口通常需要管理员权限，开发阶段可先用高端口测试。
