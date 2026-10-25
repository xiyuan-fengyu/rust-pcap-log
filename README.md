# rust-pcap-log

Rust + libpcap 的被动 TCP/UDP 会话日志器。**不代理、不监听业务端口、不修改网络配置**；运行时没有 Zeek、Python、tcpdump、Docker socket 或按连接创建的线程。

这是有实际测试的开发候选，不是完整 Zeek 替代品。交付验收、实测内存和仍未完成的范围见 [STATUS](docs/STATUS.md)、[兼容性边界](docs/COMPATIBILITY.md)、[运行记录](docs/runs/)。未获授权替换或重启任何现有监控服务。

## 构建和最小使用

本次已导出经过身份校验的 linux/amd64 镜像包（约 34.2 MiB）：
`.artifacts/rust-pcap-log-linux-amd64.tar.gz`。可用 `docker load -i` 载入；SHA-256
见 `docs/runs/evidence/2026-10-25/image-archive.json`。源码构建不依赖该导出包。


```sh
docker build --target test -t rust-pcap-log:build-test .  # Rust 单元测试
docker build -t rust-pcap-log:test .                    # release runtime

docker run --rm --network none --cap-drop ALL \
  -e 'LISTEN_0=tcp 0.0.0.0 443,8000-8100' \
  -e 'LISTEN_9=udp :: 1234' \
  rust-pcap-log:test --check-config
```

Dockerfile 固定 Rust 1.95/bookworm，使用锁定的 `pcap 2.4.0`、`libc 0.2.191` 和 Cargo.lock。链接 Debian 的 libpcap；无 pcap 命令子进程。联网构建需要 Debian、crates.io 和基础镜像仓库可达。构建过程不修改宿主机网络/Docker 配置。镜像身份和实际版本在运行证据中记录。

本机 CDN/DNS 有间歇连接失败，实际构建使用的临时 `--add-host` 参数见运行记录 03；没有写入 Dockerfile 或修改宿主网络。正常网络使用上述通用命令。不要将运行记录中的 CDN IP 当长期配置。

原生 Linux（需要 Rust 工具链、libpcap-dev、tzdata）：

```sh
cargo test --locked
cargo build --release --locked
LISTEN_0='udp 127.0.0.1 19081' target/release/rust-pcap-log --check-config
```

原生构建步骤供复现；只有 STATUS 标明的平台经过实际验证。

### 共享目标容器的网络命名空间

以下是部署示例，**不会由测试脚本对现有业务执行**：

```sh
mkdir -p ./logs
docker run -d --name my-passive-monitor \
  --network container:YOUR_TARGET_CONTAINER \
  --cap-drop ALL --cap-add NET_RAW \
  --security-opt no-new-privileges --read-only \
  -e CAPTURE_INTERFACE=eth0 \
  -e 'LISTEN_0=tcp 0.0.0.0 443,8000-8100' \
  -e 'LISTEN_8=udp 0.0.0.0 1234' \
  -e TZ=Asia/Shanghai -e LOG_FILE=/logs/access.log \
  -v "$PWD/logs:/logs" \
  rust-pcap-log:test
```

普通文件示例要求挂载目录对容器 UID/GID 可写。Linux 上 `--cap-drop ALL` 的 root 不能自动绕过文件权限；可准备可写属组并通过 `--group-add <GID>` 授予目录写权限，不要为此增加 DAC_OVERRIDE 或使用全局 chmod 777。

不需要 privileged、NET_ADMIN、host network、host PID 或 Docker socket。默认使用容器 root 身份但 capabilities 仅 NET_RAW；这不是“任意非 root 用户都验证通过”的承诺。关闭 promiscuous 模式。`--check-config` 和离线回放不需要 NET_RAW。选择 `lo` 抓回环，`any` 的 SLL/SLL2 由解析器处理；重复镜像/多接口观测不自动去重。

## 配置

| 变量 | 默认 | 行为 |
|---|---|---|
| `LISTEN_<数字>` | 必填至少一项 | `tcp\|udp IP port[,start-end]`，编号可不连续，重复/相邻范围合并 |
| `CAPTURE_INTERFACE` | `eth0` | 一个接口名 |
| `LOG_FILE` | `/dev/stdout` | `/dev/stdout`、`-`、额外别名 `stdout`，或普通文件；自动创建父目录，追加 |
| `LOG_FORMAT` | 见下 | 白名单模板；禁止控制字符（TAB 除外），最大 65536 字节 |
| `TZ` | `UTC` | 已安装的 IANA 时区；无效时非零退出 |
| `IGNORE_CHECKSUMS` | `true` | `true/false/1/0`；false 真正验证 IPv4 与完整 TCP/UDP 校验和，分片先重组 |
| `UDP_INACTIVITY_TIMEOUT` | `60` | 1..86400 秒，双向任一包刷新 |
| `SHUTDOWN_TIMEOUT` | `15` | 1..86400 秒；停止排空及单次输出阻塞的硬截止时间 |
| `PCAP_BUFFER_MB` | `8` | 1..1024 MiB，与旧项目相同有效范围 |
| `MAX_SESSIONS` | `100000` | 1..10000000，达到上限明确失败，不把淘汰流当完整会话 |
| `MAX_FRAGMENTS` | `128` | 1..65536，另受分片字节预算约束 |
| `FRAGMENT_CACHE_MB` | `8` | 1..1024 MiB，独立分片重组预算 |
| `STATS_INTERVAL` | `60` | 1..86400 秒，stderr 统计周期；离线以 PCAP 时间推进 |

`0.0.0.0` / `::` **不是所有远端 IP**：只匹配共享网络命名空间启动时本机对应地址族，加旧项目的 127/8、::1 语义。发现失败终止。地址变化后需要有计划地重启刷新快照。精确规则与通配规则按 OR 相加，不相互遮蔽。

两个端点分别按 IP + 协议 + 端口匹配，恰好一个命中才记录。方向与 TCP 谁发起无关；远端恰好使用相同端口不会仅因端口而被视为 server。

默认模板：

```text
$remote_addr:$remote_port - [$time_iso8601] $protocol in_bytes=$bytes_received out_bytes=$bytes_sent session_time=$session_time server=$server_addr:$server_port
```

允许变量：`remote_addr remote_port time_iso8601 protocol bytes_sent bytes_received session_time server_addr server_port`。支持 `$name`、`${name}`、`$$`；不执行 shell、不递归展开。`bytes_sent` 为 server→remote，`bytes_received` 为 remote→server；duration 三位小数。IP 字节不是 payload；例如 IPv4 UDP 32-byte payload 每方向计 60 bytes。分片、ACK、重传和 duration 的特殊口径见兼容文档。

业务记录仅写 LOG_FILE/stdout；诊断/计数仅写 stderr。时间戳为**输出时墙钟**，不是历史 PCAP 包时间。没有默认长连接周期快照。

### 日志轮转与停止

```sh
mv logs/access.log logs/access.log.1
docker kill --signal HUP my-passive-monitor
# stderr 确认 log file reopened。SIGHUP 不清空会话。
docker stop --time 20 my-passive-monitor  # Docker 截止时间应大于 SHUTDOWN_TIMEOUT
```

重启追加原文件，不覆盖。普通文件追加写，无用户态日志队列；每条立即 write，不保证断电后的 fsync 持久性。输出阻塞时**反压抓包**，可能导致内核丢包；超过截止时间非零退出并明确提示可能丢失记录。不以无界队列掩盖阻塞。普通停止仅输出仍保留的状态，不承诺已排空所有网卡/内核缓冲；进程对可中断 I/O 有关闭截止时间；内核不可中断的 D 状态/NFS 故障不能保证由用户态定时器解除。SIGKILL/OOM/主机故障不能排空。

### 离线回放

```sh
python3 tests/generate_pcaps.py
docker run --rm --network none --cap-drop ALL --read-only \
  -v "$PWD/tests/fixtures:/fixtures:ro" \
  -e 'LISTEN_0=tcp 100.64.0.20 443,8000-8100' \
  -e 'LISTEN_3=udp 100.64.0.20 1234' \
  rust-pcap-log:test --read-pcap /fixtures/sessions.pcap
```

`--check-config` 校验语法/模板/时区和必要的本机地址发现，不会打开抓包接口或日志文件；接口权限、路径可写性由实际启动验证。普通文件相对路径按进程工作目录解析，建议使用绝对路径。

离线和在线复用相同解析器、规则、聚合和模板。历史 PCAP 的通配地址仍按当前命名空间发现，故差分测试使用精确 IP；不要误把它当历史网络地址发现。

## 内存边界及观测

- 单线程、二进制地址、固定大小会话字段、整数计数。普通未命中流不建立状态。
- 会话 HashMap 有硬上限；BTreeSet 超时索引恰好每会话一项，更新时删除旧项，**不每包追加残留堆项**。低水位收缩 HashMap；allocator RSS 不保证立即退回内核。
- 不保留普通 TCP/UDP payload，不重组 TCP 应用字节流。分片例外：每个活动数据报分配 64 KiB 数据 + 8 KiB byte-presence bitmap，加有界元数据，实际由条目数和字节预算中较严者限制。按首次碎片后 300 秒过期。
- 四层以内封装临时记录最多四项；没有跨包输出队列。模板/单条渲染有固定输入上限。
- 抓包缓冲独立于状态表；snaplen=262144，不用少抓 ACK、重传、分片或截短包节省内存。未设置端口 BPF。
- stderr 包含 frames、parsed/accepted/filtered、active/capacity/timers/peak、emitted/reused、截断/畸形/校验和、分片完成/过期/重叠、资源限制等计数；另有 libpcap received/dropped/if_dropped。
- `received` 是平台/libpcap 系统计数，loopback 可能包含被 libpcap 内部抑制的重复方向；不能强行等同 parsed 或业务包数。**dropped=0 不是端到端完整性证明**。

不要为漂亮数字降低 PCAP_BUFFER_MB、丢状态或忽略解析失败。先在相同流量与缓冲条件下验收，再按真实峰值/丢包调整。容量耗尽、未支持封装或严重坏包的开发期策略是失败并拒绝输出假完整记录；不是无损保证。

## 自动化验证

```sh
# Docker 构建后；脚本只创建唯一 rpl-test-* 资源并 finally 清理自身。
python3 tests/differential.py
python3 tests/tcp_cycles.py  # 离线 10000 TCP SYN 状态，三轮过期；不是实网 TCP 压测
python3 -m unittest discover -s tests -p 'test_*.py' -v

# 若没有旧镜像，可从只读复制的旧源码构建独立参考镜像：
docker build -t rust-pcap-log:zeek-reference tests/reference/legacy
ZEEK_TEST_IMAGE=rust-pcap-log:zeek-reference python3 tests/differential.py

# 必须串行运行基准，避免并发构建/测试污染 CPU/内存采样。
python3 tests/benchmark.py --image zeek-monitor:memory-optimized \
  --image rust-pcap-log:test --repeats 3 --output .artifacts/memory/baseline.json
python3 tests/benchmark.py --image zeek-monitor:memory-optimized \
  --image rust-pcap-log:test --repeats 3 --extended --output .artifacts/memory/extended.json
```

发送器是独立 Python 测试容器/独立 cgroup，仅共享隔离网络命名空间。Rust 镜像没有 Python。默认测试发送镜像为 `python:3.13-slim-bookworm`；`SENDER_IMAGE`、`RUST_TEST_IMAGE`、`ZEEK_TEST_IMAGE` 可覆盖。

PCAP 差分比较**完整排序后行集合（含重复行）**：端点、协议、双向字节、duration 精确一致，不用容差掩盖；墙钟时间单独断言。安全拒绝用例是 **gate** 而不是“兼容通过”。所有测试仅表示指定夹具/平台的证据，未测试内容见 STATUS。

## 本机实测摘要（2026-10-25）

Linux/amd64 Docker Desktop，release，同 8 MiB 缓冲，旧优化版和新版本各三轮交替：

| 阶段 | 旧 Docker stats 中位数 | 新 Docker stats 中位数 | 新 RSS 中位数 |
|---|---:|---:|---:|
| 空闲 | 58.31 MiB | 1.23 MiB | 11.28 MiB |
| 保留 2000 UDP 流 | 59.86 MiB | 1.79 MiB | 12.19 MiB |
| 再加 10000 未监控流 | 80.46 MiB | 1.79 MiB | 12.19 MiB |

**不能将这里的 1.23 MiB 宣称为总物理占用**：独立 smaps 审计确认两版本都有
8192 KiB socket 抓包映射；本机 cgroup/Docker 口径没有完整体现它，而 RSS/PSS 有。
20000 UDP 流时新 RSS 中位数 18.95 MiB；过期后 active/timers 归零，三轮创建/过期
后 RSS 约 14.61 MiB，没有回到初始值，不能据此宣称长期零泄漏。
完整范围、RSS/PSS、CPU、包数和证据见 `docs/runs/2026-10-25-04-performance.md`。
