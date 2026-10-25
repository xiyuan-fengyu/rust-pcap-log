# 05 — 容器内每日轮转与目录映射（2026-10-25）

## 变更

- 延续 `LOG_FILE` 指定容器内路径；新增 `LOG_ROTATE_SUFFIX`，默认 `.%Y%m%d`。
- 按 `TZ` 的本地墙钟日期跨日归档，旧文件追加其所属日期，新建原路径文件；无流量也会检查，写入前再次检查。
- 挂载整个可写日志目录，例如 `-v "$PWD/logs:/logs" -e LOG_FILE=/logs/access.log`，而非单文件挂载。当前文件和归档均保存在宿主机，自动轮转不需要 HUP。
- 同名归档依次追加 `.1`、`.2`；Linux 使用 `renameat2(RENAME_NOREPLACE)`，不覆盖既有目标；同名尝试数量有上限。
- 同日重启追加；跨日启动时按非空文件 mtime 归档。空文件启动按当日计时，停机天数不补空归档，时钟回拨不重复轮转。
- stdout/stderr 别名及字符设备跳过，普通 FIFO 仍拒绝；普通文件符号链接保留、轮转实际目标。保留外部重命名 + HUP 入口。
- 单线程、无新依赖、无后台日志队列。轮转使用现有输出 watchdog，失败明确退出；不自动删除/压缩归档，不支持多个写入者共享同一路径。

## 构建方式和镜像

本机没有原生 Cargo，使用已有 Docker Linux/amd64 工具链和 BuildKit registry 缓存。
直接从项目 Dockerfile 构建时 Debian 包下载长时间停滞，已取消；这次实际采用既有构建/运行镜像中的依赖，重新编译当前源代码及测试，不宣称本轮完成全新联网依赖安装。

临时 `.artifacts/Dockerfile.rotation-test`：

```dockerfile
FROM rust-pcap-log:build-test AS test
COPY src /work/src
RUN --mount=type=cache,id=rpl-cargo-registry,target=/usr/local/cargo/registry cargo test --locked --offline
RUN --mount=type=cache,id=rpl-cargo-registry,target=/usr/local/cargo/registry cargo build --locked --offline --release
FROM rust-pcap-log:test AS runtime
COPY --from=test /work/target/release/rust-pcap-log /usr/local/bin/rust-pcap-log
```

```sh
docker build --network none -f .artifacts/Dockerfile.rotation-test --target test -t rust-pcap-log:rotation-build .
docker build --network none -f .artifacts/Dockerfile.rotation-test -t rust-pcap-log:rotation-test .
RUST_TEST_IMAGE=rust-pcap-log:rotation-test RUST_BUILD_IMAGE=rust-pcap-log:rotation-build \
  python3 -m unittest discover -s tests -p 'test_*.py' -v
RUST_TEST_IMAGE=rust-pcap-log:rotation-test python3 tests/differential.py
RUST_TEST_IMAGE=rust-pcap-log:rotation-test python3 tests/tcp_cycles.py
```

常规可联网环境仍使用项目原有 `make test` / `docker build`，无需修改 Dockerfile。
新运行镜像 `rust-pcap-log:rotation-test`：
`sha256:1f4253f1c69f91103315c38945e5239bc29f91b0c7adc96f4508107345db268b`。
旧 `rust-pcap-log:test` 和 `.artifacts/rust-pcap-log-linux-amd64.tar.gz` 没有更新，不含本轮功能；未部署或操作生产容器。

## 验证结果及边界

- Rust 单元测试 **30/30**。新增 7 项覆盖午夜空闲/新 inode、后缀/冲突/回拨/跨年、同日和跨日重启、空文件/闰日、标准流/设备、符号链接、外部文件替换；配置默认值和非法后缀加入原配置测试。
- Docker 集成测试 **15/15**，含原有 11 项和新增 4 项每日轮转测试；保留外部 HUP 时活动 UDP 会话及重启追加等原有断言。
- 轮转测试挂载真实宿主机临时目录，以测试专用 `LD_PRELOAD time()` 库模拟 UTC/上海午夜，验证无流量创建新文件、默认/自定义后缀、归档冲突保护，以及午夜后实际 UDP 捕获输出进入新文件。另验证 stdout 即使重定向到普通文件仍不轮转、老文件重启归档、非法配置拒绝。
- **时间推进是合成的，目录重命名/新建、Docker 运行及 UDP 抓包是实际执行的**。未修改宿主机时钟，也未给生产二进制增加假时钟配置。并非实际等候 24 小时或长期运行验收。
- PCAP 差分 **58 个用例：55 完整一致、3 个既有明确拒绝 gate，无新增失败**。
- 三轮 10000 TCP SYN 离线状态过期：新/旧各 **30000 条记录精确一致**，不代表实网 TCP 压测。
- 未重跑性能基准；未验证生产流量、其他架构、NFS/SMB 归档或多进程并发轮转；一个路径只由一个实例管理。

原始输出：`.artifacts/rotation-unit.log`、`rotation-runtime.log`、`rotation-regression.log`、`rotation-differential.log`、`rotation-tcp-cycles.log`、`.artifacts/rotation/*.json`。
可追踪摘要与源文件哈希见 `evidence/2026-10-25/daily-rotation.json`。
