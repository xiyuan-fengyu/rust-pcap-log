# 06 — 默认日志字段顺序（2026-10-25）

默认 `LOG_FORMAT` 调整为：

```text
$remote_addr:$remote_port - [$time_iso8601] $protocol server=$server_addr:$server_port in_bytes=$bytes_received out_bytes=$bytes_sent session_time=$session_time
```

仅移动 `server` 字段，不改变地址、字节统计、时间、时长语义；显式配置的 `LOG_FORMAT` 继续优先。README 同步，旧版差分参考实现不修改。

验证：
- 使用运行记录 05 的离线缓存构建方式，重新编译源代码与 release 二进制，镜像标签分别为 `rust-pcap-log:format-build`、`rust-pcap-log:format-test`。
- **31/31 Rust 单元测试通过**，新增用用户示例地址、UDP 双向 68/72 bytes 和指定时间字符串逐字核对默认输出的测试。
- 新运行镜像对 `sessions.pcap` 的实际离线回放验证了默认字段顺序和显式 `LOG_FORMAT` 覆盖；未部署生产，也未重跑完整差分/实网/性能测试。
- 新运行镜像 ID：`sha256:47dd6f3f19242f08a43ffb9b9577ef9ae7222eda028f1ce5c9392cffd9c44859`。此前 `:test`、`:rotation-test` 以及旧导出包未覆盖。

输出证据：`.artifacts/format-unit.log`、`.artifacts/format-runtime.log`、`.artifacts/format-smoke.json`。
