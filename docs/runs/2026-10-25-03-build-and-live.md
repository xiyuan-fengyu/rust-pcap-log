# 03 — Final image, strict differential, isolated capture and failures

## Image / environment

- Date: 2026-10-25. Docker Desktop 4.82.0, Engine 29.6.1, Linux 6.12.76-linuxkit,
  linux/amd64. No native Linux server/arm64/rootless result is claimed.
- `rust-pcap-log:test`:
  `sha256:aaf23a7e5abb7eeb4b980c8df3f91052d122fafbaf25e3e53d201e7cde8a4683`.
- Binary SHA-256:
  `4989938d34a48179c832cfe20a06a4cfebc485c29e77e4de20543328f61525df`.
- Release/LTO/stripped binary about 505 KiB. Actual dynamic dependencies include
  libpcap 1.10.3-1, glibc 2.36-9+deb12u14; tzdata 2026e. Runtime inspection finds
  no python3, zeek or tcpdump command. libpcap's Debian dependency libraries remain;
  this is not a statically-linked/scratch image.
- Old reference image and old source hashes agree exactly (all four Python modules
  and monitor.zeek), so the comparison is against the inspected implementation.

## Actual build commands

This machine's default DNS intermittently selected unreachable CDN nodes. Successful
builds used these **per-build** overrides, with normal TLS/signature/checksum checks:

```sh
docker build --add-host deb.debian.org:151.101.2.132 \
  --add-host index.crates.io:199.232.162.137 \
  --add-host static.crates.io:199.232.162.137 \
  --target test -t rust-pcap-log:build-test .
docker build --add-host deb.debian.org:151.101.2.132 \
  --add-host index.crates.io:199.232.162.137 \
  --add-host static.crates.io:199.232.162.137 \
  -t rust-pcap-log:test .
```

These addresses are observations from this run, not permanent mirror configuration.
No host routes/firewall/Docker daemon/DNS settings were changed. Generic Dockerfile
works with reachable package repositories; the failed unmodified-DNS attempt is
retained as `build-test-default-dns.log`, not reported as a successful build.

## Executed verification

```sh
python3 tests/differential.py
python3 tests/tcp_cycles.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

- Rust unit tests: **23 passed**, no skips. Config/rule merge/mapped IP/family,
  local discovery, template escaping/rendering, append/reopen, directional counts,
  FIN/ACK duration, reuse, SYN/UDP timeout, bounded timer index/session/fragment
  capacity, overlaps, checksums, short-frame and 20,000-input malformed smoke tests.
- Final small-PCAP matrix: **58 cases**, **55 field-for-field equal**, **3 explicit
  rejection gates**, zero unexplained differences. The atomic IPv6 fragment was
  additionally probed then added to the reproducible generator. Output wall time
  and Asia/Shanghai +08:00 are separately checked against host current wall time.
- Offline TCP state load: **10,000 SYN flows × 3 creation/expiry cycles**. Same
  PCAP gives **30,000 exact rows on each version**; each row has 40 received IP
  bytes, zero sent, duration 0.000. This is NOT live TCP throughput evidence.
- Docker integration/failure suite: **11 passed**, no skips (see delivery log).

## Live evidence

Unique `rpl-test-*` resources; no production resources entered/stopped/restarted.
Shared target-container namespace, `--cap-drop ALL --cap-add NET_RAW`, read-only
monitor root, no privileged/NET_ADMIN/socket mount/host PID. Removing NET_RAW on
existing lo fails with a permission error. --check-config needs no capture capability.

- Real eth0 TCP/UDP, namespace-local 0.0.0.0 wildcard, exact-rule OR wildcard,
  remote same-numbered TCP/UDP source ports, unmonitored port exclusion.
- UDP request/response: exact IP bytes 33 received / 37 sent. TCP headers/options
  produce larger IP counts than payload; independent PCAP suite provides exact
  TCP byte/duration comparisons.
- An active UDP session survives rename + HUP; old file unchanged, new file receives
  the retained session on stop. Restart appends rather than truncates.
- Actual IPv6 ::1 traffic through `any`, SLL link 113: five distinct sessions, each
  80/80 IP bytes. SLL2 is independently covered by PCAP, not claimed as this live DLT.
- Normal SIGTERM drains and exits 0. Capture drops were zero in these tests, not a
  completeness guarantee. Linux loopback raw ps_recv can be twice parsed frames;
  primary libpcap source and actual frames/expected records explain the difference.

## Negative controls

- Invalid config/template/interface/no capability → nonzero + stderr.
- Read-only log path, FIFO without reader, /dev/full via stdout → nonzero; no fake
  successful business record. Source-local C test shim forces getifaddrs failure
  and an empty list; both refuse wildcard and exit nonzero. Shim is TEST ONLY,
  compiled in the build-test image, never part of runtime.
- MAX_SESSIONS / MAX_FRAGMENTS → explicit counter + nonzero, no normal forced-eviction
  row. Blocked pipe with SHUTDOWN_TIMEOUT=1 exits nonzero around 1.6 seconds instead
  of accumulating an output queue. Kernel uninterruptible IO is not thereby tested.
- Initial integration failure: --check-config printed binary address arrays, not
  readable IPs. Fixed the actual CLI display (seconds, rule names, local IPs) and
  reran tests; did not weaken the assertion.

## Evidence

Durable compact/raw evidence is under `evidence/2026-10-25/` (selected large JSONs
are gzip). Original commands/build failures/full outputs remain under `.artifacts/`.
`evidence-manifest.json` gives SHA-256. The image above is the one used by all final
memory runs and final functional tests; later changes only add tests/documentation.

## Exported delivery image

```sh
docker save rust-pcap-log:test | gzip -1 > .artifacts/rust-pcap-log-linux-amd64.tar.gz
docker load -i .artifacts/rust-pcap-log-linux-amd64.tar.gz  # optional import, not needed locally
```

The export was actually generated, gzip/tar read verified, and its config SHA-256
checked against the tested image ID. 35,827,367 bytes; archive SHA-256
`0294d2cab2bb95b896b920cb6764a151fbbd0ecae0cfee17033cfdfb41939a31`.
The optional import command was not needed/executed; no production deployment was
performed. Test containers/networks are gone; deliverable images, build cache and
new-project evidence remain intentionally available.
