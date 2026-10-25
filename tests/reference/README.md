# Read-only baseline copies

Copied from `../zeek-monitor` on 2026-10-25. `source-manifest.json` records SHA-256
of original source/tests/docs. Originals have not been modified. `legacy/` can
build an isolated reference with the original runtime, not a reimplementation:

```sh
docker build -t rust-pcap-log:zeek-reference tests/reference/legacy
ZEEK_TEST_IMAGE=rust-pcap-log:zeek-reference python3 tests/differential.py
```

Actual initial differential/benchmark uses existing `zeek-monitor:memory-optimized`
image `sha256:99eb5cf3139a42f856d56a9e2a19554ebf656d920a67835d9840f631ff4b5031`.
No baseline/production image tag is overwritten. Reference Python is TEST ONLY,
never copied into the Rust runtime image. Fixture generator expects IP byte counts,
not payload bytes; synthetic capture timestamp is deliberately in 2023.
