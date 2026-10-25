# 02 — Reference probes and Rust implementation

Evidence: `.artifacts/differential/{zeek-probe,checksum-probe,overlap-tunnel-probe,additional-lifecycle-probe}.json`.
All reference invocations create a temporary read-only container with `--network none
--cap-drop ALL`, mount only new-project generated fixtures read-only, and run old
`--read-pcap`. No old-project files are written.

Observed (remote port 52000):

| Case | Old business result |
|---|---|
| full close including two trailing ACKs | received=200 sent=120 duration=0.500 |
| half close + peer data + ACK | received=160 sent=93 duration=0.600 |
| retransmitted 3-byte TCP segment | received=166 sent=80 duration=0.500 |
| IPv4 two fragments / reversed / duplicate first | received=60 duration=0 |
| IPv6 two fragments / reversed / duplicate first | received=80 duration=0 |
| fragmented UDP completes at 0.1s, then UDP at 1s | received=120 duration=0.900 |
| missing initial fragment | no business row |
| conflicting overlap, lower fragment arrives first | received=60 (first bytes preserved, checksum valid) |
| conflicting overlap, higher fragment arrives first | received=0 (preserved first bytes fail checksum) |
| bad UDP checksum | one row 0/0, duration 0 |
| bad UDP at 0, good at 1 | received=31 duration=1.000 |
| good UDP at 0, bad at 1 | received=31 duration=0.000 |
| bad TCP SYN then good SYN | separate zero-byte and 43-byte rows |
| IPIP / GRE | inner UDP row received=60 |
| VXLAN with inner/outer rules | inner UDP received=60 AND outer UDP received=110 |

These are actual Zeek 9.0.0 results, not RFC assumptions. Reference executable and
source hashes were captured in `.artifacts/reference-image-source.txt`.

Changes motivated by evidence: retain final ACK bytes but freeze fully closed TCP
duration; normalize reassembled IP sizes; first-arrival fragment overlap policy with
counter; zero-byte invalid-L4 session creation; bounded IPIP/GRE/VXLAN decoding.
Some initially implemented fatal gates for overlaps/tunnels were removed only after
these probes established the old behavior. Geneve/etc remain explicitly unimplemented.

Build issues, not hidden: host lacks Rust; first external fetches hit network
failures. Used **per-build** `--add-host` entries for verified reachable CDN endpoints,
not host/Docker daemon changes, and kept TLS validation. Initial test target reached
passing Rust tests but optional clippy was absent in the base image. Mandatory test
target now runs `cargo test --locked`; formatting was run with a temporary Rust
container installing rustfmt. Initial `cargo fetch` without target downloaded
unneeded Windows packages; interrupted this own build, then limited fetch to rustc's
host target and used a project-scoped BuildKit registry cache. Build/failure logs in
`.artifacts/build-test*.log` and `.artifacts/format-bootstrap.log`.

No successful final build/performance result is inferred from these intermediate steps.

## Final differential corrections (not tolerance changes)

The first full Rust/Zeek run found exactly two new differences:

1. Fragment expiry was previously checked after a packet. A tail at t=301s could
   complete a 300s-expired datagram. Added a bounded next-expiry watermark and expire
   BEFORE parsing, with no per-packet stale heap entries.
2. With non-copied IPv4 options, the header length is from Zeek's **first observed
   fragment**, not necessarily offset zero. Added both orderings; actual expected
   count is 64 when option-bearing offset-zero arrives first, 60 in reverse order.
   Preserved this old semantic, rather than changing expected values to our design.

Evidence: `.artifacts/differential-early.log`, `options-probe.json`; that strict run
had 57 cases, 54 exact equivalences and 3 explicit rejection gates, zero unexplained
failures. Adding the separately verified IPv6 atomic-fragment fixture brings the
final delivery matrix to 58 cases (55 equal + 3 gates), recorded in run 03. Gates: truncation, malformed total IP length, unimplemented Geneve.
Full fields include duration with no tolerance, endpoints, protocol and IP counters;
wall-clock timezone/escaping is a separate assertion.

## Old documentation drift

Read-only README cross-check: old README line 133 says missing duration falls back
to 0.000, but current monitor always supplies `c$duration` and Python formatter
indexes `record["session_time"]` (no missing-key fallback). One-packet zero duration
is a real supplied value, not a missing-field default. README line 155 uses former
Conn::Info names `orig_ip_bytes/resp_ip_bytes`; actual current code reads endpoint
`num_bytes_ip` directly. New behavior follows the code and reproducible packets.
The old README's warning about trailing ACK duration agrees with actual tests.
