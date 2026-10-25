# 04 — Release memory, CPU, capture correctness and expiry

## Method

Actual commands, executed serially after builds/functional tests:

```sh
python3 tests/benchmark.py --image zeek-monitor:memory-optimized \
  --image rust-pcap-log:test --repeats 3 --output .artifacts/memory/baseline.json
python3 tests/benchmark.py --image zeek-monitor:memory-optimized \
  --image rust-pcap-log:test --repeats 3 --extended --output .artifacts/memory/extended.json
python3 tests/summarize_benchmark.py .artifacts/memory/baseline.json \
  .artifacts/memory/extended.json
python3 tests/audit_memory.py
```

Same 8 MiB capture buffer and paced traffic for both versions. Alternating order:
old/new, new/old, old/new. Each repetition is a fresh isolated `--network none`
monitor capturing lo with NET_RAW only. A separate Python container/cgroup provides
both UDP endpoints, sharing only the monitor network namespace. No sender memory is
charged to the measured container. 32-byte UDP payload means 60 IP bytes/direction.
No BPF, snaplen 262144, no discarded ACK/retransmissions/state to improve memory.

Baseline UDP timeout=3600s retains 2000 monitored + 10000 unmatched flows until stop.
Extended timeout=12s **on both versions**: retain 20000 monitored flows, let them expire,
then three further 2000-flow create/expire cycles. This short timeout is only a test
setting, not a changed production default. Rust STATS_INTERVAL=1 supplies visibility;
old image has no corresponding periodic application counters.

Docker stats is sampled BEFORE docker exec. RSS/PSS are separately read from
/proc/status and smaps_rollup. Old process totals include Python supervisor + Zeek;
new has one process and one thread. These old totals are NOT the Zeek-only RSS from
the user's older benchmark. Raw cgroup memory.current/cpu.stat are retained but marked
as including the sampling exec shell; they are not presented as clean service-only
memory. Process CPU ticks exclude that sampler. Docker CPU% snapshots are post-traffic,
not a measurement of saturation. Sender rates exclude container startup.

## Baseline results

MiB; median [min, max], three runs each. Docker CLI values are rounded by Docker.

| Version / phase | Docker stats | RSS process sum | PSS process sum |
|---|---:|---:|---:|
| Old idle | 58.31 [57.67,58.52] | 123.81 [123.55,123.93] | 121.09 [120.86,121.21] |
| Rust idle | 1.23 [1.15,1.39] | 11.28 [11.23,11.37] | 10.43 [10.42,10.51] |
| Old 2000 monitored | 59.86 [59.84,60.23] | 125.97 [125.71,126.09] | 123.24 [123.03,123.34] |
| Rust 2000 monitored | 1.79 [1.78,1.80] | 12.19 [12.14,12.27] | 11.32 [11.29,11.42] |
| Old +10000 unmatched | 80.46 [80.10,80.52] | 146.30 [146.18,146.33] | 143.59 [143.46,143.61] |
| Rust +10000 unmatched | 1.79 [1.78,1.79] | 12.19 [12.14,12.27] | 11.33 [11.27,11.43] |

Rust keeps exactly 2000 sessions/2000 timers after unmatched traffic, and none of the
10000 unmatched flows are logged. Observed RSS growth for the monitored stage is
about 0.91 MiB / 2000 flows (roughly 475 bytes/flow for THIS allocation point, not a
universal per-flow allocation guarantee; HashMap capacity grows in steps).

**Do not call this a 1.23 MiB total-memory process.** Independent smaps audit shows
an 8192 KiB `socket:[...]` mapping with Rss=Pss=8192 KiB in BOTH versions. The local
Docker Desktop cgroup readings do not account for that entire mapping (Rust cgroup
memory.current including a sampler was only ~2.3 MiB, sock=0). RSS/PSS do reflect it.
Thus 10–25 MiB low-load exploration is supported here by measured RSS/PSS around
11–12 MiB, not by pretending the capture buffer is free. Native-host accounting may
be different. Do not set a tiny memory limit from Docker stats alone.

## High state and repeated expiry

| Version / phase | Docker stats median [range] | RSS median [range] | PSS median [range] |
|---|---:|---:|---:|
| Old 20000 active | 96.17 [96.16,96.17] | 161.93 [161.66,162.12] | 159.27 [158.92,159.39] |
| Rust 20000 active | 8.50 [8.50,8.77] | 18.95 [18.88,18.98] | 18.08 [18.05,18.12] |
| Old final cycle expired | 96.96 [96.94,97.45] | 162.46 [162.16,163.33] | 159.81 [159.40,160.62] |
| Rust final cycle expired | 4.16 [2.74,4.36] | 14.61 [13.09,14.64] | 13.74 [12.26,13.80] |

Every Rust expired snapshot has active=0 and timers=0; final capacity=0. Remaining
RSS/PSS above idle is observable retention/allocator behavior, not proof that RAM
returns immediately. All three 2000-flow cycles reuse that retained footprint without
stepwise growth in RSS. This is a bounded short test, **not a days-long leak test**.
Do not label old-version retained RSS a leak from this experiment either.

## CPU, volume, output and drops

| Workload | Old process CPU seconds median [range] | Rust | Paced sender rate |
|---|---:|---:|---:|
| 24000 packets baseline | 0.17 [0.16,0.19] | 0.06 [0.05,0.07] | about 12.8k–14.5k packets/s |
| 52000 packets + expiry cycles | 2.74 [2.72,6.13] | 0.85 [0.84,0.90] | about 13.7k–14.1k packets/s |

Raw CPU granularity is 10 ms; the extended first old run has a visible 6.13s outlier,
not hidden or attributed to an unproven cause. Timed windows include snapshots and
idle waits (~7.5–8.9s baseline, ~72–73s extended). Baseline CPU sampling ends
BEFORE SIGTERM, so its numbers exclude final drain/output CPU on BOTH versions;
extended windows include the already-expired sessions' output. This is not a max-throughput or
latency benchmark, and no "X times throughput" claim is made.

All **12** benchmark runs exit 0 without OOM and verify every business row exactly:
2000 rows/baseline run; 26000 rows/extended run; 60/60 bytes each, no extra rows.
Independent summary verification asserts Rust frames=parsed=24000 / 52000,
accepted=4000 / 52000, filtered=20000 / 0, and total parsed IP bytes=frames×60.
Old received counters equal 24000 / 52000. Rust raw Linux ps_recv=48000 / 104000
includes loopback observations libpcap suppresses before delivering packets; it is
not evidence that Rust processed half the workload. Both directions' expected rows
and frames independently agree. All reported capture drops=0, **not end-to-end proof**.

## Scope

Image IDs, all repeat values, RSS/PSS components, Docker CPU%, process CPU ticks,
throughput inputs, counters and exact assertions are in the saved JSON evidence.
Runtime images differ in distro/library versions (old Debian trixie / libpcap 1.10.5,
new bookworm / libpcap 1.10.3); this measures the complete implementations, not an
isolated language-only causal experiment.

Not verified: saturated/bursty line-rate capacity, large live TCP workloads, days-long
stability, production traffic, native Linux host accounting, arm64/rootless deployment,
full Zeek lifecycle/tunnel equivalence. Offline 10000-TCP-flow × 3 cycles is separately
verified but does not fill the live-TCP performance gap.
