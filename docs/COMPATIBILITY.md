# Compatibility contract and acceptance gates

This is a **business-session logger, not a full Zeek implementation**. Passing a
fixture means exactly those bytes/endpoint/lifecycle assertions passed, not universal
compatibility. See `docs/STATUS.md` for what was actually run. No production
replacement is authorized by tests in this repository.

## Preserved semantics

- Exact address/protocol/port and local-family wildcard OR; exactly one matched
  endpoint. Local address snapshot uses getifaddrs in the capture namespace, plus
  127/8 and ::1. No discovery fallback to all remote hosts.
- TCP/UDP IP-layer counts, including visible TCP retransmissions and pure ACKs.
  IPv4 total length, IPv6 40 + payload length; not caplen or Ethernet length.
- **Fragments:** baseline Zeek counts a successfully reconstructed IP datagram
  once, not the sum of fragment headers. IPv6 fragment header is removed.
  With IPv4 non-copied options, Zeek retains the header length of the first
  OBSERVED fragment, not necessarily offset zero: our ordered/reversed fixtures
  intentionally give 64/60 bytes, respectively. This order dependence is preserved.
  Missing pieces do not become invented traffic; incomplete/expired cache counters
  are separate. First-observed overlapping bytes are retained (verified differential
  cases include conflicting exact duplicates and both orders of partial overlap).
  Conflict-byte counts are diagnosed even if the business byte count is unambiguous.
- Tail ACK after both TCP endpoints closed counts bytes but does not extend duration.
  Single FIN is not unconditional removal. Closed/RST connections linger 5 seconds;
  single-sided SYN attempts expire 5 seconds from creation; ordinary TCP inactivity
  is 300 seconds, interactive destination ports 21/22/23/513 use 3600 seconds.
  A changed initial SYN sequence or closed connection can start a new incarnation.
- Bad IPv4 header checksum: discard before creating a session. Bad TCP/UDP checksum
  can create a **zero-byte** session just like the actual baseline; rejected packets
  do not advance duration or accepted TCP state. This unusual behavior is tested,
  not silently normalized into "no row". UDP/IPv4 checksum zero is legal;
  UDP/IPv6 zero is rejected when checksum checks are enabled.
- Capture timestamps drive duration. Output uses current wall clock with TZ and
  seconds precision. Offline expiration uses nondecreasing PCAP clock; regressions
  are counted. Live expiration uses monotonic time, independently of wall clock.

## Packet scope

Ethernet, up to 8 VLAN/QinQ tags, Linux SLL/SLL2, raw IPv4/IPv6. IPv4 options affect
header length/checksum but are not application-decoded. IPv6 HBH/destination options,
AH lengths and routing headers with segments-left=0 are traversed (maximum 16 headers).
Non-transport control protocols/ARP are ignored, not made into TCP/UDP sessions.

Bounded IP-in-IP (v4/v6), GRE v0 without source routing (optional checksum/key/sequence),
transparent Ethernet GRE and classic VXLAN are implemented to a maximum nesting depth
of four. VXLAN can generate both an outer UDP and an inner session, as Zeek does;
the parser's additional-record vector is bounded by that depth. This is not a claim
that every tunnel flavor or overlay-tenant identity agrees with Zeek.

## Explicit incomplete compatibility / decisions still requiring acceptance

1. **Not a complete TCP state machine.** The compact tracker does not reproduce
   every Zeek sequence-window, endpoint flip, SYN/ACK anomaly, RST validity,
   timer scheduling race or historical connection reuse heuristic. Exact timeout
   boundaries can differ from Zeek timer scheduling. Tests intentionally use exact
   field comparisons, never fuzzy duration tolerances. Untested cases are not passed.
2. No application analysis. Zeek's analyzer-confirmation-based SSH/FTP one-hour
   timeout extension has no path here. The old script declares it, but whether
   it actually triggers with that bare-loading combination on nonstandard ports
   has NOT been verified. Well-known destination-port extension is retained. Unusual interactive service ports/direction heuristics are a remaining
   difference, not an approved silent policy change.
3. Geneve, GTP, Teredo, MPLS/PPPoE, GRE source routing/PPTP, active IPv6 routing,
   home-address options, jumbograms and nesting/header limits currently **fail
   nonzero with a diagnostic**, instead of emitting invented complete counters.
   ESP cannot be decrypted; no inner session is invented. DLT_NULL is not supported.
4. Truncated IP data, malformed structure, inconsistent fragment terminal sizes,
   fragment-cache/session capacity exhaustion also fail nonzero. Retained sessions
   are **not drained as normal complete records on those fatal paths**. Previously
   emitted rows cannot be recalled. Old Zeek often continues after such traffic;
   this conservative development safety gate is not behavioral equivalence and
   is **not yet accepted as a production policy**.
5. Differing IPv4 header/options between fragments, duplicate IDs after completion,
   network namespace changes after startup, multiple interfaces duplicate capture,
   and traffic with overlay tenant collisions require further workload-specific
   verification. No deduplication of mirrored packets is claimed.
6. Checksums offload/GRO/GSO can make passive observations differ from wire packets.
   Default IGNORE_CHECKSUMS=true matches the old default. false really validates
   available complete IP/TCP/UDP/GRE data but does not repair offload metadata.

These remaining points must be resolved or expressly accepted before treating this
as a replacement for the old service. This repository does not quietly turn an
unsupported traffic type into successful-but-incomplete business statistics.
