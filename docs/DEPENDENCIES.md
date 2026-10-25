# Verified dependency/API choices

Cargo.toml pins `pcap=2.4.0` and `libc=0.2.191`; Cargo.lock records the resolved
transitive versions/checksums. Linux host-target fetch avoids downloading irrelevant
Windows libraries; a scoped BuildKit registry cache does not change runtime contents.
Rust release binary links libpcap directly. Linux FFI in `output.rs` / `config.rs`
is narrowly limited to libc address discovery, timezone formatting, POSIX signals,
fd/poll operations; pointer ownership/signal-safety comments are inline.

Primary references inspected, in addition to actually compiling and testing:

- https://docs.rs/pcap/2.4.0/pcap/struct.Capture.html — from_device/from_file,
  snaplen, buffer_size, promisc, timeout, open, setnonblock, next_packet, stats.
- https://www.tcpdump.org/manpages/pcap_stats.3pcap.html — platform-dependent
  ps_recv/ps_drop/ps_ifdrop; zero is not a completeness guarantee.
- https://raw.githubusercontent.com/the-tcpdump-group/libpcap/libpcap-1.10.3/pcap-linux.c
  — linux_check_direction suppresses duplicate loopback outgoing observations;
  PACKET_RX_RING is mmap'ed. pcap_next_ex uses a bounded oneshot copy buffer.
- Zeek 9.0.0 installed `base/init-bare.zeek` and
  `base/protocols/conn/inactivity.zeek`, and the copied original monitor script:
  actual constants, callbacks and counters, with strict runnable differential tests.

The runtime image's exact libpcap/Debian versions, image ID and binary hash are
recorded in the final run artifacts. A working API compile is not proof of Zeek
semantic compatibility; see COMPATIBILITY.md and individual fixture results.
