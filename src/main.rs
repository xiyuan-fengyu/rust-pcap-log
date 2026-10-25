use pcap::{Activated, Capture};
use rust_pcap_log::{
    Result,
    config::Config,
    engine::Engine,
    output::{self, REOPEN, STOP, Sink},
    packet::{Issue, Parser},
};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};
#[derive(Default, Debug)]
struct CaptureStats {
    frames: u64,
    ip_bytes: u64,
    truncated: u64,
    malformed: u64,
    checksum_rejected: u64,
    unsupported: u64,
    fragment_limit: u64,
    fragment_conflict: u64,
    timestamp_regressions: u64,
}
fn run<T: Activated + ?Sized>(mut cap: Capture<T>, config: Config, live: bool) -> Result<()> {
    let link = cap.get_datalink().0;
    if ![1, 12, 101, 113, 228, 229, 276].contains(&link) {
        return Err(format!("unsupported capture datalink {link}").into());
    }
    let mut sink = Sink::new(&config.log_file)?;
    let mut parser = Parser::new(
        !config.ignore_checksums,
        config.max_fragments,
        config.fragment_bytes,
    );
    let mut engine = Engine::new(config.rules, config.max_sessions, config.udp_timeout);
    let start = Instant::now();
    let mut stats = CaptureStats::default();
    let mut clock = 0;
    let mut last_stamp = 0;
    let mut maintenance = 0;
    let mut report_at = config.stats_interval;
    eprintln!(
        "[rust-pcap-log] ready: libpcap link={link} buffer_mb={} snaplen=262144 promisc=false live={live} timezone={} thread_count=1",
        config.pcap_buffer_mb, config.tz
    );
    let result = (|| -> Result<()> {
        loop {
            if REOPEN.swap(false, Ordering::SeqCst) {
                sink.reopen()?;
                eprintln!("[rust-pcap-log] log file reopened");
            }
            if STOP.load(Ordering::SeqCst) {
                break;
            }
            if live {
                clock = start.elapsed().as_micros() as u64;
            }
            let packet = match cap.next_packet() {
                Ok(p) => Some(p),
                Err(pcap::Error::TimeoutExpired) => None,
                Err(pcap::Error::NoMorePackets) if !live => break,
                Err(e) => return Err(format!("capture failed: {e}").into()),
            };
            let mut emit = |s: &rust_pcap_log::engine::Session| {
                sink.write(config.template.render(s, &output::wall_time()?).as_bytes())
            };
            if let Some(p) = packet {
                stats.frames += 1;
                if p.header.ts.tv_sec < 0 || !(0..1_000_000).contains(&p.header.ts.tv_usec) {
                    return Err("invalid packet timestamp".into());
                }
                let stamp = p.header.ts.tv_sec as u64 * 1_000_000 + p.header.ts.tv_usec as u64;
                if stamp < last_stamp {
                    stats.timestamp_regressions += 1;
                }
                last_stamp = last_stamp.max(stamp);
                if !live {
                    clock = clock.max(stamp);
                }
                if p.header.caplen < p.header.len {
                    stats.truncated += 1;
                }
                if p.header.caplen > p.header.len {
                    return Err("malformed capture: caplen exceeds wire length".into());
                }
                // Expire even when the current packet is irrelevant or a fragment.
                engine.expire(clock, &mut emit)?;
                match parser.parse(link, p.data, clock) {
                    Ok(packet) => {
                        for packet in parser.take_additional().chain(packet) {
                            if packet.checksum_valid {
                                stats.ip_bytes += packet.ip_bytes as u64;
                            } else {
                                stats.checksum_rejected += 1;
                            }
                            engine.process(packet, clock, stamp, &mut emit)?;
                        }
                    }
                    Err(Issue::Checksum) => {
                        stats.checksum_rejected += 1;
                        if stats.checksum_rejected == 1 {
                            eprintln!(
                                "[rust-pcap-log] checksum rejected: offload may cause false negatives; IGNORE_CHECKSUMS=false"
                            );
                        }
                    }
                    Err(issue) => {
                        match issue {
                            Issue::Truncated => stats.truncated += 1,
                            Issue::Malformed => stats.malformed += 1,
                            Issue::Unsupported => stats.unsupported += 1,
                            Issue::FragmentLimit => stats.fragment_limit += 1,
                            Issue::FragmentConflict => stats.fragment_conflict += 1,
                            _ => {}
                        }
                        return Err(format!("packet {issue}: unsafe to emit apparently complete records; retained sessions NOT drained (see compatibility documentation)").into());
                    }
                }
            } else {
                engine.expire(clock, &mut emit)?;
                std::thread::sleep(Duration::from_millis(10));
            }
            if clock >= maintenance {
                parser.expire(clock);
                engine.compact();
                maintenance = clock + 1_000_000;
            }
            if clock >= report_at {
                report(&engine, &parser, &stats, "periodic");
                if live {
                    capture_stats(&mut cap)?;
                }
                report_at = clock + config.stats_interval;
            }
        }
        let mut emit = |s: &rust_pcap_log::engine::Session| {
            sink.write(config.template.render(s, &output::wall_time()?).as_bytes())
        };
        engine.drain(&mut emit)?;
        if parser.fragment_count() != 0 {
            eprintln!(
                "[rust-pcap-log] incomplete fragment datagrams={} (not counted as completed IP packets)",
                parser.fragment_count()
            );
        }
        Ok(())
    })();
    report(
        &engine,
        &parser,
        &stats,
        if result.is_ok() { "final" } else { "fatal" },
    );
    if live {
        let s = capture_stats(&mut cap);
        if result.is_ok() {
            s?;
        } else if let Err(e) = s {
            eprintln!("[rust-pcap-log] {e}");
        }
    }
    result?;
    sink.finish()
}
fn capture_stats<T: Activated + ?Sized>(cap: &mut Capture<T>) -> Result<()> {
    let s = cap.stats()?;
    eprintln!(
        "[rust-pcap-log] capture: received={} dropped={} if_dropped={} (capture-system counters; NOT end-to-end completeness)",
        s.received, s.dropped, s.if_dropped
    );
    Ok(())
}
fn report(e: &Engine, p: &Parser, s: &CaptureStats, phase: &str) {
    eprintln!(
        "[rust-pcap-log] stats: phase={phase} frames={} parsed={} accepted={} filtered={} emitted={} active={} capacity={} timers={} peak={} session_limit={} truncated={} malformed={} checksum_rejected={} unsupported={} fragment_limit={} fragment_conflict={} overlap_conflicting_bytes={} fragments={} fragment_bytes={} fragments_completed={} fragments_expired={} timestamp_regressions={} ip_bytes={} reused={}",
        s.frames,
        e.stats.packets,
        e.stats.accepted,
        e.stats.filtered,
        e.stats.emitted,
        e.sessions.len(),
        e.sessions.capacity(),
        e.timer_count(),
        e.stats.peak_sessions,
        e.stats.session_limit,
        s.truncated,
        s.malformed,
        s.checksum_rejected,
        s.unsupported,
        s.fragment_limit,
        s.fragment_conflict,
        p.overlap_conflicts,
        p.fragment_count(),
        p.fragment_memory(),
        p.fragments_completed,
        p.fragments_expired,
        s.timestamp_regressions,
        s.ip_bytes,
        e.stats.reused
    );
}
fn main() -> std::process::ExitCode {
    match entry() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("[rust-pcap-log] fatal: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}
fn entry() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--help"] || args == ["-h"] {
        println!(
            "rust-pcap-log [--check-config | --read-pcap FILE]\nConfiguration: LISTEN_<number>=tcp|udp IP port[,range], LOG_FILE, LOG_FORMAT, TZ, CAPTURE_INTERFACE, IGNORE_CHECKSUMS, UDP_INACTIVITY_TIMEOUT, SHUTDOWN_TIMEOUT, PCAP_BUFFER_MB, MAX_SESSIONS, MAX_FRAGMENTS, FRAGMENT_CACHE_MB, STATS_INTERVAL"
        );
        return Ok(());
    }
    if args == ["--version"] {
        println!("rust-pcap-log {} (pcap 2.4.0)", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let check = args == ["--check-config"];
    let pcap = if args.len() == 2 && args[0] == "--read-pcap" {
        Some(&args[1])
    } else if args.is_empty() || check {
        None
    } else {
        return Err("usage: rust-pcap-log [--check-config | --read-pcap FILE]".into());
    };
    let config = Config::from_env()?;
    if check {
        println!("CAPTURE_INTERFACE={} TZ={} IGNORE_CHECKSUMS={} PCAP_BUFFER_MB={}", config.interface, config.tz, config.ignore_checksums, config.pcap_buffer_mb);
        println!("UDP_INACTIVITY_TIMEOUT={} SHUTDOWN_TIMEOUT={} STATS_INTERVAL={}", config.udp_timeout / 1_000_000, config.shutdown_timeout, config.stats_interval / 1_000_000);
        println!("MAX_SESSIONS={} MAX_FRAGMENTS={} FRAGMENT_CACHE_MB={}", config.max_sessions, config.max_fragments, config.fragment_bytes / 1024 / 1024);
        println!("LOG_FILE={:?} LOG_FORMAT={:?}", config.log_file, std::env::var("LOG_FORMAT").unwrap_or_else(|_| rust_pcap_log::config::DEFAULT_FORMAT.into()));
        for rule in &config.rules.groups {
            println!("RULE: {} {} {:?}", if rule.proto == 6 { "tcp" } else { "udp" }, rule.addr, rule.ports);
        }
        let mut local: Vec<_> = config.rules.local.iter().collect();
        local.sort();
        println!("LOCAL_ADDRESSES: {}", local.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", "));
        println!("WILDCARD_LOOPBACK: 127.0.0.0/8, ::1 (family-specific)");
        return Ok(());
    }
    output::init_timezone(&config.tz);
    output::install_signals(config.shutdown_timeout)?;
    if let Some(file) = pcap {
        run(Capture::from_file(file)?, config, false)
    } else {
        // No BPF: fragments, extension headers and both directions reach parser.
        let cap = Capture::from_device(config.interface.as_str())?
            .snaplen(262144)
            .promisc(false)
            .buffer_size(config.pcap_buffer_mb * 1024 * 1024)
            .timeout(100)
            .open()?
            .setnonblock()?;
        run(cap, config, true)
    }
}
