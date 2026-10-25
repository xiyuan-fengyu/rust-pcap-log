use crate::{
    Result,
    config::{Address, Rules},
    packet::Packet,
};
use std::collections::{BTreeSet, HashMap};
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    pub server: Address,
    pub remote: Address,
    pub server_port: u16,
    pub remote_port: u16,
    pub proto: u8,
}
#[derive(Clone, Debug)]
pub struct Session {
    pub key: Key,
    pub sent: u64,
    pub received: u64,
    pub first_stamp: u64,
    pub last_stamp: u64,
    deadline: u64,
    last_activity: u64,
    first_activity: u64,
    closed_at: Option<u64>,
    initial_seq: [Option<u32>; 2],
    seen: u8,
    closed: u8,
    syn_only: bool,
    first_dir: usize,
    interactive: bool,
}
impl Session {
    pub fn duration(&self) -> f64 {
        self.last_stamp.saturating_sub(self.first_stamp) as f64 / 1_000_000.0
    }
    fn reuse(&self, p: &Packet, dir: usize) -> bool {
        if p.proto != 6 || p.flags & 2 == 0 {
            return false;
        }
        if p.flags & 16 != 0 && (dir != self.first_dir || self.seen == 3) {
            return false;
        }
        self.seen == 0
            || self.closed_at.is_some()
            || self.closed != 0
            || self.initial_seq[dir].is_some_and(|n| n != p.seq)
    }
    fn update(&mut self, p: &Packet, dir: usize, t: u64, stamp: u64, udp_timeout: u64) {
        if dir == 0 {
            self.sent += p.ip_bytes as u64;
        } else {
            self.received += p.ip_bytes as u64;
        }
        self.last_activity = t;
        if p.proto == 17 {
            self.last_stamp = self.last_stamp.max(stamp);
            self.deadline = t + udp_timeout;
            return;
        }
        // Like Zeek, the ACK after BOTH endpoints closed contributes bytes, but
        // no longer advances duration. Retransmissions before close DO advance it.
        if self.closed != 3 {
            self.last_stamp = self.last_stamp.max(stamp);
        }
        self.seen |= 1 << dir;
        if self.initial_seq[dir].is_none() {
            self.initial_seq[dir] = Some(if p.flags & 2 != 0 {
                p.seq
            } else {
                p.seq.wrapping_sub(1)
            });
        }
        if p.flags & 16 != 0 && self.initial_seq[1 - dir].is_none() {
            self.initial_seq[1 - dir] = Some(p.ack.wrapping_sub(1));
        }
        if p.flags & 2 == 0 || self.seen == 3 {
            self.syn_only = false;
        }
        if p.flags & 5 != 0 {
            self.closed |= 1 << dir;
        }
        if self.closed_at.is_none()
            && (p.flags & 4 != 0 || self.closed == 3 || (p.flags & 1 != 0 && self.seen != 3))
        {
            self.closed_at = Some(t);
        }
        self.deadline = if let Some(t) = self.closed_at {
            t + 5_000_000
        } else if self.syn_only {
            self.first_activity + 5_000_000
        } else {
            t + if self.interactive {
                3_600_000_000
            } else {
                300_000_000
            }
        };
    }
}
#[derive(Default, Debug)]
pub struct Stats {
    pub packets: u64,
    pub accepted: u64,
    pub filtered: u64,
    pub emitted: u64,
    pub reused: u64,
    pub session_limit: u64,
    pub peak_sessions: usize,
}
pub struct Engine {
    pub sessions: HashMap<Key, Session>,
    timers: BTreeSet<(u64, Key)>,
    pub stats: Stats,
    rules: Rules,
    max_sessions: usize,
    udp_timeout: u64,
}
impl Engine {
    pub fn new(rules: Rules, max_sessions: usize, udp_timeout: u64) -> Self {
        Self {
            sessions: HashMap::new(),
            timers: BTreeSet::new(),
            stats: Stats::default(),
            rules,
            max_sessions,
            udp_timeout,
        }
    }
    pub fn timer_count(&self) -> usize {
        self.timers.len()
    }
    pub fn process(
        &mut self,
        p: Packet,
        t: u64,
        stamp: u64,
        emit: &mut impl FnMut(&Session) -> Result<()>,
    ) -> Result<()> {
        self.expire(t, emit)?;
        self.stats.packets += 1;
        let a = self.rules.matches(p.src, p.sport, p.proto);
        let b = self.rules.matches(p.dst, p.dport, p.proto);
        if a == b {
            self.stats.filtered += 1;
            return Ok(());
        }
        let (key, dir) = if a {
            (
                Key {
                    server: p.src,
                    remote: p.dst,
                    server_port: p.sport,
                    remote_port: p.dport,
                    proto: p.proto,
                },
                0,
            )
        } else {
            (
                Key {
                    server: p.dst,
                    remote: p.src,
                    server_port: p.dport,
                    remote_port: p.sport,
                    proto: p.proto,
                },
                1,
            )
        };
        if self.sessions.get(&key).is_some_and(|s| s.reuse(&p, dir)) {
            let s = self.sessions.remove(&key).unwrap();
            self.timers.remove(&(s.deadline, key));
            emit(&s)?;
            self.stats.emitted += 1;
            self.stats.reused += 1;
        }
        if !self.sessions.contains_key(&key) {
            if self.sessions.len() >= self.max_sessions {
                self.stats.session_limit += 1;
                return Err("MAX_SESSIONS reached: refusing partial/evicted business records; exiting without draining retained state".into());
            }
            let interactive = [21, 22, 23, 513].contains(&p.dport);
            self.sessions.insert(
                key,
                Session {
                    key,
                    sent: 0,
                    received: 0,
                    first_stamp: stamp,
                    last_stamp: stamp,
                    deadline: t + if p.proto == 17 {
                        self.udp_timeout
                    } else {
                        300_000_000
                    },
                    last_activity: t,
                    first_activity: t,
                    closed_at: None,
                    initial_seq: [None; 2],
                    seen: 0,
                    closed: 0,
                    syn_only: p.checksum_valid && p.flags & 2 != 0,
                    first_dir: dir,
                    interactive,
                },
            );
        }
        let s = self.sessions.get_mut(&key).unwrap();
        self.timers.remove(&(s.deadline, key));
        if p.checksum_valid {
            s.update(&p, dir, t, stamp, self.udp_timeout);
        }
        self.timers.insert((s.deadline, key));
        self.stats.accepted += 1;
        self.stats.peak_sessions = self.stats.peak_sessions.max(self.sessions.len());
        Ok(())
    }
    pub fn expire(&mut self, t: u64, emit: &mut impl FnMut(&Session) -> Result<()>) -> Result<()> {
        while let Some(&(deadline, key)) = self.timers.first() {
            if deadline > t {
                break;
            }
            self.timers.pop_first();
            let s = self.sessions.remove(&key).unwrap();
            emit(&s)?;
            self.stats.emitted += 1;
        }
        Ok(())
    }
    pub fn compact(&mut self) {
        if self.sessions.capacity() > 1024 && self.sessions.len() < self.sessions.capacity() / 4 {
            self.sessions.shrink_to_fit();
        }
    }
    pub fn drain(&mut self, emit: &mut impl FnMut(&Session) -> Result<()>) -> Result<()> {
        for (_, s) in self.sessions.drain() {
            emit(&s)?;
            self.stats.emitted += 1;
        }
        self.timers.clear();
        self.sessions.shrink_to_fit();
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};
    fn engine(max: usize) -> Engine {
        let r = Rules::parse(
            &BTreeMap::from([
                ("LISTEN_1".into(), "tcp 10.0.0.1 443".into()),
                ("LISTEN_8".into(), "udp 10.0.0.1 53".into()),
            ]),
            HashSet::new(),
        )
        .unwrap();
        Engine::new(r, max, 60_000_000)
    }
    fn packet(proto: u8) -> Packet {
        Packet {
            checksum_valid: true,
            src: "10.0.0.2".parse().unwrap(),
            dst: "10.0.0.1".parse().unwrap(),
            sport: 443,
            dport: if proto == 6 { 443 } else { 53 },
            proto,
            ip_bytes: 40,
            seq: 100,
            ack: 0,
            flags: 2,
            payload_len: 0,
        }
    }
    #[test]
    fn direction_and_counter() {
        let mut e = engine(8);
        let mut p = packet(17);
        let mut out = vec![];
        let mut emit = |s: &Session| {
            out.push(s.clone());
            Ok(())
        };
        e.process(p, 0, 0, &mut emit).unwrap();
        std::mem::swap(&mut p.src, &mut p.dst);
        std::mem::swap(&mut p.sport, &mut p.dport);
        e.process(p, 1, 1, &mut emit).unwrap();
        e.drain(&mut emit).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!((out[0].sent, out[0].received), (40, 40));
    }
    #[test]
    fn one_fin_not_removed_tail_ack_counted() {
        let mut e = engine(8);
        let mut p = packet(6);
        let mut out = vec![];
        let mut emit = |s: &Session| {
            out.push(s.clone());
            Ok(())
        };
        e.process(p, 0, 0, &mut emit).unwrap();
        std::mem::swap(&mut p.src, &mut p.dst);
        p.flags = 18;
        e.process(p, 1, 100_000, &mut emit).unwrap();
        p.flags = 17;
        e.process(p, 2, 200_000, &mut emit).unwrap();
        assert_eq!(e.sessions.len(), 1);
        std::mem::swap(&mut p.src, &mut p.dst);
        e.process(p, 3, 300_000, &mut emit).unwrap();
        p.flags = 16;
        e.process(p, 4, 400_000, &mut emit).unwrap();
        e.drain(&mut emit).unwrap();
        assert_eq!(out[0].duration(), 0.3);
        assert_eq!(out[0].sent + out[0].received, 200);
    }
    #[test]
    fn timeout_index_bounded_and_udp_idle() {
        let mut e = engine(1);
        let p = packet(17);
        let mut count = 0;
        let mut emit = |_: &Session| {
            count += 1;
            Ok(())
        };
        for t in 0..10000 {
            e.process(p, t, t, &mut emit).unwrap();
        }
        assert_eq!(e.timer_count(), 1);
        e.expire(60_009_998, &mut emit).unwrap();
        assert_eq!(e.sessions.len(), 1);
        e.expire(60_009_999, &mut emit).unwrap();
        assert_eq!(e.sessions.len(), 0);
        assert_eq!(count, 1);
    }
    #[test]
    fn excluded_flows_no_state_and_limit_no_eviction() {
        let mut e = engine(1);
        let mut p = packet(17);
        let mut emit = |_: &Session| Ok(());
        p.dport = 999;
        for n in 0..10000 {
            p.sport = n;
            e.process(p, 0, 0, &mut emit).unwrap();
        }
        assert!(e.sessions.is_empty());
        p.dport = 53;
        e.process(p, 0, 0, &mut emit).unwrap();
        p.sport = 30000;
        assert!(e.process(p, 0, 0, &mut emit).is_err());
        assert_eq!(e.sessions.len(), 1);
        assert_eq!(e.stats.emitted, 0);
    }
    #[test]
    fn syn_retransmit_and_reuse() {
        let mut e = engine(8);
        let mut p = packet(6);
        let mut out = vec![];
        let mut emit = |s: &Session| {
            out.push(s.clone());
            Ok(())
        };
        e.process(p, 0, 0, &mut emit).unwrap();
        e.process(p, 1, 1, &mut emit).unwrap();
        p.seq = 200;
        e.process(p, 2, 2, &mut emit).unwrap();
        assert_eq!(e.sessions.len(), 1);
        e.drain(&mut emit).unwrap();
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].received, 80);
    }
    #[test]
    fn incomplete_handshake_fixed_timeout() {
        let mut e = engine(8);
        let p = packet(6);
        let mut out = vec![];
        let mut emit = |s: &Session| {
            out.push(s.clone());
            Ok(())
        };
        e.process(p, 0, 0, &mut emit).unwrap();
        e.process(p, 4_000_000, 4_000_000, &mut emit).unwrap();
        e.expire(5_000_000, &mut emit).unwrap();
        assert!(e.sessions.is_empty());
        assert_eq!(out[0].duration(), 4.0);
    }
    #[test]
    fn rst_lingers_and_drain_errors_propagate() {
        let mut e = engine(8);
        let mut p = packet(6);
        p.flags = 4;
        e.process(p, 0, 0, &mut |_| Ok(())).unwrap();
        assert_eq!(e.sessions.len(), 1);
        assert!(e.drain(&mut |_| Err("output failed".into())).is_err());
    }
}
#[cfg(test)]
mod more_tests {
    use super::*;
    use std::collections::{BTreeMap, HashSet};
    #[test]
    fn both_endpoints_and_neither_excluded() {
        let rules = Rules::parse(
            &BTreeMap::from([
                ("LISTEN_1".into(), "tcp 127.0.0.1 80".into()),
                ("LISTEN_2".into(), "tcp 127.0.0.2 80".into()),
            ]),
            HashSet::new(),
        )
        .unwrap();
        let mut e = Engine::new(rules, 2, 60_000_000);
        let mut p = Packet {
            checksum_valid: true,
            src: "127.0.0.1".parse().unwrap(),
            dst: "127.0.0.2".parse().unwrap(),
            sport: 80,
            dport: 80,
            proto: 6,
            ip_bytes: 40,
            seq: 1,
            ack: 0,
            flags: 2,
            payload_len: 0,
        };
        e.process(p, 0, 0, &mut |_| panic!("excluded output"))
            .unwrap();
        p.sport = 90;
        p.dport = 90;
        e.process(p, 0, 0, &mut |_| panic!("excluded output"))
            .unwrap();
        assert!(e.sessions.is_empty());
        assert_eq!(e.stats.filtered, 2);
    }
    #[test]
    fn state_layout_is_fixed() {
        assert!(std::mem::size_of::<Key>() <= 40);
        assert!(std::mem::size_of::<Session>() <= 192);
    }
}
