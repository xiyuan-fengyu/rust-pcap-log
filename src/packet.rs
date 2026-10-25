//! No unfragmented payload retention. IP fragments are reconstructed in a separately
//! bounded cache, for L4 checksums and Zeek's reassembled-IP byte accounting.
use crate::config::Address;
use std::collections::HashMap;

#[derive(Clone, Copy, Debug)]
pub struct Packet {
    pub checksum_valid: bool,
    pub src: Address,
    pub dst: Address,
    pub sport: u16,
    pub dport: u16,
    pub proto: u8,
    pub ip_bytes: u32,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Issue {
    Truncated,
    Malformed,
    Checksum,
    Unsupported,
    FragmentLimit,
    FragmentConflict,
}
impl std::fmt::Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Issue {}
type Parsed<T> = std::result::Result<T, Issue>;
fn u16be(b: &[u8], p: usize) -> u16 {
    u16::from_be_bytes([b[p], b[p + 1]])
}
fn u32be(b: &[u8], p: usize) -> u32 {
    u32::from_be_bytes(b[p..p + 4].try_into().unwrap())
}
fn need(b: &[u8], n: usize) -> Parsed<()> {
    if b.len() < n {
        Err(Issue::Truncated)
    } else {
        Ok(())
    }
}
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in bytes.chunks(2) {
        sum += ((c[0] as u32) << 8) + u32::from(*c.get(1).unwrap_or(&0));
    }
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn l4_checksum(src: Address, dst: Address, proto: u8, v4: bool, data: &[u8]) -> bool {
    let mut sum = 0u32;
    let mut add = |bytes: &[u8]| {
        for c in bytes.chunks(2) {
            sum += ((c[0] as u32) << 8) + u32::from(*c.get(1).unwrap_or(&0));
        }
    };
    if v4 {
        add(&src.0[12..]);
        add(&dst.0[12..]);
    } else {
        add(&src.0);
        add(&dst.0);
    }
    add(data);
    sum += proto as u32 + data.len() as u32;
    while sum >> 16 != 0 {
        sum = (sum & 65535) + (sum >> 16);
    }
    sum == 65535
}
#[derive(Hash, Eq, PartialEq, Clone, Copy, Debug)]
struct FragKey {
    src: Address,
    dst: Address,
    id: u32,
    proto: u8,
    v4: bool,
}
const DATA: usize = 65536;
// Conservative per-slot reservation includes HashMap capacity/metadata slack.
const FRAG_COST: usize = DATA + DATA / 8 + 1024;
struct Fragment {
    data: Box<[u8]>,
    seen: Box<[u8]>,
    end: Option<usize>,
    filled: usize,
    highest: usize,
    header_len: usize,
    first: bool,
    created: u64,
    conflicts: u64,
}
impl Fragment {
    fn new(header_len: usize, t: u64) -> Self {
        Self {
            data: vec![0; DATA].into_boxed_slice(),
            seen: vec![0; DATA / 8].into_boxed_slice(),
            end: None,
            filled: 0,
            highest: 0,
            header_len,
            first: false,
            created: t,
            conflicts: 0,
        }
    }
    fn insert(
        &mut self,
        offset: usize,
        more: bool,
        data: &[u8],
        _header_len: usize,
    ) -> Parsed<bool> {
        let end = offset + data.len();
        if data.is_empty() || end > DATA || (more && !data.len().is_multiple_of(8)) {
            return Err(Issue::Malformed);
        }
        if offset == 0 {
            // Zeek retains the IP header length of the first OBSERVED fragment,
            // which need not be offset zero (non-copied IPv4 options matter).
            self.first = true;
        }
        if !more {
            if self.end.is_some_and(|n| n != end) || self.highest > end {
                return Err(Issue::FragmentConflict);
            }
            self.end = Some(end);
        }
        if self.end.is_some_and(|n| end > n) {
            return Err(Issue::FragmentConflict);
        }
        self.highest = self.highest.max(end);
        for (i, &v) in data.iter().enumerate() {
            let n = offset + i;
            let mask = 1 << (n % 8);
            if self.seen[n / 8] & mask != 0 {
                if self.data[n] != v {
                    self.conflicts += 1;
                }
            } else {
                self.seen[n / 8] |= mask;
                self.data[n] = v;
                self.filled += 1;
            }
        }
        Ok(self.first && self.end == Some(self.filled))
    }
}
pub struct Parser {
    fragments: HashMap<FragKey, Fragment>,
    max_fragments: usize,
    max_bytes: usize,
    next_expiry: u64,
    pub fragments_completed: u64,
    pub fragments_expired: u64,
    pub fragments_seen: u64,
    pub peak_fragments: usize,
    pub overlap_conflicts: u64,
    depth: u8,
    additional: Vec<Packet>,
    verify: bool,
}
impl Parser {
    pub fn new(verify: bool, max_fragments: usize, max_bytes: usize) -> Self {
        Self {
            fragments: HashMap::new(),
            max_fragments,
            max_bytes,
            next_expiry: u64::MAX,
            fragments_completed: 0,
            fragments_expired: 0,
            fragments_seen: 0,
            peak_fragments: 0,
            overlap_conflicts: 0,
            depth: 0,
            additional: Vec::new(),
            verify,
        }
    }
    pub fn fragment_count(&self) -> usize {
        self.fragments.len()
    }
    pub fn fragment_memory(&self) -> usize {
        self.fragments.len() * FRAG_COST
    }
    pub fn expire(&mut self, t: u64) {
        if t < self.next_expiry { return; }
        let n = self.fragments.len();
        self.fragments
            .retain(|_, v| t.saturating_sub(v.created) < 300_000_000);
        self.fragments_expired += (n - self.fragments.len()) as u64;
        self.next_expiry = self.fragments.values().map(|f| f.created + 300_000_000).min().unwrap_or(u64::MAX);
        if self.fragments.is_empty() {
            self.fragments.shrink_to_fit();
        }
    }
    pub fn take_additional(&mut self) -> impl Iterator<Item = Packet> + '_ {
        self.additional.drain(..)
    }
    pub fn parse(&mut self, link: i32, frame: &[u8], t: u64) -> Parsed<Option<Packet>> {
        self.expire(t);
        self.depth = 0;
        self.additional.clear();
        self.parse_link(link, frame, t)
    }
    fn parse_link(&mut self, link: i32, frame: &[u8], t: u64) -> Parsed<Option<Packet>> {
        let (mut proto, mut offset) = match link {
            1 => {
                need(frame, 14)?;
                (u16be(frame, 12), 14)
            }
            113 => {
                need(frame, 16)?;
                (u16be(frame, 14), 16)
            }
            276 => {
                need(frame, 20)?;
                (u16be(frame, 0), 20)
            }
            12 | 101 => {
                need(frame, 1)?;
                (if frame[0] >> 4 == 4 { 0x0800 } else { 0x86dd }, 0)
            }
            228 => (0x0800, 0),
            229 => (0x86dd, 0),
            _ => return Err(Issue::Unsupported),
        };
        let mut tags = 0;
        while matches!(proto, 0x8100 | 0x88a8 | 0x9100) {
            tags += 1;
            if tags > 8 {
                return Err(Issue::Unsupported);
            }
            need(frame, offset + 4)?;
            proto = u16be(frame, offset + 2);
            offset += 4;
        }
        match proto {
            0x0800 => self.ipv4(&frame[offset..], t),
            0x86dd => self.ipv6(&frame[offset..], t),
            0x0806 => Ok(None),
            0x8847 | 0x8848 | 0x8864 => Err(Issue::Unsupported),
            _ => Ok(None),
        }
    }
    fn ipv4(&mut self, b: &[u8], t: u64) -> Parsed<Option<Packet>> {
        need(b, 20)?;
        let hl = ((b[0] & 15) * 4) as usize;
        let len = u16be(b, 2) as usize;
        if b[0] >> 4 != 4 || hl < 20 || len < hl {
            return Err(Issue::Malformed);
        }
        need(b, len)?;
        if self.verify && checksum(&b[..hl]) != 0 {
            return Err(Issue::Checksum);
        }
        let src = Address::v4(b[12..16].try_into().unwrap());
        let dst = Address::v4(b[16..20].try_into().unwrap());
        let proto = b[9];
        let frag = u16be(b, 6);
        if frag & 0x8000 != 0 {
            return Err(Issue::Malformed);
        }
        if frag & 0x3fff != 0 {
            let key = FragKey {
                src,
                dst,
                id: u16be(b, 4) as u32,
                proto,
                v4: true,
            };
            return self.fragment(
                key,
                (frag as usize & 8191) * 8,
                frag & 0x2000 != 0,
                &b[hl..len],
                hl,
                t,
            );
        }
        self.dispatch(src, dst, proto, true, &b[hl..len], len, t)
    }
    fn ipv6(&mut self, b: &[u8], t: u64) -> Parsed<Option<Packet>> {
        need(b, 40)?;
        if b[0] >> 4 != 6 {
            return Err(Issue::Malformed);
        }
        let len = 40 + u16be(b, 4) as usize;
        if len == 40 {
            return if b[6] == 59 {
                Ok(None)
            } else {
                Err(Issue::Unsupported)
            };
        }
        need(b, len)?;
        let src = Address::v6(b[8..24].try_into().unwrap());
        let dst = Address::v6(b[24..40].try_into().unwrap());
        let (proto, offset) = extensions(&b[..len], b[6], 40)?;
        if proto == 44 {
            need(&b[..len], offset + 8)?;
            let fh = u16be(b, offset + 2);
            if fh & 6 != 0 {
                return Err(Issue::Malformed);
            }
            let key = FragKey {
                src,
                dst,
                id: u32be(b, offset + 4),
                proto: b[offset],
                v4: false,
            };
            // RFC atomic fragments still remove the fragment header, as Zeek does.
            return self.fragment(
                key,
                (fh & 0xfff8) as usize,
                fh & 1 != 0,
                &b[offset + 8..len],
                offset,
                t,
            );
        }
        self.dispatch(src, dst, proto, false, &b[offset..len], len, t)
    }
    fn fragment(
        &mut self,
        key: FragKey,
        offset: usize,
        more: bool,
        bytes: &[u8],
        hl: usize,
        t: u64,
    ) -> Parsed<Option<Packet>> {
        self.fragments_seen += 1;
        if !self.fragments.contains_key(&key) {
            if self.fragments.len() >= self.max_fragments
                || (self.fragments.len() + 1) * FRAG_COST > self.max_bytes
            {
                return Err(Issue::FragmentLimit);
            }
            self.fragments.insert(key, Fragment::new(hl, t));
            self.next_expiry = self.next_expiry.min(t + 300_000_000);
            self.peak_fragments = self.peak_fragments.max(self.fragments.len());
        }
        let f = self.fragments.get_mut(&key).unwrap();
        let before = f.conflicts;
        let complete = f.insert(offset, more, bytes, hl)?;
        self.overlap_conflicts += f.conflicts - before;
        if !complete {
            return Ok(None);
        }
        let f = self.fragments.remove(&key).unwrap();
        self.fragments_completed += 1;
        let end = f.end.unwrap();
        if end + f.header_len > if key.v4 { 65535 } else { 65575 } {
            return Err(Issue::Malformed);
        }
        let (proto, off) = if key.v4 {
            (key.proto, 0)
        } else {
            extensions(&f.data[..end], key.proto, 0)?
        };
        self.dispatch(
            key.src,
            key.dst,
            proto,
            key.v4,
            &f.data[off..end],
            f.header_len + end,
            t,
        )
    }
    fn descend(&mut self) -> Parsed<()> {
        self.depth += 1;
        if self.depth > 4 {
            Err(Issue::Unsupported)
        } else {
            Ok(())
        }
    }
    fn dispatch(
        &mut self,
        src: Address,
        dst: Address,
        proto: u8,
        v4: bool,
        b: &[u8],
        len: usize,
        t: u64,
    ) -> Parsed<Option<Packet>> {
        if proto == 4 || proto == 41 {
            self.descend()?;
            return if proto == 4 {
                self.ipv4(b, t)
            } else {
                self.ipv6(b, t)
            };
        }
        if proto == 47 {
            self.descend()?;
            need(b, 4)?;
            let flags = u16be(b, 0);
            if flags & !0xb000 != 0 {
                return Err(Issue::Unsupported);
            }
            let mut off = 4;
            if flags & 0x8000 != 0 {
                need(b, 8)?;
                if self.verify && checksum(b) != 0 {
                    return Err(Issue::Checksum);
                }
                off += 4;
            }
            if flags & 0x2000 != 0 {
                off += 4;
            }
            if flags & 0x1000 != 0 {
                off += 4;
            }
            need(b, off)?;
            return match u16be(b, 2) {
                0x0800 => self.ipv4(&b[off..], t),
                0x86dd => self.ipv6(&b[off..], t),
                0x6558 => self.parse_link(1, &b[off..], t),
                _ => Err(Issue::Unsupported),
            };
        }
        let p = transport(src, dst, proto, v4, b, len, self.verify)?;
        if let Some(p) = p {
            if p.proto == 17
                && [4789, 8472].iter().any(|n| *n == p.sport || *n == p.dport)
                && p.checksum_valid
            {
                self.descend()?;
                let udp_len = u16be(b, 4) as usize;
                let vx = &b[8..udp_len];
                need(vx, 8)?;
                if vx[0] != 8 || vx[1..4] != [0, 0, 0] || vx[7] != 0 {
                    return Err(Issue::Unsupported);
                }
                // One outer UDP record plus inner sessions, like bare Zeek. The
                // vector is explicitly bounded by the four-level depth limit.
                self.additional.push(p);
                return self.parse_link(1, &vx[8..], t);
            }
            if p.proto == 17
                && [6081, 2152, 3544]
                    .iter()
                    .any(|n| *n == p.sport || *n == p.dport)
            {
                return Err(Issue::Unsupported);
            }
        }
        Ok(p)
    }
}
fn extensions(b: &[u8], mut proto: u8, mut off: usize) -> Parsed<(u8, usize)> {
    for _ in 0..16 {
        if !matches!(proto, 0 | 43 | 60 | 51) {
            return Ok((proto, off));
        }
        need(b, off + 2)?;
        let len = if proto == 51 {
            (b[off + 1] as usize + 2) * 4
        } else {
            (b[off + 1] as usize + 1) * 8
        };
        need(b, off + len)?;
        // Active routing and home-address options change checksum pseudoheaders.
        // Do not guess endpoint identity or validate against the wrong address.
        if proto == 43 && b[off + 3] != 0 {
            return Err(Issue::Unsupported);
        }
        if proto == 60 || proto == 0 {
            let mut p = off + 2;
            while p < off + len {
                let kind = b[p];
                if kind == 0 {
                    p += 1;
                    continue;
                }
                if p + 2 > off + len {
                    return Err(Issue::Malformed);
                }
                let n = b[p + 1] as usize + 2;
                if p + n > off + len {
                    return Err(Issue::Malformed);
                }
                if kind == 0xc9 || kind == 0xc2 {
                    return Err(Issue::Unsupported);
                }
                p += n;
            }
        }
        proto = b[off];
        off += len;
    }
    if matches!(proto, 0 | 43 | 60 | 51) {
        Err(Issue::Unsupported)
    } else {
        Ok((proto, off))
    }
}
fn transport(
    src: Address,
    dst: Address,
    proto: u8,
    v4: bool,
    b: &[u8],
    ip_len: usize,
    verify: bool,
) -> Parsed<Option<Packet>> {
    let mut p = Packet {
        checksum_valid: true,
        src,
        dst,
        proto,
        sport: 0,
        dport: 0,
        ip_bytes: ip_len as u32,
        seq: 0,
        ack: 0,
        flags: 0,
        payload_len: 0,
    };
    match proto {
        6 => {
            need(b, 20)?;
            let n = ((b[12] >> 4) * 4) as usize;
            if n < 20 || n > b.len() {
                return Err(Issue::Malformed);
            }
            if verify && !l4_checksum(src, dst, 6, v4, b) {
                p.checksum_valid = false;
            }
            p.seq = u32be(b, 4);
            p.ack = u32be(b, 8);
            p.flags = b[13];
            p.payload_len = (b.len() - n) as u32;
        }
        17 => {
            need(b, 8)?;
            let n = u16be(b, 4) as usize;
            if n < 8 || n > b.len() {
                return Err(Issue::Malformed);
            }
            let zero = u16be(b, 6) == 0;
            if verify && ((!v4 && zero) || (!zero && !l4_checksum(src, dst, 17, v4, &b[..n]))) {
                p.checksum_valid = false;
            }
            p.payload_len = (n - 8) as u32;
        }
        4 | 41 | 47 => return Err(Issue::Unsupported),
        1 | 2 | 58 | 59 | 50 => return Ok(None),
        _ => return Ok(None),
    }
    p.sport = u16be(b, 0);
    p.dport = u16be(b, 2);
    Ok(Some(p))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_vectors() {
        assert_eq!(checksum(&[0, 1, 0, 2, 255, 252]), 0);
        assert_eq!(checksum(&[1]), 0xfeff);
    }
    #[test]
    fn fragments_out_of_order_duplicates() {
        let mut f = Fragment::new(20, 0);
        assert!(!f.insert(8, false, &[3; 8], 20).unwrap());
        assert!(!f.insert(8, false, &[3; 8], 20).unwrap());
        assert!(f.insert(0, true, &[2; 8], 20).unwrap());
        assert_eq!(f.filled, 16);
    }
    #[test]
    fn conflicting_overlap() {
        let mut f = Fragment::new(20, 0);
        f.insert(0, true, &[2; 16], 20).unwrap();
        assert!(f.insert(8, false, &[3; 16], 20).unwrap());
        assert_eq!(f.conflicts, 8);
        assert_eq!(&f.data[8..16], &[2; 8]);
    }
    #[test]
    fn bounds_and_expiry() {
        let mut p = Parser::new(false, 1, FRAG_COST);
        let key = FragKey {
            src: Address::v4([1, 2, 3, 4]),
            dst: Address::v4([4, 3, 2, 1]),
            id: 1,
            proto: 17,
            v4: true,
        };
        p.fragment(key, 8, false, &[0; 8], 20, 0).unwrap();
        let mut other = key;
        other.id = 2;
        assert!(matches!(
            p.fragment(other, 8, false, &[0; 8], 20, 0),
            Err(Issue::FragmentLimit)
        ));
        p.expire(300_000_000);
        assert_eq!(p.fragment_count(), 0);
        assert_eq!(p.fragments_expired, 1);
    }
    #[test]
    fn all_short_prefixes_no_panic() {
        let mut p = Parser::new(true, 2, FRAG_COST * 2);
        for n in 0..100 {
            for link in [1, 113, 276, 101] {
                let b = vec![0xff; n];
                let _ = p.parse(link, &b, 0);
            }
        }
    }
}
#[cfg(test)]
mod fuzz_tests {
    use super::*;
    #[test]
    fn deterministic_malformed_smoke() {
        let mut seed = 0xabcdef0123456789u64;
        for n in 0..20000 {
            let len = n % 256;
            let mut b = vec![0; len];
            for x in &mut b {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *x = seed as u8;
            }
            if len > 14 && n % 3 == 0 {
                b[12..14].copy_from_slice(if n % 2 == 0 { &[8, 0] } else { &[0x86, 0xdd] });
            }
            let mut p = Parser::new(n % 2 == 0, 2, FRAG_COST * 2);
            let _ = p.parse([1, 113, 276, 101][n % 4], &b, 0);
        }
    }
}
