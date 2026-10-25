use crate::{Result, engine::Session};
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::{
        fd::{AsRawFd, FromRawFd, IntoRawFd},
        unix::fs::OpenOptionsExt,
    },
    path::Path,
    sync::atomic::{AtomicBool, AtomicU32, Ordering},
};
pub static STOP: AtomicBool = AtomicBool::new(false);
pub static REOPEN: AtomicBool = AtomicBool::new(false);
static TIMEOUT: AtomicU32 = AtomicU32::new(15);
const NAMES: [&str; 9] = [
    "remote_addr",
    "remote_port",
    "time_iso8601",
    "protocol",
    "bytes_sent",
    "bytes_received",
    "session_time",
    "server_addr",
    "server_port",
];
#[derive(Debug)]
enum Token {
    Text(String),
    Field(usize),
}
#[derive(Debug)]
pub struct Template {
    tokens: Vec<Token>,
}
impl Template {
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty() || s.len() > 65536 || s.chars().any(|c| c < ' ' && c != '\t') {
            return Err("LOG_FORMAT: nonempty single line <=65536 bytes required".into());
        }
        let b = s.as_bytes();
        let mut tokens = vec![];
        let mut text = String::new();
        let mut pos = 0;
        while pos < b.len() {
            if b[pos] != b'$' {
                let ch = s[pos..].chars().next().unwrap();
                text.push(ch);
                pos += ch.len_utf8();
                continue;
            }
            pos += 1;
            if b.get(pos) == Some(&b'$') {
                text.push('$');
                pos += 1;
                continue;
            }
            if !text.is_empty() {
                tokens.push(Token::Text(std::mem::take(&mut text)));
            }
            let braces = b.get(pos) == Some(&b'{');
            if braces {
                pos += 1;
            }
            let start = pos;
            if !b
                .get(pos)
                .is_some_and(|c| c.is_ascii_alphabetic() || *c == b'_')
            {
                return Err("LOG_FORMAT: invalid $ syntax".into());
            }
            while b
                .get(pos)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                pos += 1;
            }
            let name = &s[start..pos];
            let field = NAMES
                .iter()
                .position(|n| *n == name)
                .ok_or_else(|| format!("LOG_FORMAT: unknown variable {name}"))?;
            if braces {
                if b.get(pos) != Some(&b'}') {
                    return Err("LOG_FORMAT: missing }".into());
                }
                pos += 1;
            }
            tokens.push(Token::Field(field));
        }
        if !text.is_empty() {
            tokens.push(Token::Text(text));
        }
        Ok(Self { tokens })
    }
    pub fn render(&self, s: &Session, wall: &str) -> String {
        let values = [
            s.key.remote.to_string(),
            s.key.remote_port.to_string(),
            wall.into(),
            if s.key.proto == 6 {
                "TCP".into()
            } else {
                "UDP".into()
            },
            s.sent.to_string(),
            s.received.to_string(),
            format!("{:.3}", s.duration()),
            s.key.server.to_string(),
            s.key.server_port.to_string(),
        ];
        let mut out = String::new();
        for t in &self.tokens {
            match t {
                Token::Text(v) => out.push_str(v),
                Token::Field(i) => out.push_str(&values[*i]),
            }
        }
        out.push('\n');
        out
    }
}
unsafe extern "C" {
    fn tzset();
}
pub fn init_timezone(tz: &str) {
    // SAFETY: called before capture, no threads exist or will be created.
    unsafe {
        std::env::set_var("TZ", tz);
        tzset();
    }
}
pub fn wall_time() -> Result<String> {
    // SAFETY: valid time_t, tm and bounded output buffers. localtime_r owns none.
    unsafe {
        let mut now = 0;
        libc::time(&mut now);
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&now, &mut tm).is_null() {
            return Err("localtime_r failed".into());
        }
        let mut b = [0i8; 64];
        let n = libc::strftime(
            b.as_mut_ptr(),
            b.len(),
            c"%Y-%m-%dT%H:%M:%S%z".as_ptr(),
            &tm,
        );
        if n < 5 {
            return Err("strftime failed".into());
        }
        let mut s = std::ffi::CStr::from_ptr(b.as_ptr()).to_str()?.to_owned();
        s.insert(s.len() - 2, ':');
        Ok(s)
    }
}
extern "C" fn stop(_: libc::c_int) {
    if !STOP.swap(true, Ordering::SeqCst) {
        unsafe {
            libc::alarm(TIMEOUT.load(Ordering::Relaxed));
        }
    }
}
extern "C" fn reopen(_: libc::c_int) {
    REOPEN.store(true, Ordering::SeqCst);
}
extern "C" fn deadline(_: libc::c_int) {
    let text = b"[rust-pcap-log] fatal: output/shutdown deadline exceeded; records may be lost\n";
    // Async-signal-safe hard deadline, including blocked regular-file writes.
    unsafe {
        let flags = libc::fcntl(2, libc::F_GETFL);
        if flags >= 0 {
            libc::fcntl(2, libc::F_SETFL, flags | libc::O_NONBLOCK);
        }
        libc::write(2, text.as_ptr().cast(), text.len());
        libc::_exit(1);
    }
}
pub fn install_signals(timeout: u32) -> Result<()> {
    TIMEOUT.store(timeout, Ordering::Relaxed);
    unsafe {
        for (sig, handler) in [
            (libc::SIGTERM, stop as *const () as libc::sighandler_t),
            (libc::SIGINT, stop as *const () as libc::sighandler_t),
            (libc::SIGHUP, reopen as *const () as libc::sighandler_t),
            (libc::SIGALRM, deadline as *const () as libc::sighandler_t),
            (libc::SIGPIPE, libc::SIG_IGN),
        ] {
            let mut a: libc::sigaction = std::mem::zeroed();
            a.sa_sigaction = handler;
            libc::sigemptyset(&mut a.sa_mask);
            if libc::sigaction(sig, &a, std::ptr::null_mut()) != 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
    }
    Ok(())
}
fn output_alarm(seconds: u32) {
    // Prevent a TERM between checking STOP and canceling the output alarm from
    // accidentally canceling the shutdown watchdog. Single-threaded runtime.
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        let mut old = std::mem::zeroed();
        libc::sigemptyset(&mut mask);
        libc::sigaddset(&mut mask, libc::SIGTERM);
        libc::sigaddset(&mut mask, libc::SIGINT);
        libc::sigprocmask(libc::SIG_BLOCK, &mask, &mut old);
        if !STOP.load(Ordering::SeqCst) {
            libc::alarm(seconds);
        }
        libc::sigprocmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
}
pub struct Sink {
    file: File,
    path: String,
    stdout: bool,
}
impl Sink {
    pub fn new(path: &str) -> Result<Self> {
        let stdout = matches!(path, "-" | "/dev/stdout" | "stdout");
        let file = if stdout {
            // Own a duplicate, never close process stdout itself.
            let fd = unsafe { libc::dup(1) };
            if fd < 0 {
                return Err(io::Error::last_os_error().into());
            }
            unsafe { File::from_raw_fd(fd) }
        } else {
            Self::open(path)?
        };
        let fd = file.as_raw_fd();
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error().into());
            }
        }
        Ok(Self {
            file,
            path: path.into(),
            stdout,
        })
    }
    fn open(path: &str) -> Result<File> {
        if let Some(parent) = Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o640)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)?;
        if !f.metadata()?.is_file() {
            return Err("LOG_FILE must be regular file or stdout".into());
        }
        Ok(f)
    }
    pub fn finish(self) -> Result<()> {
        // Check close errors too. This is NOT an fsync durability guarantee.
        let fd = self.file.into_raw_fd();
        if unsafe { libc::close(fd) } != 0 {
            return Err(format!("log close failed: {}", io::Error::last_os_error()).into());
        }
        Ok(())
    }
    pub fn reopen(&mut self) -> Result<()> {
        if !self.stdout {
            self.file = Self::open(&self.path)?;
        }
        Ok(())
    }
    pub fn write(&mut self, mut bytes: &[u8]) -> Result<()> {
        // No queue: backpressure capture, hard-fail after timeout, never silently
        // drop a record. alarm also bounds kernel-blocked regular file IO.
        output_alarm(TIMEOUT.load(Ordering::Relaxed));
        while !bytes.is_empty() {
            match self.file.write(bytes) {
                Ok(0) => return Err("log write returned zero".into()),
                Ok(n) => bytes = &bytes[n..],
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    let mut p = libc::pollfd {
                        fd: self.file.as_raw_fd(),
                        events: libc::POLLOUT,
                        revents: 0,
                    };
                    unsafe {
                        libc::poll(&mut p, 1, 100);
                    }
                }
                Err(e) => return Err(format!("log write failed: {e}").into()),
            }
        }
        output_alarm(0);
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn templates() {
        assert!(Template::parse("$$ ${protocol} $remote_addr\t汉字").is_ok());
        for s in [
            "",
            "$",
            "${foo}",
            "$HOME",
            "$(whoami)",
            "x\ny",
            "${protocol",
        ] {
            assert!(Template::parse(s).is_err(), "{s}");
        }
    }
    #[test]
    fn append_and_rotation() {
        let dir = std::env::temp_dir().join(format!("rust-pcap-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("log");
        std::fs::write(&p, "old\n").unwrap();
        let mut sink = Sink::new(p.to_str().unwrap()).unwrap();
        sink.write(b"first\n").unwrap();
        std::fs::rename(&p, dir.join("old")).unwrap();
        sink.reopen().unwrap();
        sink.write(b"new\n").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("old")).unwrap(),
            "old\nfirst\n"
        );
        assert_eq!(std::fs::read_to_string(p).unwrap(), "new\n");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
#[cfg(test)]mod render_tests {
    use super::*;use crate::{config::Rules,engine::Engine,packet::Packet};use std::collections::{BTreeMap,HashSet};
    #[test]fn render_all_fields_and_no_recursive_expansion(){
        let rules=Rules::parse(&BTreeMap::from([("LISTEN_1".into(),"udp 127.0.0.1 53".into())]),HashSet::new()).unwrap();let mut e=Engine::new(rules,1,60_000_000);
        let p=Packet{checksum_valid:true,src:"127.0.0.2".parse().unwrap(),dst:"127.0.0.1".parse().unwrap(),sport:1234,dport:53,proto:17,ip_bytes:32,seq:0,ack:0,flags:0,payload_len:4};
        e.process(p,0,0,&mut |_|Ok(())).unwrap();e.process(p,100_000,100_000,&mut |_|Ok(())).unwrap();
        let template=Template::parse("${protocol}suffix $$remote_addr $remote_addr:$remote_port $server_addr:$server_port $bytes_received/$bytes_sent $session_time $time_iso8601").unwrap();
        let mut lines=vec![];e.drain(&mut |s|{lines.push(template.render(s,"wall"));Ok(())}).unwrap();
        assert_eq!(lines,["UDPsuffix $remote_addr 127.0.0.2:1234 127.0.0.1:53 64/0 0.100 wall\n"]);
    }
}
