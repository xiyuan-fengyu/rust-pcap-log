use super::*;
use std::{
    fs::{self, FileTimes},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    sync::atomic::AtomicUsize,
    time::{Duration, UNIX_EPOCH},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let p = std::env::temp_dir().join(format!(
            "rpl-rotation-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn log(&self) -> PathBuf {
        self.0.join("access.log")
    }
    fn read(&self, name: &str) -> String {
        fs::read_to_string(self.0.join(name)).unwrap()
    }
    fn sink(&self, suffix: &str, now: libc::time_t) -> Sink {
        Sink::open_at(self.log().to_str().unwrap(), suffix, now).unwrap()
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
// Use local noon/midnight without mutating the process-global timezone in parallel tests.
fn stamp(year: i32, month: i32, day: i32, hour: i32, minute: i32, second: i32) -> libc::time_t {
    unsafe {
        let mut tm: libc::tm = std::mem::zeroed();
        tm.tm_year = year - 1900;
        tm.tm_mon = month - 1;
        tm.tm_mday = day;
        tm.tm_hour = hour;
        tm.tm_min = minute;
        tm.tm_sec = second;
        tm.tm_isdst = -1;
        let value = libc::mktime(&mut tm);
        assert_ne!(value, -1);
        value
    }
}
fn set_mtime(path: &Path, stamp: libc::time_t) {
    File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_times(FileTimes::new().set_modified(UNIX_EPOCH + Duration::from_secs(stamp as u64)))
        .unwrap();
}

#[test]
fn midnight_rotates_idle_file_once_and_creates_a_new_inode() {
    let d = TestDir::new();
    let before = stamp(2026, 10, 25, 23, 59, 59);
    let after = stamp(2026, 10, 26, 0, 0, 0);
    let mut sink = d.sink(rotation::DEFAULT_SUFFIX, before);
    sink.file.write_all(b"old\n").unwrap();
    let inode = sink.file.metadata().unwrap().ino();
    sink.rotate_at(before).unwrap();
    assert!(!d.0.join("access.log.20261025").exists());
    // No write/packet is required to rotate the file.
    sink.rotate_at(after).unwrap();
    assert_ne!(inode, sink.file.metadata().unwrap().ino());
    assert_eq!(d.read("access.log"), "");
    sink.file.write_all(b"new\n").unwrap();
    sink.rotate_at(after + 60).unwrap();
    assert_eq!(d.read("access.log.20261025"), "old\n");
    assert_eq!(d.read("access.log"), "new\n");
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 2);
}

#[test]
fn custom_suffix_collisions_and_backwards_clock_preserve_records() {
    let d = TestDir::new();
    let day = stamp(2026, 12, 31, 12, 0, 0);
    let mut sink = d.sink(".%Y-%m-%d.bak", day);
    fs::write(d.0.join("access.log.2026-12-31.bak"), "existing").unwrap();
    fs::write(d.0.join("access.log.2026-12-31.bak.1"), "existing1").unwrap();
    sink.file.write_all(b"last year").unwrap();
    sink.rotate_at(stamp(2027, 1, 1, 0, 0, 0)).unwrap();
    sink.rotate_at(day).unwrap();
    assert_eq!(d.read("access.log.2026-12-31.bak"), "existing");
    assert_eq!(d.read("access.log.2026-12-31.bak.1"), "existing1");
    assert_eq!(d.read("access.log.2026-12-31.bak.2"), "last year");
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 4);
}

#[test]
fn restart_archives_nonempty_old_file_by_mtime_but_appends_same_day() {
    let d = TestDir::new();
    let day = stamp(2026, 10, 25, 12, 0, 0);
    fs::write(d.log(), "previous run\n").unwrap();
    set_mtime(&d.log(), day);
    {
        let mut sink = d.sink(rotation::DEFAULT_SUFFIX, day);
        sink.file.write_all(b"same day\n").unwrap();
    }
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    set_mtime(&d.log(), day);
    let _sink = d.sink(rotation::DEFAULT_SUFFIX, stamp(2026, 10, 28, 12, 0, 0));
    assert_eq!(d.read("access.log.20261025"), "previous run\nsame day\n");
    assert_eq!(d.read("access.log"), "");
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 2);
}

#[test]
fn empty_old_file_starts_today_and_leap_day_uses_calendar_date() {
    let d = TestDir::new();
    fs::write(d.log(), "").unwrap();
    set_mtime(&d.log(), stamp(2024, 2, 28, 12, 0, 0));
    let mut sink = d.sink(rotation::DEFAULT_SUFFIX, stamp(2024, 2, 29, 23, 59, 59));
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 1);
    sink.rotate_at(stamp(2024, 3, 1, 0, 0, 0)).unwrap();
    assert_eq!(d.read("access.log.20240229"), "");
}

#[test]
fn stream_aliases_and_character_devices_skip_rotation() {
    for path in [
        "-",
        "stdout",
        "/dev/stdout",
        "/dev/fd/1",
        "/proc/self/fd/1",
        "stderr",
        "/dev/stderr",
        "/dev/fd/2",
        "/proc/self/fd/2",
        "/dev/null",
    ] {
        let mut sink = Sink::new(path).unwrap();
        assert!(sink.rotation.is_none(), "{path}");
        sink.rotate_at(stamp(2099, 1, 1, 0, 0, 0)).unwrap();
        sink.reopen().unwrap();
        assert!(sink.rotation.is_none(), "{path}");
    }
}

#[test]
fn rotation_keeps_symlink_and_archives_target() {
    let d = TestDir::new();
    let target = d.0.join("real.log");
    fs::write(&target, "").unwrap();
    std::os::unix::fs::symlink(&target, d.log()).unwrap();
    let mut sink = d.sink(rotation::DEFAULT_SUFFIX, stamp(2026, 10, 25, 12, 0, 0));
    sink.file.write_all(b"target").unwrap();
    sink.rotate_at(stamp(2026, 10, 26, 0, 0, 0)).unwrap();
    assert!(d.log().is_symlink());
    assert_eq!(d.read("real.log.20261025"), "target");
    assert_eq!(d.read("access.log"), "");
}

#[test]
fn externally_replaced_log_is_not_archived_as_our_file() {
    let d = TestDir::new();
    let mut sink = d.sink(rotation::DEFAULT_SUFFIX, stamp(2026, 10, 25, 12, 0, 0));
    sink.file.write_all(b"ours").unwrap();
    fs::rename(d.log(), d.0.join("external")).unwrap();
    fs::write(d.log(), "someone else").unwrap();
    assert!(
        sink.rotate_at(stamp(2026, 10, 26, 0, 0, 0))
            .unwrap_err()
            .to_string()
            .contains("SIGHUP")
    );
    assert_eq!(d.read("external"), "ours");
    assert_eq!(d.read("access.log"), "someone else");
    assert_eq!(fs::read_dir(&d.0).unwrap().count(), 2);
}
