//! Daily wall-clock rotation for regular files only.
use crate::Result;
use std::{
    ffi::CString,
    fs::{File, Metadata},
    io,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

pub const DEFAULT_SUFFIX: &str = ".%Y%m%d";

pub fn validate_suffix(suffix: &str) -> Result<()> {
    if suffix.is_empty()
        || suffix.len() > 128
        || suffix
            .chars()
            .any(|c| c.is_control() || matches!(c, '/' | '\\'))
    {
        return Err("LOG_ROTATE_SUFFIX: expected a nonempty filename suffix <=128 bytes, without separators/control characters".into());
    }
    let mut chars = suffix.chars();
    while let Some(c) = chars.next() {
        if c == '%' && !chars.next().is_some_and(|c| "YymdjF%".contains(c)) {
            return Err("LOG_ROTATE_SUFFIX: supported directives are %Y %y %m %d %j %F %%".into());
        }
    }
    Ok(())
}

pub(crate) fn now() -> Result<libc::time_t> {
    // SAFETY: time accepts a null output pointer.
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    if now == -1 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(now)
}

fn local_date(stamp: libc::time_t) -> Result<libc::tm> {
    // SAFETY: localtime_r initializes the supplied tm; timezone is set once at startup.
    unsafe {
        let mut tm = std::mem::zeroed();
        if libc::localtime_r(&stamp, &mut tm).is_null() {
            return Err("log rotation: localtime_r failed".into());
        }
        Ok(tm)
    }
}

pub(crate) struct Rotation {
    path: PathBuf,
    suffix: CString,
    date: libc::tm,
    checked_at: Option<libc::time_t>,
}
impl Rotation {
    pub(crate) fn new(
        path: &str,
        suffix: &str,
        metadata: &Metadata,
        now: libc::time_t,
    ) -> Result<Self> {
        validate_suffix(suffix)?;
        Ok(Self {
            // Rotate the actual file, not its symlink. Stream aliases never reach here.
            path: std::fs::canonicalize(path)?,
            suffix: CString::new(suffix)?,
            date: local_date(if metadata.len() > 0 {
                metadata.mtime() as libc::time_t
            } else {
                now
            })?,
            checked_at: None,
        })
    }

    pub(crate) fn already_checked(&self, now: libc::time_t) -> bool {
        self.checked_at == Some(now)
    }

    pub(crate) fn archive_if_due(&mut self, file: &File, now: libc::time_t) -> Result<bool> {
        if self.checked_at == Some(now) {
            return Ok(false);
        }
        let today = local_date(now)?;
        // A backwards clock adjustment must not produce repeated/backwards archives.
        if (today.tm_year, today.tm_yday) <= (self.date.tm_year, self.date.tm_yday) {
            self.checked_at = Some(now);
            return Ok(false);
        }
        let disk = std::fs::metadata(&self.path)?;
        let opened = file.metadata()?;
        if disk.dev() != opened.dev() || disk.ino() != opened.ino() {
            return Err(
                "log rotation: LOG_FILE was replaced externally; reopen it with SIGHUP".into(),
            );
        }
        let mut buf = [0u8; 512];
        // SAFETY: valid format, initialized tm, bounded output buffer.
        let len = unsafe {
            libc::strftime(
                buf.as_mut_ptr().cast(),
                buf.len(),
                self.suffix.as_ptr(),
                &self.date,
            )
        };
        if len == 0 {
            return Err("LOG_ROTATE_SUFFIX: formatted suffix is empty or too long".into());
        }
        let mut name = self.path.as_os_str().to_os_string();
        name.push(std::str::from_utf8(&buf[..len])?);
        let base = PathBuf::from(name);
        for index in 0..10_000 {
            let archive = if index == 0 {
                base.clone()
            } else {
                let mut name = base.as_os_str().to_os_string();
                name.push(format!(".{index}"));
                PathBuf::from(name)
            };
            match rename_no_replace(&self.path, &archive) {
                Ok(()) => {
                    eprintln!(
                        "[rust-pcap-log] log rotated: {} -> {}",
                        self.path.display(),
                        archive.display()
                    );
                    self.date = today;
                    self.checked_at = Some(now);
                    return Ok(true);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(format!("log rotation failed: {e}").into()),
            }
        }
        Err("log rotation: archive collision limit reached (10000); no files overwritten".into())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

fn rename_no_replace(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStrExt;
        let from = CString::new(from.as_os_str().as_bytes())?;
        let to = CString::new(to.as_os_str().as_bytes())?;
        // SAFETY: valid NUL-terminated paths. RENAME_NOREPLACE never clobbers an archive.
        let result = unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                from.as_ptr(),
                libc::AT_FDCWD,
                to.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Same-directory regular files only; hard_link also refuses existing targets.
        std::fs::hard_link(from, to)?;
        std::fs::remove_file(from)
    }
}
