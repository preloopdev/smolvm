//! Event-driven waits on the branchpoint state directory.
//!
//! Both sides of the branchpoint handshake communicate through marker files in
//! one directory. A wait here blocks in the kernel until that directory
//! changes, so neither side polls or spins; the caller always re-checks its
//! markers after a wake, which closes the check/sleep race. Where inotify is
//! unavailable the wait degrades to a short sleep and the same re-check loop
//! turns into ordinary polling.

use std::path::Path;
use std::time::Duration;

#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

/// A watch on one directory.
pub struct DirWatcher {
    #[cfg(target_os = "linux")]
    fd: OwnedFd,
}

/// The sleep a non-inotify wait uses between re-checks.
#[cfg(not(target_os = "linux"))]
const FALLBACK_INTERVAL: Duration = Duration::from_millis(5);

impl DirWatcher {
    /// Watch `dir` for files appearing, disappearing, or finishing a write.
    #[cfg(target_os = "linux")]
    pub fn new(dir: &Path) -> std::io::Result<Self> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "watched directory path contains NUL",
            )
        })?;
        let raw_fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC | libc::IN_NONBLOCK) };
        if raw_fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };
        let mask = libc::IN_CREATE
            | libc::IN_DELETE
            | libc::IN_MOVED_FROM
            | libc::IN_MOVED_TO
            | libc::IN_CLOSE_WRITE;
        if unsafe { libc::inotify_add_watch(fd.as_raw_fd(), path.as_ptr(), mask) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self { fd })
    }

    /// Watch `dir`; without inotify every wait is a short sleep.
    #[cfg(not(target_os = "linux"))]
    pub fn new(dir: &Path) -> std::io::Result<Self> {
        if !dir.is_dir() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{} is not a directory", dir.display()),
            ));
        }
        Ok(Self {})
    }

    /// Block until the directory changes or `timeout` elapses; `None` waits
    /// without a time limit. Either way the caller re-checks its markers
    /// next, so the two are not distinguished. An untimed wait holds no
    /// kernel timer, which is what lets a waiter sit inside a snapshot and
    /// wake correctly in every restored copy.
    #[cfg(target_os = "linux")]
    pub fn wait(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        let millis = match timeout {
            None => -1,
            Some(timeout) => timeout.as_millis().min(i32::MAX as u128) as i32,
        };
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            let ready = unsafe { libc::poll(&mut descriptor, 1, millis) };
            if ready > 0 {
                self.drain();
                return Ok(());
            }
            if ready == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    pub fn wait(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        std::thread::sleep(timeout.map_or(FALLBACK_INTERVAL, |t| t.min(FALLBACK_INTERVAL)));
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn drain(&self) {
        let mut events = [0_u8; 4096];
        loop {
            let read = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    events.as_mut_ptr().cast(),
                    events.len(),
                )
            };
            if read <= 0 {
                return;
            }
        }
    }
}

/// Re-check `done` after every change to `dir` until it holds or `timeout`
/// elapses. Returns whether it held. Without a watch this polls at a short
/// interval so the outcome is the same, only later.
pub fn wait_until(dir: &Path, timeout: Duration, mut done: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let watcher = DirWatcher::new(dir).ok();
    loop {
        if done() {
            return true;
        }
        let now = std::time::Instant::now();
        if now >= deadline {
            return false;
        }
        let remaining = deadline - now;
        match watcher.as_ref().map(|w| w.wait(Some(remaining))) {
            Some(Ok(_)) => {}
            Some(Err(_)) | None => std::thread::sleep(remaining.min(Duration::from_millis(5))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait_until_returns_when_the_condition_holds() {
        let temp = tempfile::tempdir().unwrap();
        let marker = temp.path().join("marker");
        let writer = {
            let marker = marker.clone();
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(40));
                std::fs::write(&marker, "x").unwrap();
            })
        };
        let started = std::time::Instant::now();
        assert!(wait_until(temp.path(), Duration::from_secs(5), || marker.exists()));
        assert!(started.elapsed() < Duration::from_secs(2));
        writer.join().unwrap();
    }

    #[test]
    fn wait_until_reports_a_timeout() {
        let temp = tempfile::tempdir().unwrap();
        let started = std::time::Instant::now();
        assert!(!wait_until(temp.path(), Duration::from_millis(60), || {
            false
        }));
        assert!(started.elapsed() >= Duration::from_millis(60));
    }
}
