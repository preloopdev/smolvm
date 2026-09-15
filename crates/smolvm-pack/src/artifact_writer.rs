//! Bounded, aligned bulk writes; integrity covers logical bytes, not padding.
use std::fs::File;
use std::io::{self, Write};
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
use std::path::Path;

#[cfg(target_os = "linux")]
const ALIGN: usize = 4096;
#[cfg(any(target_os = "linux", test))]
const CAPACITY: usize = 1024 * 1024;

pub(crate) enum ArtifactWriter {
    Buffered(File),
    #[cfg(target_os = "linux")]
    Aligned(AlignedWriter),
}

#[cfg(target_os = "linux")]
pub(crate) struct AlignedWriter {
    file: File,
    buffer: Vec<u8>,
    start: usize,
    used: usize,
    written: u64,
    direct: bool,
}

impl ArtifactWriter {
    pub(crate) fn create(path: &Path, direct: bool) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        if direct {
            use std::os::unix::fs::OpenOptionsExt;
            match File::options()
                .write(true)
                .truncate(true)
                .create(true)
                .custom_flags(libc::O_DIRECT)
                .open(path)
            {
                Ok(file) => {
                    let buffer = vec![0_u8; CAPACITY + ALIGN];
                    let start = buffer.as_ptr().align_offset(ALIGN);
                    return Ok(Self::Aligned(AlignedWriter {
                        file,
                        buffer,
                        start,
                        used: 0,
                        written: 0,
                        direct: true,
                    }));
                }
                Err(error) if unsupported(&error) => {}
                Err(error) => return Err(error),
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = direct;
        Ok(Self::Buffered(File::create(path)?))
    }

    pub(crate) fn finish(self) -> io::Result<File> {
        match self {
            Self::Buffered(file) => Ok(file),
            #[cfg(target_os = "linux")]
            Self::Aligned(mut writer) => {
                writer.flush()?;
                writer.file.set_len(writer.written + writer.used as u64)?;
                Ok(writer.file)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn unsupported(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

impl Write for ArtifactWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match self {
            Self::Buffered(file) => file.write(bytes),
            #[cfg(target_os = "linux")]
            Self::Aligned(writer) => writer.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Buffered(file) => file.flush(),
            #[cfg(target_os = "linux")]
            Self::Aligned(writer) => writer.flush(),
        }
    }
}

#[cfg(target_os = "linux")]
impl Write for AlignedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.used == CAPACITY {
            self.flush()?;
            self.written += self.used as u64;
            self.used = 0;
        }
        let n = bytes.len().min(CAPACITY - self.used);
        let start = self.start + self.used;
        self.buffer[start..start + n].copy_from_slice(&bytes[..n]);
        self.used += n;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.used == 0 {
            return Ok(());
        }
        let padded = self.used.div_ceil(ALIGN) * ALIGN;
        self.buffer[self.start + self.used..self.start + padded].fill(0);
        // A partial flush writes an aligned tail but retains it. Later writes
        // overwrite that same tail; finish truncates padding before publication.
        self.file.seek(SeekFrom::Start(self.written))?;
        let bytes = &self.buffer[self.start..self.start + padded];
        match self.file.write(bytes) {
            Ok(n) if n == padded => Ok(()),
            Ok(_) => Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "short aligned artifact write",
            )),
            Err(error) => {
                #[cfg(target_os = "linux")]
                if self.direct && self.written == 0 && unsupported(&error) {
                    use std::os::fd::AsRawFd;
                    // Some filesystems accept O_DIRECT on open but reject the
                    // first aligned write. No successful bytes are discarded.
                    let fd = self.file.as_raw_fd();
                    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                    if flags < 0
                        || unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_DIRECT) } < 0
                    {
                        return Err(io::Error::last_os_error());
                    }
                    self.direct = false;
                    return self.file.write_all(bytes);
                }
                Err(error)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arbitrary_writes_and_flushes_preserve_exact_bytes() {
        for direct in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("artifact");
            let mut writer = ArtifactWriter::create(&path, direct).unwrap();
            let mut expected = Vec::new();
            for n in [1, 4095, 7, CAPACITY + 19, 13, 0, 8191] {
                let bytes: Vec<_> = (0..n).map(|i| (i % 251) as u8).collect();
                writer.write_all(&bytes).unwrap();
                expected.extend_from_slice(&bytes);
                writer.flush().unwrap();
                writer.flush().unwrap();
            }
            writer.finish().unwrap().sync_all().unwrap();
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
    }

    #[test]
    fn empty_artifact_stays_empty() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("empty");
        let file = ArtifactWriter::create(&path, true)
            .unwrap()
            .finish()
            .unwrap();
        file.sync_all().unwrap();
        assert_eq!(file.metadata().unwrap().len(), 0);
    }
}
