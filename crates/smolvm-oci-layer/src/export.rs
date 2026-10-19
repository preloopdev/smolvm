//! Writing a materialized layer tree back out as an OCI image layer blob.
//!
//! The inverse of [`crate::extract_oci_layer`]: a directory that is itself an
//! overlayfs upper (a machine's container overlay) holds *native* overlayfs
//! markers, and its siblings that were unpacked from a layer tar hold the same
//! markers in their own form. Neither form exists in the OCI tar representation
//! an image layer is stored as, so both are translated back on the way out:
//!
//! - a 0:0 character-device whiteout, or a zero-size regular file carrying the
//!   `*.overlay.whiteout` xattr, becomes an OCI `.wh.<name>` marker entry;
//! - an `*.overlay.opaque` xattr on a directory becomes an `.wh..wh..opq` entry
//!   inside it.
//!
//! Everything a layer tar cannot carry (sockets, fifos, real device nodes) is
//! skipped and counted, and the two overlayfs features that would need lower
//! layers to reinterpret (metacopy, redirect_dir) are refused rather than
//! silently exported as something else — a metacopy stub tars as an empty file,
//! which would truncate the file's real content in the packed image.
//!
//! xattrs other than the overlay markers are not carried: the pack import path
//! never applied them, so emitting `SCHILY.xattr.*` records would not round-trip
//! through `smolvm machine create --from`. The one that matters in practice —
//! `security.capability` — is equally absent from the flattened single-layer
//! packs this feature replaces, so parity is unchanged.

use std::collections::HashMap;
use std::ffi::CString;
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};

use tracing::warn;

/// What an exported layer tar carried.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExportStats {
    /// Entries written, marker entries included.
    pub entries: u64,
    /// Regular-file bytes written.
    pub bytes: u64,
    /// `.wh.<name>` markers written.
    pub whiteouts: u64,
    /// `.wh..wh..opq` markers written.
    pub opaque_dirs: u64,
    /// Entries a layer tar cannot represent (sockets, fifos, device nodes).
    pub skipped: u64,
}

/// Write `source`'s tree as an OCI image layer tar to `out`.
///
/// The tar holds the directory's *contents*, so extracting it into an empty
/// directory reproduces `source` exactly (markers aside). Entries are written
/// in sorted order, which — with the fixed header fields below — makes the same
/// tree produce the same bytes on every export.
pub fn export_layer_tar(source: &Path, out: impl Write) -> std::io::Result<ExportStats> {
    if !source.is_dir() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{} is not a directory", source.display()),
        ));
    }
    let mut writer = LayerWriter {
        builder: tar::Builder::new(out),
        stats: ExportStats::default(),
        hardlinks: HashMap::new(),
    };
    writer.walk(source, Path::new(""))?;
    writer.builder.finish()?;
    Ok(writer.stats)
}

struct LayerWriter<W: Write> {
    builder: tar::Builder<W>,
    stats: ExportStats,
    /// First path written for each (device, inode) of a multiply-linked file,
    /// so later links are written as tar hardlinks instead of duplicate data.
    hardlinks: HashMap<(u64, u64), PathBuf>,
}

impl<W: Write> LayerWriter<W> {
    /// Write `dir`'s contents under the archive prefix `prefix`.
    fn walk(&mut self, dir: &Path, prefix: &Path) -> std::io::Result<()> {
        let mut children: Vec<(PathBuf, std::ffi::OsString)> = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            children.push((entry.path(), entry.file_name()));
        }
        // Sorted so two exports of the same tree produce the same tar.
        children.sort_by(|a, b| a.1.cmp(&b.1));

        for (path, name) in children {
            let relative = prefix.join(&name);
            let metadata = std::fs::symlink_metadata(&path)?;
            let file_type = metadata.file_type();

            if file_type.is_dir() {
                self.write_dir(&path, &relative, &metadata)?;
                self.walk(&path, &relative)?;
            } else if file_type.is_symlink() {
                let target = std::fs::read_link(&path)?;
                self.write_link(&relative, &target, &metadata)?;
            } else if file_type.is_file() {
                self.write_file(&path, &relative, &metadata)?;
            } else {
                self.write_special(&relative, &metadata)?;
            }
        }
        Ok(())
    }

    fn write_dir(
        &mut self,
        path: &Path,
        relative: &Path,
        metadata: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        if xattr(path, OVERLAY_REDIRECT).is_some() {
            return Err(refuse(
                relative,
                "it is a redirected directory (trusted.overlay.redirect): its \
                 contents live at another path in a lower layer, which a layer \
                 tar cannot express",
            ));
        }
        let mut header = self.header(metadata, tar::EntryType::Directory)?;
        header.set_size(0);
        self.builder.append_data(&mut header, relative, std::io::empty())?;
        self.stats.entries += 1;

        if overlay_opaque(path) {
            let marker = relative.join(OPAQUE_MARKER);
            let mut header = self.marker_header();
            self.builder
                .append_data(&mut header, &marker, std::io::empty())?;
            self.stats.entries += 1;
            self.stats.opaque_dirs += 1;
        }
        Ok(())
    }

    fn write_file(
        &mut self,
        path: &Path,
        relative: &Path,
        metadata: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        if let Some(name) = marker_name(relative) {
            // A real file whose name a layer tar reserves for markers cannot be
            // represented: extraction would read it as a deletion.
            return Err(refuse(
                relative,
                &format!("'{name}' is a reserved whiteout marker name"),
            ));
        }
        if xattr(path, OVERLAY_METACOPY).is_some() {
            return Err(refuse(
                relative,
                "it is a metacopy stub (trusted.overlay.metacopy) whose data \
                 lives in a lower layer; a layer tar cannot express it",
            ));
        }
        if overlay_whiteout(path) {
            let whiteout = whiteout_path(relative);
            let mut header = self.marker_header();
            self.builder
                .append_data(&mut header, &whiteout, std::io::empty())?;
            self.stats.entries += 1;
            self.stats.whiteouts += 1;
            return Ok(());
        }

        // A file with more than one link is written once; the rest become tar
        // hardlinks to it, so the packed image does not multiply its size.
        if metadata.nlink() > 1 {
            let key = (metadata.dev(), metadata.ino());
            if let Some(first) = self.hardlinks.get(&key) {
                let first = first.clone();
                let mut header = self.header(metadata, tar::EntryType::Link)?;
                header.set_size(0);
                self.builder.append_link(&mut header, relative, &first)?;
                self.stats.entries += 1;
                return Ok(());
            }
            self.hardlinks.insert(key, relative.to_path_buf());
        }

        let mut file = File::open(path)?;
        let mut header = self.header(metadata, tar::EntryType::Regular)?;
        header.set_size(metadata.len());
        self.builder.append_data(&mut header, relative, &mut file)?;
        self.stats.entries += 1;
        self.stats.bytes = self.stats.bytes.saturating_add(metadata.len());
        Ok(())
    }

    fn write_link(
        &mut self,
        relative: &Path,
        target: &Path,
        metadata: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        let mut header = self.header(metadata, tar::EntryType::Symlink)?;
        header.set_size(0);
        self.builder.append_link(&mut header, relative, target)?;
        self.stats.entries += 1;
        Ok(())
    }

    /// Device nodes and fifos. A 0:0 character device is overlayfs's own
    /// whiteout and translates; anything else has no place in a layer tar.
    fn write_special(
        &mut self,
        relative: &Path,
        metadata: &std::fs::Metadata,
    ) -> std::io::Result<()> {
        let file_type = metadata.file_type();
        if file_type.is_char_device() && metadata.rdev() == 0 {
            let whiteout = whiteout_path(relative);
            let mut header = self.marker_header();
            self.builder
                .append_data(&mut header, &whiteout, std::io::empty())?;
            self.stats.entries += 1;
            self.stats.whiteouts += 1;
            return Ok(());
        }
        warn!(
            path = %relative.display(),
            "skipping a device node a layer tar cannot carry"
        );
        self.stats.skipped += 1;
        Ok(())
    }

    fn header(
        &self,
        metadata: &std::fs::Metadata,
        entry_type: tar::EntryType,
    ) -> std::io::Result<tar::Header> {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(metadata.mode() & 0o7777);
        header.set_uid(metadata.uid() as u64);
        header.set_gid(metadata.gid() as u64);
        header.set_mtime(metadata.mtime().max(0) as u64);
        Ok(header)
    }

    /// A marker entry: owned by root, mode 0644, empty — what docker writes for
    /// `.wh.` entries, and what extraction reads back into a whiteout.
    fn marker_header(&self) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(0);
        header
    }
}

/// OCI opaque-directory marker.
const OPAQUE_MARKER: &str = ".wh..wh..opq";
/// xattrs overlayfs records a deletion and a directory replacement in.
const OVERLAY_OPAQUE: [&str; 2] = ["trusted.overlay.opaque", "user.overlay.opaque"];
const OVERLAY_WHITEOUT: [&str; 2] = ["trusted.overlay.whiteout", "user.overlay.whiteout"];
/// Features whose upper entries only mean something with a lower layer to
/// reinterpret them; both are refused rather than mis-exported.
const OVERLAY_METACOPY: &str = "trusted.overlay.metacopy";
const OVERLAY_REDIRECT: &str = "trusted.overlay.redirect";

/// The `.wh.<name>` path a whiteout for `relative` takes.
fn whiteout_path(relative: &Path) -> PathBuf {
    let name = relative
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default();
    relative.with_file_name(format!(".wh.{name}"))
}

/// The reserved marker name `relative` ends in, if it is one.
fn marker_name(relative: &Path) -> Option<String> {
    let name = relative.file_name()?.to_string_lossy().to_string();
    if name == OPAQUE_MARKER || (name.starts_with(".wh.") && name.len() > 4) {
        return Some(name);
    }
    None
}

fn overlay_opaque(dir: &Path) -> bool {
    OVERLAY_OPAQUE
        .iter()
        .any(|name| xattr(dir, name).is_some_and(|value| value == b"y"))
}

fn overlay_whiteout(file: &Path) -> bool {
    OVERLAY_WHITEOUT.iter().any(|name| xattr(file, name).is_some())
}

fn refuse(relative: &Path, why: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!("cannot export '{}': {why}", relative.display()),
    )
}

/// An xattr's value, or `None` when it is absent or unreadable.
///
/// Only the overlay markers are ever asked for, and the export runs in the
/// guest (Linux) as root, so an unreadable value means absent.
#[cfg(target_os = "linux")]
fn xattr(path: &Path, name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let c_name = CString::new(name).ok()?;
    let mut buffer = vec![0u8; 256];
    loop {
        let read = unsafe {
            libc::lgetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
            )
        };
        if read >= 0 {
            buffer.truncate(read as usize);
            return Some(buffer);
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ERANGE) && buffer.len() < (1 << 20) {
            buffer.resize(buffer.len() * 2, 0);
            continue;
        }
        return None;
    }
}

/// Non-Linux stub: nothing this crate does reaches a guest outside Linux, and
/// the host builds must still compile (macOS `lgetxattr` has its own shape).
#[cfg(not(target_os = "linux"))]
fn xattr(_path: &Path, _name: &str) -> Option<Vec<u8>> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar_bytes(source: &Path) -> Vec<u8> {
        let mut bytes = Vec::new();
        export_layer_tar(source, &mut bytes).unwrap();
        bytes
    }

    fn extract(bytes: &[u8], dest: &Path) {
        // Every caller hands the extractor an existing staging directory.
        std::fs::create_dir_all(dest).unwrap();
        crate::extract_oci_layer(bytes, dest).unwrap();
    }

    #[test]
    fn plain_tree_round_trips_through_export_and_extraction() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("source");
        std::fs::create_dir_all(source.join("etc/nested")).unwrap();
        std::fs::write(source.join("etc/passwd"), b"root:x:0:0::/root:/bin/sh\n").unwrap();
        std::fs::write(source.join("etc/nested/empty"), b"").unwrap();
        // 0755 dirs, a setuid file, and an executable bit must all survive.
        std::fs::write(source.join("etc/nested/tool"), b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            source.join("etc/nested/tool"),
            std::fs::Permissions::from_mode(0o4755),
        )
        .unwrap();
        std::os::unix::fs::symlink("/etc/passwd", source.join("etc/aliases")).unwrap();

        let bytes = tar_bytes(&source);
        let dest = tmp.path().join("dest");
        extract(&bytes, &dest);

        assert_eq!(
            std::fs::read(dest.join("etc/passwd")).unwrap(),
            b"root:x:0:0::/root:/bin/sh\n"
        );
        assert_eq!(std::fs::read(dest.join("etc/nested/empty")).unwrap(), b"");
        assert_eq!(
            std::fs::metadata(dest.join("etc/nested/tool"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o4755
        );
        assert_eq!(
            std::fs::read_link(dest.join("etc/aliases")).unwrap(),
            Path::new("/etc/passwd")
        );
    }

    #[test]
    fn marker_names_and_opaque_dirs_are_translated() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("upper");
        std::fs::create_dir_all(source.join("var/lib/apt/lists")).unwrap();
        std::fs::write(source.join("var/lib/apt/lists/keep"), b"kept").unwrap();

        // A deleted file must only be representable as an OCI marker.
        assert_eq!(
            whiteout_path(Path::new("var/lib/apt/lists/stale")),
            Path::new("var/lib/apt/lists/.wh.stale")
        );
        assert_eq!(marker_name(Path::new("a/.wh.b")), Some(".wh.b".to_string()));
        assert_eq!(
            marker_name(Path::new("a/.wh..wh..opq")),
            Some(".wh..wh..opq".to_string())
        );
        assert_eq!(marker_name(Path::new("a/wherever")), None);

        // A file whose name is a reserved marker is refused, not exported as a
        // name extraction would read as a deletion.
        std::fs::write(source.join("var/lib/apt/lists/.wh.stale"), b"").unwrap();
        let error = export_layer_tar(&source, Vec::new()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains(".wh.stale"), "{error}");
    }

    /// The translation that matters: the same tree exported, extracted into an
    /// overlayfs lowerdir, and used as one must hide the deleted path and
    /// replace the opaque directory — this is what a machine booting from the
    /// layer will see.
    #[cfg(target_os = "linux")]
    #[test]
    fn whiteout_and_opaque_markers_survive_a_round_trip() {
        use std::os::unix::fs::MetadataExt;

        let tmp = tempfile::tempdir().unwrap();
        let base = tmp.path().join("base");
        std::fs::create_dir_all(base.join("etc/apt/lists")).unwrap();
        std::fs::create_dir_all(base.join("var/keep")).unwrap();
        std::fs::write(base.join("etc/apt/lists/base-only"), b"from base").unwrap();
        std::fs::write(base.join("etc/deleted-by-top"), b"from base").unwrap();
        std::fs::write(base.join("var/keep/old"), b"from base").unwrap();

        // The upper: a whiteout for `etc/deleted-by-top`, an opaque replacement
        // of `var/keep`, and a new file.
        let upper = tmp.path().join("upper");
        std::fs::create_dir_all(upper.join("etc")).unwrap();
        std::fs::create_dir_all(upper.join("var/keep")).unwrap();
        std::fs::write(upper.join("etc/new"), b"from upper").unwrap();
        std::fs::write(upper.join("var/keep/new"), b"from upper").unwrap();
        if crate::create_overlay_whiteout(&upper.join("etc/deleted-by-top")).is_err() {
            eprintln!("skipping: creating an overlay whiteout needs root on Linux");
            return;
        }
        if crate::set_overlay_opaque(&upper.join("var/keep")).is_err() {
            eprintln!("skipping: trusted.overlay.opaque needs CAP_SYS_ADMIN");
            return;
        }

        let bytes = tar_bytes(&upper);
        let lower = tmp.path().join("lower");
        extract(&bytes, &lower);

        // What the layer's own bytes say: OCI markers, not devices.
        let mut names = Vec::new();
        {
            let mut archive = tar::Archive::new(std::io::Cursor::new(bytes.as_slice()));
            for entry in archive.entries().unwrap() {
                let entry = entry.unwrap();
                let path = entry.path().unwrap().to_string_lossy().to_string();
                // A char-device whiteout in the source must not be one in the tar.
                assert_ne!(entry.header().entry_type(), tar::EntryType::Char);
                names.push(path);
            }
        }
        assert!(names.contains(&"etc/.wh.deleted-by-top".to_string()), "{names:?}");
        assert!(
            names.contains(&"var/keep/.wh..wh..opq".to_string()),
            "{names:?}"
        );

        // And what the kernel will read back out of the extracted lowerdir.
        let whiteout = std::fs::symlink_metadata(lower.join("etc/deleted-by-top")).unwrap();
        assert!(whiteout.file_type().is_char_device(), "whiteout is a char device");
        assert_eq!(whiteout.rdev(), 0, "whiteout device number is 0/0");
        assert_eq!(overlay_opaque(&lower.join("var/keep")), true);
    }

    #[test]
    fn hardlinked_files_are_written_once() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("upper");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("first"), b"shared body").unwrap();
        std::fs::hard_link(source.join("first"), source.join("second")).unwrap();

        let bytes = tar_bytes(&source);
        let mut links = 0;
        let mut regular_bytes = 0u64;
        let mut archive = tar::Archive::new(std::io::Cursor::new(bytes.as_slice()));
        for entry in archive.entries().unwrap() {
            let entry = entry.unwrap();
            match entry.header().entry_type() {
                tar::EntryType::Link => {
                    links += 1;
                    assert_eq!(
                        entry.link_name().unwrap().unwrap().to_string_lossy(),
                        "first"
                    );
                }
                tar::EntryType::Regular => regular_bytes += entry.header().size().unwrap(),
                _ => {}
            }
        }
        assert_eq!(links, 1, "the second link is a tar hardlink");
        assert_eq!(regular_bytes, 11, "the body is stored once");
    }

    #[test]
    fn a_metacopy_stub_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("upper");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("stub"), b"").unwrap();
        if set_xattr(&source.join("stub"), OVERLAY_METACOPY, b"y").is_err() {
            eprintln!("skipping: trusted.* xattrs need root on Linux");
            return;
        }
        let error = export_layer_tar(&source, Vec::new()).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("metacopy"), "{error}");
    }

    #[cfg(target_os = "linux")]
    fn set_xattr(path: &Path, name: &str, value: &[u8]) -> std::io::Result<()> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        let c_name = CString::new(name).unwrap();
        let rc = unsafe {
            libc::lsetxattr(
                c_path.as_ptr(),
                c_name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// Non-Linux hosts cannot set the overlay xattrs the export reads, so the
    /// tests that need them skip rather than fail there.
    #[cfg(not(target_os = "linux"))]
    fn set_xattr(_path: &Path, _name: &str, _value: &[u8]) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "overlay xattrs are Linux-only",
        ))
    }
}
