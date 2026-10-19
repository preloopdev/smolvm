//! Digest-keyed store of extracted OCI layers, shared across packs.
//!
//! A layer's identity is the SHA-256 of its **uncompressed** tar — the OCI
//! `diff_id` — so two packs that carry the same layer (a golden and the golden
//! plus one changed layer, say) resolve to the same directory and neither the
//! bytes nor the extraction are paid twice.
//!
//! Layout, under the store directory:
//!
//! ```text
//! <store_dir>/<diff_id>/            extracted tree, complete by construction
//! <store_dir>/<diff_id>.partial/    an extraction in flight
//! <store_dir>/.incoming/…           blob transfers and install locks
//! ```
//!
//! A directory with the layer's final name exists only after a whole layer was
//! unpacked into a `.partial` sibling and renamed into place, so "does this
//! layer exist" is one `is_dir()` and never a size check. That is the same
//! contract [`crate::extract`] uses for a pack's `layers/<id>/` directory; the
//! store simply makes the layer the unit instead of the pack.
//!
//! ## Why a store and not a per-pack cache
//!
//! The per-pack extraction cache is keyed by the pack's footer checksum, so any
//! change in a pack — one new layer, a re-baked rootfs, one more file in
//! `/workspace` — invalidates every layer in it, and the host pays a full
//! re-extract of tens of GB. Keying by layer content makes the unchanged layers
//! free and bounds a golden update's cost to the layers that actually changed.
//!
//! ## Relationship to the streaming store in `crate::extract`
//!
//! The runtime's own store API (`extract::shared_layers_dir`,
//! `extract::layer_present`, `extract::install_layer_from_stream`) is being
//! built in the same release. This module is the store primitive the split
//! registry path uses today, with the same layout, the same `.partial`-rename
//! discipline and the same digest verification, so the two can be collapsed to
//! one implementation without a format change.

use crate::extract::materialize_layer_from_reader;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// Directory of in-flight blob transfers and install locks.
pub const INCOMING_DIR: &str = ".incoming";
/// Suffix of an in-flight extraction, matching [`crate::extract`]'s staging.
pub const PARTIAL_SUFFIX: &str = ".partial";

/// The shared layer store under the pack cache root.
///
/// On macOS the store has to live on a case-sensitive volume: Linux layers
/// regularly carry paths that differ only in case, and the default APFS volume
/// would silently drop one of them. `layers-cs` is the mount point of that
/// volume, matching the runtime's `extract::shared_layers_dir`.
pub fn shared_layers_dir(shared_root: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        shared_root.join("layers-cs")
    }
    #[cfg(not(target_os = "macos"))]
    {
        shared_root.join("layers")
    }
}

/// Where a partially downloaded layer blob is staged.
///
/// Verified against `blob_digest` before use, so the staged file's name carries
/// the digest it must hash to: a resumed transfer can only ever append bytes to
/// a file whose prefix is the same blob.
pub fn incoming_blob_path(store_dir: &Path, diff_id: &str, blob_digest: &str) -> PathBuf {
    let diff = diff_id_hex(diff_id).unwrap_or("invalid-layer-digest");
    let blob = blob_digest.strip_prefix("sha256:").unwrap_or(blob_digest);
    store_dir
        .join(INCOMING_DIR)
        .join(format!("{diff}-{blob}.tar.zst.partial"))
}

/// Scratch directory of one store.
pub fn incoming_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(INCOMING_DIR)
}

/// Install one layer whose tar is read from `reader`, under `<store_dir>/<diff_id>/`.
///
/// The bytes are unpacked into a `.partial` sibling and renamed into place, so
/// an interrupted install leaves nothing that reads as a complete layer; the
/// next attempt discards the staging directory and starts clean. The
/// uncompressed bytes are hashed on the way through and the installed tree is
/// removed again if they do not hash to `diff_id` — a wrong digest annotation
/// must not leave a directory that later reads as a present layer.
pub fn install_layer_from_reader<R: Read>(
    store_dir: &Path,
    diff_id: &str,
    reader: R,
    owner_xattr: bool,
) -> std::io::Result<()> {
    let digest = normalize_diff_id(diff_id)?;
    let final_dir = store_dir.join(digest.trim_start_matches("sha256:"));
    if final_dir.is_dir() {
        return Ok(());
    }
    fs::create_dir_all(store_dir)?;
    let _lock = InstallLock::claim(store_dir, &digest)?;
    let mut hashing = HashingReader {
        inner: reader,
        hasher: Sha256::new(),
        bytes: 0,
    };
    let installed = materialize_layer_from_reader(&mut hashing, &final_dir, owner_xattr);
    let actual = format!("sha256:{:x}", hashing.hasher.finalize());
    match installed {
        Err(error) => Err(error),
        Ok(_) if actual == digest => Ok(()),
        Ok(_) => {
            let _ = fs::remove_dir_all(&final_dir);
            Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("layer bytes hash to {actual}, not the expected {digest}"),
            ))
        }
    }
}

/// Install a layer from a zstd-compressed blob file on disk.
pub fn install_layer_from_blob(
    store_dir: &Path,
    diff_id: &str,
    blob: &Path,
    owner_xattr: bool,
) -> std::io::Result<()> {
    let decoder = zstd::stream::read::Decoder::new(fs::File::open(blob)?)?;
    install_layer_from_reader(store_dir, diff_id, decoder, owner_xattr)
}

/// Identity of one compressed layer blob, as [`compress_layer_blob`] produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedLayer {
    /// `sha256:` of the uncompressed tar (OCI `diff_id`).
    pub diff_id: String,
    /// Size of the uncompressed tar in bytes.
    pub uncompressed_size: u64,
    /// `sha256:` of the compressed blob bytes.
    pub blob_digest: String,
    /// Size of the compressed blob in bytes.
    pub blob_size: u64,
}

/// Compress `reader`'s bytes into `dest` while hashing both the compressed blob
/// and the bytes that go in, at the pack format's own zstd level.
///
/// Both digests come out of one pass, which is what a publisher needs: the
/// digest of the compressed bytes is the blob's OCI digest, and the digest of
/// the uncompressed tar is the layer's `diff_id`, the name a consumer looks the
/// layer up under.
pub fn compress_layer_blob<R: Read>(
    reader: R,
    dest: &Path,
) -> Result<CompressedLayer, std::io::Error> {
    let mut sink = HashingWriter {
        inner: fs::File::create(dest)?,
        hasher: Sha256::new(),
        bytes: 0,
    };
    let mut diff_hasher = Sha256::new();
    let mut uncompressed = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    {
        let mut encoder =
            zstd::stream::write::Encoder::new(&mut sink, crate::assets::ZSTD_LEVEL)?;
        let mut reader = reader;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            diff_hasher.update(&buf[..n]);
            uncompressed += n as u64;
            encoder.write_all(&buf[..n])?;
        }
        // The frame epilogue (checksums, final block) is written through the
        // same sink, so the compressed digest covers the whole blob and not
        // just the blocks the caller fed in.
        encoder.finish()?;
    }
    sink.inner.sync_all()?;
    let blob_size = fs::metadata(dest)?.len();
    Ok(CompressedLayer {
        diff_id: format!("sha256:{:x}", diff_hasher.finalize()),
        uncompressed_size: uncompressed,
        blob_digest: format!("sha256:{:x}", sink.hasher.finalize()),
        blob_size,
    })
}

/// A reader that hashes whatever passes through it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
    bytes: u64,
}

impl<R: Read> Read for HashingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes += n as u64;
        Ok(n)
    }
}

/// A writer that hashes whatever reaches the file behind it.
struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    bytes: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.bytes += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// SHA-256 of a reader's bytes plus the byte count, lowercase hex.
pub fn sha256_reader<R: Read>(mut reader: R) -> std::io::Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1024 * 1024];
    let mut total = 0u64;
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        total += n as u64;
    }
    Ok((format!("sha256:{:x}", hasher.finalize()), total))
}

/// SHA-256 of a file's bytes plus the byte count, lowercase hex.
pub fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    sha256_reader(fs::File::open(path)?)
}

/// The bare hex of a layer identity, or `None` when it is not `sha256:<64 hex>`
/// (a bare 64-hex digest is accepted too).
pub fn diff_id_hex(diff_id: &str) -> Option<&str> {
    let hex = diff_id.strip_prefix("sha256:").unwrap_or(diff_id);
    (hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(hex)
}

/// Whether the store already holds the extracted tree for `diff_id`.
///
/// A final-name directory is complete by construction, so this is the whole
/// "do we need to fetch or extract this layer" test.
pub fn layer_present(store_dir: &Path, diff_id: &str) -> bool {
    let Some(hex) = diff_id_hex(diff_id) else {
        return false;
    };
    store_dir.join(hex.to_ascii_lowercase()).is_dir()
}

/// Normalize a layer identity to `sha256:<lowercase hex>`.
pub fn normalize_diff_id(diff_id: &str) -> Result<String, std::io::Error> {
    diff_id_hex(diff_id)
        .map(|hex| format!("sha256:{}", hex.to_ascii_lowercase()))
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("`{diff_id}` is not a sha256 layer digest"),
            )
        })
}

/// The layer identities a pack's manifest names, in stacking order (bottom→top).
pub fn manifest_layer_ids(manifest: &crate::format::PackManifest) -> Vec<String> {
    manifest
        .assets
        .layers
        .iter()
        .filter_map(|layer| normalize_diff_id(&layer.digest).ok())
        .collect()
}

/// One install per store and layer, so two pulls racing for the same layer do
/// not unpack into the same `.partial` staging directory.
struct InstallLock {
    file: fs::File,
}

impl InstallLock {
    fn claim(store_dir: &Path, diff_id: &str) -> std::io::Result<Self> {
        let hex = diff_id_hex(diff_id).unwrap_or("invalid-layer-digest");
        let dir = incoming_dir(store_dir);
        fs::create_dir_all(&dir)?;
        let file = fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(dir.join(format!("{}.install.lock", hex.to_ascii_lowercase())))?;
        // Blocking lock: whoever holds it is installing the same content this
        // caller wants, so waiting is strictly cheaper than unpacking twice.
        file.lock()?;
        Ok(Self { file })
    }
}

impl Drop for InstallLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A one-entry tar built in memory.
    fn tar_with(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, Cursor::new(body))
            .unwrap();
        builder.into_inner().unwrap()
    }

    /// A blob's identity is the digest of its uncompressed tar and the digest
    /// of the blob it wrote, and both survive a round trip through the file:
    /// that is what "content-addressed layer" means to a publisher and a
    /// consumer that never see each other's bytes.
    #[test]
    fn compress_layer_blob_hashes_the_tar_and_the_blob() {
        let temp = tempfile::tempdir().unwrap();
        let tar = tar_with("opt/hello.txt", b"hello");
        let dest = temp.path().join("hello.tar.zst");
        let layer = compress_layer_blob(Cursor::new(&tar), &dest).unwrap();

        let (diff_id, tar_size) = sha256_reader(Cursor::new(&tar)).unwrap();
        assert_eq!(layer.diff_id, diff_id);
        assert_eq!(layer.uncompressed_size, tar_size);

        let blob_bytes = std::fs::read(&dest).unwrap();
        let (blob_digest, blob_size) = sha256_reader(Cursor::new(&blob_bytes)).unwrap();
        assert_eq!(layer.blob_digest, blob_digest);
        assert_eq!(layer.blob_size, blob_size);
        assert_eq!(layer.blob_size, blob_bytes.len() as u64);
        assert!(layer.blob_size < tar.len() as u64);

        // The blob really is the tar, zstd-wrapped.
        let mut decoded = Vec::new();
        zstd::stream::read::Decoder::new(Cursor::new(&blob_bytes))
            .unwrap()
            .read_to_end(&mut decoded)
            .unwrap();
        assert_eq!(decoded, tar);
    }

    /// Installing from the *compressed* stream leaves the tree the tar
    /// describes, and the layer reads as present only afterwards.
    #[test]
    fn install_layer_from_blob_leaves_a_complete_tree() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("layers");
        let tar = tar_with("opt/hello.txt", b"hello");
        let blob = temp.path().join("layer.tar.zst");
        let layer = compress_layer_blob(Cursor::new(&tar), &blob).unwrap();

        assert!(!layer_present(&store, &layer.diff_id));

        install_layer_from_blob(&store, &layer.diff_id, &blob, false).unwrap();

        assert!(layer_present(&store, &layer.diff_id));
        assert_eq!(
            std::fs::read(store.join(diff_id_hex(&layer.diff_id).unwrap()).join("opt/hello.txt"))
                .unwrap(),
            b"hello"
        );
    }

    /// A blob that does not hash to the digest it was requested under must not
    /// leave a directory that reads as a present layer: the next consumer would
    /// otherwise stack the wrong tree silently.
    #[test]
    fn a_mismatched_layer_digest_leaves_no_layer() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("layers");
        let tar = tar_with("opt/hello.txt", b"hello");
        let blob = temp.path().join("layer.tar.zst");
        compress_layer_blob(Cursor::new(&tar), &blob).unwrap();

        let wrong = format!("sha256:{}", "ab".repeat(32));
        let error = install_layer_from_blob(&store, &wrong, &blob, false).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(!layer_present(&store, &wrong));
        assert!(!store.join("ab".repeat(32)).exists());
    }

    /// An interrupted install leaves only a `.partial` tree: the next attempt
    /// must not treat the half-written layer as present, and must not fail on
    /// the leftover staging directory either.
    #[test]
    fn a_partial_install_is_not_a_layer() {
        let temp = tempfile::tempdir().unwrap();
        let store = temp.path().join("layers");
        let diff_id = format!("sha256:{}", "ab".repeat(32));
        let staging = store.join(format!("{}{}", diff_id_hex(&diff_id).unwrap(), PARTIAL_SUFFIX));
        std::fs::create_dir_all(staging.join("opt")).unwrap();
        std::fs::write(staging.join("opt/half.txt"), b"half").unwrap();

        assert!(!layer_present(&store, &diff_id));

        let tar = tar_with("opt/hello.txt", b"hello");
        install_layer_from_reader(&store, &diff_id, Cursor::new(tar), false).unwrap();

        assert!(layer_present(&store, &diff_id));
        assert!(!staging.exists());
        let names: Vec<String> = std::fs::read_dir(store.join(diff_id_hex(&diff_id).unwrap()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["opt".to_string()]);
    }

    /// A manifest's digest names a directory, so a traversal or a short digest
    /// is refused before it reaches the filesystem.
    #[test]
    fn diff_ids_are_validated_before_they_name_a_directory() {
        assert!(diff_id_hex(&"a".repeat(64)).is_some());
        assert!(diff_id_hex(&format!("sha256:{}", "A".repeat(64))).is_some());
        assert!(diff_id_hex("sha256:../../etc").is_none());
        assert!(diff_id_hex(&"a".repeat(63)).is_none());
        assert_eq!(
            normalize_diff_id(&"A".repeat(64)).unwrap(),
            format!("sha256:{}", "a".repeat(64))
        );
        assert!(!layer_present(&PathBuf::from("/store"), "sha256:../../etc"));
        assert!(install_layer_from_reader(&PathBuf::from("/store"), "sha256:../../etc", Cursor::new(Vec::new()), false).is_err());
    }

    /// The identities come out of a pack's manifest in stacking order, so a
    /// consumer can tell "which of these layers must I fetch" from the pack
    /// alone.
    #[test]
    fn manifest_layer_ids_follow_manifest_order() {
        let mut manifest = crate::format::PackManifest::new(
            "img".into(),
            "sha256:0".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        for id in ["bb", "aa"] {
            manifest.assets.layers.push(crate::format::LayerEntry {
                digest: format!("sha256:{}", id.repeat(32)),
                path: format!("layers/{}.tar", id.repeat(32)),
                size: 1,
            });
        }
        assert_eq!(
            manifest_layer_ids(&manifest),
            vec![
                format!("sha256:{}", "bb".repeat(32)),
                format!("sha256:{}", "aa".repeat(32)),
            ]
        );
    }
}
