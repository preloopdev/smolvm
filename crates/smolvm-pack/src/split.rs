//! Split a `.smolmachine` into a base pack plus one blob per OCI layer.
//!
//! A pack's layers are already separate, content-addressed members of its
//! assets archive — but they travel inside the pack, so every publish uploads
//! all of them again and every consumer downloads all of them again, even when
//! one layer changed. This module takes a pack apart into:
//!
//! * a **base pack**: a valid `.smolmachine` whose `assets.layers[]` still names
//!   every layer, in stacking order, but whose assets archive carries none of
//!   the layer tars; and
//! * one **zstd blob per layer**, keyed by the layer's content.
//!
//! Layer identity is the SHA-256 of the **uncompressed** tar (the OCI
//! `diff_id`), computed while the member streams out. That is what makes two
//! publishes that share a layer share its bytes: the identity does not depend on
//! the compression level, the pack's checksum, or anything else about the pack
//! that carried it.
//!
//! ## Cost
//!
//! Deriving costs one pass over the pack's assets: the layer members stream
//! into their own compressed blobs while every other member lands in a staging
//! directory, which the ordinary packer then compresses into the base. Both
//! halves are cached under [`SplitCache`] — the base keyed by the pack's footer
//! checksum, the blobs by layer content — so a second publish of the same pack
//! re-reads nothing, and a second publish that differs in one layer compresses
//! only that layer.

use crate::assets::{unpack_assets_skipping, AssetCollector};
use crate::format::{LayerEntry, PackFooter, PackManifest};
use crate::packer::{read_footer_from_sidecar, read_manifest_from_sidecar, Packer};
use crate::{PackError, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[derive(Debug, Clone, PartialEq, Eq)]
struct CompressedLayer {
    diff_id: String,
    uncompressed_size: u64,
    blob_digest: String,
    blob_size: u64,
}

fn diff_id_hex(diff_id: &str) -> Option<&str> {
    let hex = diff_id.strip_prefix("sha256:").unwrap_or(diff_id);
    (hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(hex)
}

fn sha256_reader<R: Read>(mut reader: R) -> std::io::Result<(String, u64)> {
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

fn sha256_file(path: &Path) -> std::io::Result<(String, u64)> {
    sha256_reader(fs::File::open(path)?)
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn compress_layer_blob<R: Read>(reader: R, dest: &Path) -> std::io::Result<CompressedLayer> {
    let mut sink = HashingWriter {
        inner: fs::File::create(dest)?,
        hasher: Sha256::new(),
    };
    let mut diff_hasher = Sha256::new();
    let mut uncompressed_size = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    {
        let mut encoder = zstd::stream::write::Encoder::new(&mut sink, crate::assets::ZSTD_LEVEL)?;
        let mut reader = reader;
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            diff_hasher.update(&buf[..n]);
            uncompressed_size += n as u64;
            encoder.write_all(&buf[..n])?;
        }
        encoder.finish()?;
    }
    sink.inner.sync_all()?;
    let blob_size = fs::metadata(dest)?.len();
    Ok(CompressedLayer {
        diff_id: format!("sha256:{:x}", diff_hasher.finalize()),
        uncompressed_size,
        blob_size,
        blob_digest: format!("sha256:{:x}", sink.hasher.finalize()),
    })
}

/// Member prefix of a layer inside a pack's assets archive.
pub const LAYER_MEMBER_PREFIX: &str = "layers/";

/// One layer of a split pack, as a publisher sees it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SplitLayer {
    /// `sha256:<hex>` of the uncompressed layer tar (OCI `diff_id`).
    pub diff_id: String,
    /// Path the base pack names for this layer (`layers/<diff_id>.tar`).
    pub archive_path: String,
    /// Member path the layer had in the pack it came from.
    pub member_path: String,
    /// Size of the uncompressed tar in bytes.
    pub uncompressed_size: u64,
    /// `sha256:<hex>` of the compressed blob — the blob's OCI digest.
    pub blob_digest: String,
    /// Size of the compressed blob in bytes.
    pub blob_size: u64,
    /// File name of the blob inside the split cache's `blobs/` directory.
    pub blob_file: String,
}

impl SplitLayer {
    /// Absolute path of the layer's blob in `blobs_dir`.
    pub fn blob_path(&self, blobs_dir: &Path) -> PathBuf {
        blobs_dir.join(&self.blob_file)
    }
}

/// A pack taken apart: the base pack plus its layers, bottom→top.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPack {
    /// The `.smolmachine` with no layer tars in its assets.
    pub base_path: PathBuf,
    /// `sha256:<hex>` of the base pack file (its OCI blob digest).
    pub base_digest: String,
    /// Size of the base pack file in bytes.
    pub base_size: u64,
    /// Layers in stacking order, bottom→top.
    pub layers: Vec<SplitLayer>,
    /// Whether this run reused cached artifacts instead of re-deriving them.
    pub cached: bool,
}

/// Persistent caches a split publish reads and writes.
///
/// Split across two keys on purpose: the base is identified by the pack it came
/// from (nobody can name it before deriving it), while a layer blob is
/// identified by the layer's own content, which is what lets two different
/// packs share it.
#[derive(Debug, Clone)]
pub struct SplitCache {
    root: PathBuf,
}

impl SplitCache {
    /// A cache rooted at `root` (created on demand).
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Directory holding content-addressed layer blobs.
    pub fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }

    /// Where this cache lives, for a caller that has to explain itself.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn bases_dir(&self) -> PathBuf {
        self.root.join("bases")
    }

    fn temp_dir(&self) -> PathBuf {
        self.root.join("tmp")
    }

    /// Cache entry directory for one pack, keyed by the pack's own checksum.
    ///
    /// The checksum covers the assets and the manifest, so a pack that differs
    /// in any byte a consumer could observe lands in a different entry.
    fn base_entry(&self, footer: &PackFooter) -> PathBuf {
        self.bases_dir().join(format!(
            "{:08x}-{:x}-{:x}",
            footer.checksum, footer.assets_size, footer.manifest_size
        ))
    }

    fn blob_record_path(&self, diff_id: &str) -> Option<PathBuf> {
        diff_id_hex(diff_id).map(|hex| self.blobs_dir().join(format!("{hex}.json")))
    }
}

/// What a cached layer blob records about itself, written after the blob was
/// fully written and hashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlobRecord {
    blob_digest: String,
    blob_size: u64,
    uncompressed_size: u64,
}

/// Take `pack` apart into a base pack and per-layer blobs.
///
/// A cache hit costs a few small reads: the base pack and the layer list come
/// from [`SplitCache`], and each blob is checked against the size its record was
/// written with.
pub fn split_pack(pack: &Path, cache: &SplitCache) -> Result<SplitPack> {
    let footer = read_footer_from_sidecar(pack)?;
    let manifest = read_manifest_from_sidecar(pack)?;
    if manifest.assets.layers.is_empty() {
        return Err(PackError::AssetNotFound(
            "this pack carries no layers to split".into(),
        ));
    }

    let entry = cache.base_entry(&footer);
    if let Some(split) = read_cached_split(&entry, cache, &manifest)? {
        return Ok(split);
    }

    fs::create_dir_all(cache.blobs_dir())?;
    fs::create_dir_all(cache.temp_dir())?;
    fs::create_dir_all(&entry)?;
    let staging = cache.temp_dir().join("staging");
    if staging.exists() {
        fs::remove_dir_all(&staging)?;
    }

    let derived = derive_layers(pack, &footer, cache, &staging)?;
    let layers = reconcile_with_manifest(&manifest, derived)?;

    // The base names every layer, in stacking order, at the identity a consumer
    // will look up in its own layer store.
    let mut base_manifest = manifest.clone();
    base_manifest.assets.layers = layers
        .iter()
        .map(|layer| LayerEntry {
            digest: layer.diff_id.clone(),
            path: layer.archive_path.clone(),
            size: layer.uncompressed_size,
        })
        .collect();

    let base_path = entry.join("base.smolmachine");
    let base_tmp = entry.join("base.smolmachine.partial");
    let _ = fs::remove_file(&base_tmp);
    let collector = AssetCollector::new(staging.clone())?;
    let packed = Packer::new(base_manifest)
        .with_asset_collector(collector)
        .pack_artifact(&base_tmp)?;
    debug_assert_eq!(packed.sidecar_path.as_deref(), Some(base_tmp.as_path()));
    fs::rename(&base_tmp, &base_path)?;
    let _ = fs::remove_dir_all(&staging);

    fs::write(
        entry.join("layers.json"),
        serde_json::to_vec_pretty(&layers)?,
    )?;
    let (base_digest, base_size) = sha256_file(&base_path)?;
    Ok(SplitPack {
        base_path,
        base_digest,
        base_size,
        layers,
        cached: false,
    })
}

/// Read a cached base entry, when it is complete and its blobs are all present.
///
/// A record whose blob is missing or truncated is not a cache hit: the caller
/// re-derives, and the derivation overwrites the entry.
fn read_cached_split(
    entry: &Path,
    cache: &SplitCache,
    manifest: &PackManifest,
) -> Result<Option<SplitPack>> {
    let base_path = entry.join("base.smolmachine");
    let layers_path = entry.join("layers.json");
    if !base_path.is_file() || !layers_path.is_file() {
        return Ok(None);
    }
    let Ok(raw) = fs::read(&layers_path) else {
        return Ok(None);
    };
    let Ok(layers) = serde_json::from_slice::<Vec<SplitLayer>>(&raw) else {
        return Ok(None);
    };
    if layers.len() != manifest.assets.layers.len() {
        return Ok(None);
    }
    for layer in &layers {
        let blob = layer.blob_path(&cache.blobs_dir());
        match fs::metadata(&blob) {
            Ok(meta) if meta.len() == layer.blob_size => {}
            _ => return Ok(None),
        }
        let Some(record_path) = cache.blob_record_path(&layer.diff_id) else {
            return Ok(None);
        };
        let Ok(raw) = fs::read(&record_path) else {
            return Ok(None);
        };
        let Ok(record) = serde_json::from_slice::<BlobRecord>(&raw) else {
            return Ok(None);
        };
        if record.blob_digest != layer.blob_digest
            || record.blob_size != layer.blob_size
            || record.uncompressed_size != layer.uncompressed_size
        {
            return Ok(None);
        }
    }
    let (base_digest, base_size) = sha256_file(&base_path)?;
    Ok(Some(SplitPack {
        base_path,
        base_digest,
        base_size,
        layers,
        cached: true,
    }))
}

/// One pass over the pack's assets: stream every layer member into its own
/// blob, and unpack every other member into `staging` for the base pack.
fn derive_layers(
    pack: &Path,
    footer: &PackFooter,
    cache: &SplitCache,
    staging: &Path,
) -> Result<Vec<SplitLayer>> {
    let mut file = fs::File::open(pack)?;
    file.seek(SeekFrom::Start(footer.assets_offset))?;
    let assets = file.take(footer.assets_size);

    let mut layers: Vec<SplitLayer> = Vec::new();
    let mut failure: Option<PackError> = None;
    unpack_assets_skipping(
        BufReader::new(assets),
        staging,
        |path| is_layer_member(path),
        |path, reader| {
            // Keep the first failure: a later one is a consequence of the
            // stream being abandoned at the first.
            match compress_one_layer(path, reader, cache) {
                Ok(layer) => layers.push(layer),
                Err(error) => {
                    failure = Some(error);
                    return Err(PackError::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        "layer stream abandoned after an earlier failure",
                    )));
                }
            }
            Ok(())
        },
    )
    .map_err(|error| failure.unwrap_or(error))?;
    Ok(layers)
}

/// Whether an assets member is an OCI layer tar.
fn is_layer_member(path: &Path) -> bool {
    let name = path.to_string_lossy().replace('\\', "/");
    name.starts_with(LAYER_MEMBER_PREFIX)
        && name.ends_with(".tar")
        && path.components().count() == 2
}

/// Compress one layer member into the cache's content-addressed blob.
///
/// A layer whose blob is already cached at the same digest is reused: the
/// compressed bytes are identical by construction, so the freshly compressed
/// copy is dropped rather than replacing an identical file.
fn compress_one_layer<R: Read + ?Sized>(
    member_path: &Path,
    member: &mut R,
    cache: &SplitCache,
) -> Result<SplitLayer> {
    let temp = cache.temp_dir().join(format!(
        "{}.tar.zst",
        member_path
            .file_stem()
            .map(|stem| stem.to_string_lossy().into_owned())
            .unwrap_or_else(|| "layer".to_string())
    ));
    let _ = fs::remove_file(&temp);
    let layer: CompressedLayer = compress_layer_blob(member, &temp)?;
    let hex = diff_id_hex(&layer.diff_id)
        .ok_or_else(|| PackError::Compression("a layer hashed to a non-sha256 identity".into()))?
        .to_owned();
    let blob_file = format!("{hex}.tar.zst");
    let blob_path = cache.blobs_dir().join(&blob_file);
    let record_path = cache.blobs_dir().join(format!("{hex}.json"));

    let cached = fs::read(&record_path)
        .ok()
        .and_then(|raw| serde_json::from_slice::<BlobRecord>(&raw).ok())
        .is_some_and(|record| {
            record.blob_digest == layer.blob_digest
                && record.blob_size == layer.blob_size
                && record.uncompressed_size == layer.uncompressed_size
                && fs::metadata(&blob_path).is_ok_and(|meta| meta.len() == record.blob_size)
        });

    if cached {
        let _ = fs::remove_file(&temp);
    } else {
        fs::rename(&temp, &blob_path)?;
        fs::write(
            &record_path,
            serde_json::to_vec_pretty(&BlobRecord {
                blob_digest: layer.blob_digest.clone(),
                blob_size: layer.blob_size,
                uncompressed_size: layer.uncompressed_size,
            })?,
        )?;
    }

    Ok(SplitLayer {
        diff_id: layer.diff_id,
        archive_path: format!("layers/{hex}.tar"),
        member_path: member_path.to_string_lossy().replace('\\', "/"),
        uncompressed_size: layer.uncompressed_size,
        blob_digest: layer.blob_digest,
        blob_size: layer.blob_size,
        blob_file,
    })
}

/// Order the derived layers as the manifest names them, and refuse a pack whose
/// archive and manifest disagree.
///
/// A pack is the only source of truth about its own layers: if the archive
/// carries a layer the manifest does not name (or the other way round), the base
/// pack would name a layer nobody can install.
fn reconcile_with_manifest(
    manifest: &PackManifest,
    mut derived: Vec<SplitLayer>,
) -> Result<Vec<SplitLayer>> {
    if derived.len() != manifest.assets.layers.len() {
        let found: Vec<String> = derived
            .iter()
            .map(|layer| layer.member_path.clone())
            .collect();
        let named: Vec<String> = manifest
            .assets
            .layers
            .iter()
            .map(|entry| entry.path.clone())
            .collect();
        return Err(PackError::Tar(format!(
            "asset archive carries {} layer(s) but the manifest names {}; archive: {found:?}, manifest: {named:?}",
            derived.len(),
            manifest.assets.layers.len()
        )));
    }
    let mut ordered = Vec::with_capacity(derived.len());
    for entry in &manifest.assets.layers {
        let wanted = entry.path.replace('\\', "/");
        let position = derived
            .iter()
            .position(|layer| layer.member_path == wanted)
            .ok_or_else(|| {
                PackError::AssetNotFound(format!(
                    "asset archive is missing the layer `{}` the manifest names",
                    entry.path
                ))
            })?;
        ordered.push(derived.remove(position));
    }
    Ok(ordered)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The member paths of a pack's assets archive, in tar order.
    fn assets_members(pack: &Path) -> Vec<String> {
        let footer = read_footer_from_sidecar(pack).unwrap();
        let mut file = std::fs::File::open(pack).unwrap();
        file.seek(SeekFrom::Start(footer.assets_offset)).unwrap();
        let decoder = zstd::stream::read::Decoder::new(file.take(footer.assets_size)).unwrap();
        let mut archive = tar::Archive::new(decoder);
        archive
            .entries()
            .unwrap()
            .map(|entry| {
                entry
                    .unwrap()
                    .path()
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    /// A tar of one file, as a layer's bytes.
    fn layer_tar(name: &str, body: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, name, std::io::Cursor::new(body))
            .unwrap();
        builder.into_inner().unwrap()
    }

    /// A pack with `layers` and one non-layer asset, built the way `pack create`
    /// builds one.
    fn write_pack(path: &Path, layers: &[(&str, Vec<u8>)]) -> PackManifest {
        let staging = path.parent().unwrap().join("staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(staging.join("agent-rootfs.tar"), b"rootfs").unwrap();
        let mut collector = AssetCollector::new(staging).unwrap();
        for (digest, bytes) in layers {
            collector
                .add_layer(&format!("sha256:{digest}"), bytes)
                .unwrap();
        }
        let mut manifest = PackManifest::new(
            "img".into(),
            "sha256:0".into(),
            "linux/amd64".into(),
            "linux/amd64".into(),
        );
        manifest.assets = collector.inventory().clone();
        let info = Packer::new(manifest.clone())
            .with_asset_collector(collector)
            .pack_artifact(path)
            .unwrap();
        assert!(info.total_size > 0);
        manifest
    }

    /// Splitting a pack puts every layer in its own blob, names them in the base
    /// at their content identity, and leaves the base without any layer member.
    #[test]
    fn split_pack_separates_layers_from_the_base() {
        let temp = tempfile::tempdir().unwrap();
        let pack = temp.path().join("golden.smolmachine");
        let layers: Vec<(String, Vec<u8>)> = (0..3)
            .map(|index| {
                (
                    format!("{:02x}", index + 1).repeat(32),
                    layer_tar("opt/file.txt", format!("layer {index}").as_bytes()),
                )
            })
            .collect();
        let refs: Vec<(&str, Vec<u8>)> = layers
            .iter()
            .map(|(digest, bytes)| (digest.as_str(), bytes.clone()))
            .collect();
        write_pack(&pack, &refs);

        let cache = SplitCache::new(temp.path().join("cache"));
        let split = split_pack(&pack, &cache).unwrap();
        assert!(!split.cached);
        assert_eq!(split.layers.len(), 3);

        // Every layer blob exists, holds the layer's own tar, and is named and
        // digested by that tar's content (not by the digest the pack happened to
        // record for it).
        for (layer, (_, expected)) in split.layers.iter().zip(layers.iter()) {
            let blob = layer.blob_path(&cache.blobs_dir());
            let bytes = std::fs::read(&blob).unwrap();
            assert_eq!(bytes.len() as u64, layer.blob_size);
            let (blob_digest, blob_size) = sha256_reader(std::io::Cursor::new(&bytes)).unwrap();
            assert_eq!(blob_digest, layer.blob_digest);
            assert_eq!(blob_size, layer.blob_size);
            let decoded: Vec<u8> = zstd::stream::read::Decoder::new(&bytes[..])
                .unwrap()
                .bytes()
                .collect::<std::io::Result<_>>()
                .unwrap();
            assert_eq!(&decoded, expected);
            assert_eq!(
                layer.diff_id,
                format!("sha256:{:x}", sha2::Sha256::digest(expected))
            );
        }

        // The base is a valid pack that names every layer and carries none.
        let base_manifest = read_manifest_from_sidecar(&split.base_path).unwrap();
        assert_eq!(base_manifest.assets.layers.len(), 3);
        for (entry, layer) in base_manifest.assets.layers.iter().zip(split.layers.iter()) {
            assert_eq!(entry.digest, layer.diff_id);
            assert_eq!(
                entry.path,
                format!("layers/{}.tar", diff_id_hex(&layer.diff_id).unwrap())
            );
            assert_eq!(entry.size, layer.uncompressed_size);
        }
        let members = assets_members(&split.base_path);
        assert!(
            members.iter().any(|member| member == "agent-rootfs.tar"),
            "the base keeps every non-layer member: {members:?}"
        );
        assert!(
            !members
                .iter()
                .any(|member| member.starts_with("layers/") && member.ends_with(".tar")),
            "the base must carry no layer tars: {members:?}"
        );
        // The base pack is complete on its own: its assets and manifest hash to
        // the checksum in its footer.
        assert!(crate::packer::verify_sidecar_checksum(
            &split.base_path,
            &read_footer_from_sidecar(&split.base_path).unwrap()
        )
        .unwrap());
    }

    /// A second split of the same pack reuses the cached base and blobs, so a
    /// republish costs no compression at all.
    #[test]
    fn a_second_split_is_a_cache_hit() {
        let temp = tempfile::tempdir().unwrap();
        let pack = temp.path().join("golden.smolmachine");
        let bytes = layer_tar("opt/file.txt", b"one");
        let digest = "ab".repeat(32);
        write_pack(&pack, &[(&digest, bytes)]);

        let cache = SplitCache::new(temp.path().join("cache"));
        let first = split_pack(&pack, &cache).unwrap();
        assert!(!first.cached);
        let second = split_pack(&pack, &cache).unwrap();
        assert!(second.cached);
        assert_eq!(first.base_digest, second.base_digest);
        assert_eq!(first.base_size, second.base_size);
        assert_eq!(first.layers, second.layers);
        assert!(!first.cached);

        // A truncated blob stops being a cache hit rather than shipping a
        // half-written layer.
        let blob = second.layers[0].blob_path(&cache.blobs_dir());
        let bytes = std::fs::read(&blob).unwrap();
        std::fs::write(&blob, &bytes[..bytes.len() / 2]).unwrap();
        let third = split_pack(&pack, &cache).unwrap();
        assert!(!third.cached);
        assert_eq!(std::fs::read(&blob).unwrap(), bytes);
    }

    /// Layers are handed to the base in the manifest's order, not the archive's,
    /// because that order is the overlay stack the guest reads.
    #[test]
    fn the_base_names_layers_in_manifest_order() {
        assert_eq!(
            reconcile_with_manifest(
                &{
                    let mut manifest = PackManifest::new(
                        "img".into(),
                        "sha256:0".into(),
                        "linux/amd64".into(),
                        "linux/amd64".into(),
                    );
                    manifest.assets.layers = vec![
                        LayerEntry {
                            digest: "sha256:aa".into(),
                            path: "layers/aa.tar".into(),
                            size: 1,
                        },
                        LayerEntry {
                            digest: "sha256:bb".into(),
                            path: "layers/bb.tar".into(),
                            size: 1,
                        },
                    ];
                    manifest
                },
                vec![
                    SplitLayer {
                        diff_id: format!("sha256:{}", "bb".repeat(32)),
                        archive_path: format!("layers/{}.tar", "bb".repeat(32)),
                        member_path: "layers/bb.tar".into(),
                        uncompressed_size: 1,
                        blob_digest: format!("sha256:{}", "cc".repeat(32)),
                        blob_size: 1,
                        blob_file: format!("{}.tar.zst", "bb".repeat(32)),
                    },
                    SplitLayer {
                        diff_id: format!("sha256:{}", "aa".repeat(32)),
                        archive_path: format!("layers/{}.tar", "aa".repeat(32)),
                        member_path: "layers/aa.tar".into(),
                        uncompressed_size: 1,
                        blob_digest: format!("sha256:{}", "dd".repeat(32)),
                        blob_size: 1,
                        blob_file: format!("{}.tar.zst", "aa".repeat(32)),
                    },
                ],
            )
            .unwrap()
            .iter()
            .map(|layer| layer.member_path.clone())
            .collect::<Vec<_>>(),
            vec!["layers/aa.tar".to_string(), "layers/bb.tar".to_string()]
        );
    }
}
