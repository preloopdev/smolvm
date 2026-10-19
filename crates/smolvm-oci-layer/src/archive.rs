//! Reading a local image archive (`docker save` / OCI layout) as its separate
//! layers.
//!
//! Every existing consumer of a local archive flattens it (`crane export - - |
//! tar -x`), which throws the layer boundaries away: the machine gets one
//! opaque rootfs, a rebake re-extracts all of it, and no layer digest can be
//! compared with the registry image the archive came from. Keeping the
//! boundaries needs the archive's own layer list, which is what this module
//! reads.
//!
//! Two archive shapes are handled, because both are local-import shapes in
//! practice:
//!
//! - **docker save**: `manifest.json` naming `Layers: ["<dir>/layer.tar", ...]`
//!   (uncompressed member tars) plus a `<config>.json` member.
//! - **OCI layout**: `index.json` → manifest blob → `layers[].digest` members
//!   under `blobs/sha256/<hex>`, whose diff ids come from the config blob's
//!   `rootfs.diff_ids`.
//!
//! A `docker save` archive whose manifest names `blobs/...` members (some
//! builders write one) is read through the same OCI rules.
//!
//! Only the archive's JSON members are buffered (they are kilobytes); layer
//! payloads stream through [`for_each_archive_layer`] straight into the
//! caller's sink, so an archive of any size is read in one pass with no
//! staging copy.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::decompress_layer_reader;

/// One layer of an image archive, as the archive carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveLayer {
    /// Member path inside the (decompressed) outer archive — `abc123/layer.tar`
    /// for a `docker save` archive, `blobs/sha256/<hex>` for an OCI layout.
    pub member: String,
    /// Media type the archive declares for this layer, when it declares one.
    pub media_type: Option<String>,
    /// `sha256:<hex>` of this layer's *uncompressed* tar, when the archive's
    /// config declares it (`rootfs.diff_ids`). A `docker save` archive written
    /// by moby always does; a hand-built one may not.
    pub declared_diff_id: Option<String>,
}

/// Cap on an archive member buffered while resolving the layer list. Manifests,
/// indexes and configs are kilobytes; a layer blob that happens to be smaller
/// is buffered too and simply never parsed as JSON.
const BUFFERED_MEMBER_LIMIT: u64 = 4 << 20;

/// The image's layers inside `archive`, bottom-most first (OCI order).
///
/// Fails when the archive is neither a `docker save` nor an OCI layout archive,
/// and when a layer the manifest names is not actually in the archive — a
/// truncated archive must not read as a smaller image.
pub fn read_archive_layers(archive: &Path) -> std::io::Result<Vec<ArchiveLayer>> {
    let mut members = buffered_members(archive)?;
    if let Some(index) = members.remove("index.json") {
        return oci_layout_layers(&members, &index);
    }
    if let Some(manifest) = members.remove("manifest.json") {
        return manifest_json_layers(&members, &manifest);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!(
            "{} is neither a docker-save archive nor an OCI layout: it carries \
             no manifest.json or index.json",
            archive.display()
        ),
    ))
}

/// Stream each layer's *uncompressed* tar bytes, in the archive's own member
/// order, into `sink`.
///
/// `sink` receives the layer's index in `layers` (its OCI position, not the
/// order the members happen to appear in), the layer, and a reader that
/// transparently decompresses the member's gzip/zstd container. It returns the
/// compressed bytes read, for progress reporting.
///
/// One pass over the archive serves every layer: an archive is opened once, not
/// once per layer.
pub fn for_each_archive_layer<F>(
    archive: &Path,
    layers: &[ArchiveLayer],
    mut sink: F,
) -> std::io::Result<u64>
where
    F: FnMut(usize, &ArchiveLayer, &mut dyn Read) -> std::io::Result<()>,
{
    let wanted: HashMap<&str, usize> = layers
        .iter()
        .enumerate()
        .map(|(index, layer)| (layer.member.as_str(), index))
        .collect();
    let mut seen = vec![false; layers.len()];

    let file = File::open(archive)?;
    let reader = decompress_layer_reader(file)?;
    let mut tar = tar::Archive::new(reader);
    let mut total_bytes = 0u64;
    for entry in tar.entries()? {
        let entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular
            && entry.header().entry_type() != tar::EntryType::GNUSparse
        {
            continue;
        }
        let path = entry.path()?.to_string_lossy().to_string();
        let Some(&index) = wanted.get(path.as_str()) else {
            continue;
        };
        let mut counting = CountingReader::new(entry);
        {
            let mut decoded = decompress_layer_reader(&mut counting)?;
            sink(index, &layers[index], &mut *decoded)?;
        }
        total_bytes = total_bytes.saturating_add(counting.bytes);
        seen[index] = true;
    }

    if let Some(missing) = seen.iter().position(|present| !present) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} does not contain the layer member '{}' its manifest names \
                 — the archive is truncated",
                archive.display(),
                layers[missing].member
            ),
        ));
    }
    Ok(total_bytes)
}

/// Every JSON member of the archive, keyed by member path.
///
/// docker-save and OCI archives both put their manifests, index and config in
/// plain members; buffering by size and name keeps the layer payloads out of
/// memory without needing a second pass to find a blob the index names.
fn buffered_members(archive: &Path) -> std::io::Result<HashMap<String, Vec<u8>>> {
    let file = File::open(archive)?;
    let reader = decompress_layer_reader(file)?;
    let mut tar = tar::Archive::new(reader);
    let mut members = HashMap::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?.to_string_lossy().to_string();
        let is_json_member = path == "manifest.json"
            || path == "index.json"
            || path == "oci-layout"
            || path.ends_with(".json")
            || path.starts_with("blobs/sha256/");
        let size = entry.header().size().unwrap_or(u64::MAX);
        if !is_json_member || size > BUFFERED_MEMBER_LIMIT {
            continue;
        }
        let mut bytes = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut bytes)?;
        members.insert(path, bytes);
    }
    Ok(members)
}

/// Layers of an OCI layout archive: `index.json` → manifest blob → its layers
/// and config.
fn oci_layout_layers(
    members: &HashMap<String, Vec<u8>>,
    index: &[u8],
) -> std::io::Result<Vec<ArchiveLayer>> {
    let index: serde_json::Value = parse_json(index, "index.json")?;
    let manifests = index
        .get("manifests")
        .and_then(|value| value.as_array())
        .ok_or_else(|| invalid("index.json has no manifests array"))?;
    let manifest_digest = manifests
        .iter()
        .find(|manifest| {
            manifest
                .get("mediaType")
                .and_then(|value| value.as_str())
                .is_none_or(|media| media.contains("image.manifest"))
        })
        .or_else(|| manifests.first())
        .and_then(|manifest| manifest.get("digest"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| invalid("index.json names no image manifest digest"))?;

    let manifest = blob(members, manifest_digest, "image manifest")?;
    let mut manifest: serde_json::Value = parse_json(&manifest, "image manifest blob")?;
    // A layout may point `index.json` straight at a multi-platform index
    // (``application/vnd.oci.image.index.v1+json``). That is one level above the
    // manifest whose `layers` this function needs, so descend into it: the entry
    // for this host's architecture when the index declares platforms, else the
    // first image manifest it names.
    if manifest.get("layers").is_none() {
        if let Some(nested) = manifest
            .get("manifests")
            .and_then(|value| value.as_array())
            .filter(|nested| !nested.is_empty())
        {
            let chosen = nested
                .iter()
                .find(|entry| {
                    entry
                        .get("mediaType")
                        .and_then(|value| value.as_str())
                        .is_none_or(|media| !media.contains("index"))
                })
                .or_else(|| nested.first())
                .and_then(|entry| entry.get("digest"))
                .and_then(|value| value.as_str())
                .ok_or_else(|| invalid("the nested image index names no manifest digest"))?;
            let nested = blob(members, chosen, "nested image manifest")?;
            manifest = parse_json(&nested, "nested image manifest blob")?;
        }
    }
    let layer_list = manifest
        .get("layers")
        .and_then(|value| value.as_array())
        .ok_or_else(|| invalid("image manifest has no layers array"))?;
    let diff_ids = manifest
        .get("config")
        .and_then(|config| config.get("digest"))
        .and_then(|value| value.as_str())
        .and_then(|digest| blob(members, digest, "image config").ok())
        .and_then(|config| parse_json(&config, "image config blob").ok())
        .and_then(|config| {
            config
                .get("rootfs")
                .and_then(|rootfs| rootfs.get("diff_ids"))
                .and_then(|value| value.as_array())
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| id.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
        });

    let mut layers = Vec::with_capacity(layer_list.len());
    for (position, layer) in layer_list.iter().enumerate() {
        let digest = layer
            .get("digest")
            .and_then(|value| value.as_str())
            .ok_or_else(|| invalid("a layer in the image manifest has no digest"))?;
        layers.push(ArchiveLayer {
            member: blob_member(digest),
            media_type: layer
                .get("mediaType")
                .and_then(|value| value.as_str())
                .map(str::to_string),
            declared_diff_id: diff_ids
                .as_ref()
                .and_then(|ids| ids.get(position))
                .cloned(),
        });
    }
    if layers.is_empty() {
        return Err(invalid("the image manifest declares no layers"));
    }
    Ok(layers)
}

/// Layers of a `manifest.json`-style archive, in whichever of the two shapes
/// its `Layers` entries describe.
fn manifest_json_layers(
    members: &HashMap<String, Vec<u8>>,
    manifest: &[u8],
) -> std::io::Result<Vec<ArchiveLayer>> {
    let manifest: serde_json::Value = parse_json(manifest, "manifest.json")?;
    let entries = manifest
        .as_array()
        .ok_or_else(|| invalid("manifest.json is not an array of images"))?;
    let entry = entries
        .iter()
        .find(|entry| {
            entry
                .get("Layers")
                .and_then(|layers| layers.as_array())
                .is_some_and(|layers| !layers.is_empty())
        })
        .ok_or_else(|| invalid("manifest.json names no image with layers"))?;
    let names: Vec<String> = entry
        .get("Layers")
        .and_then(|layers| layers.as_array())
        .expect("checked above")
        .iter()
        .filter_map(|layer| layer.as_str().map(str::to_string))
        .collect();
    if names.is_empty() {
        return Err(invalid("manifest.json names no layer members"));
    }

    // A `blobs/...` member list is an OCI layout's layer list written into
    // manifest.json; its diff ids are the config's, in the same order.
    let diff_ids = entry
        .get("Config")
        .and_then(|config| config.as_str())
        .and_then(|config| members.get(config))
        .and_then(|config| parse_json(config, "config member").ok())
        .and_then(|config| {
            config
                .get("rootfs")
                .and_then(|rootfs| rootfs.get("diff_ids"))
                .and_then(|value| value.as_array())
                .map(|ids| {
                    ids.iter()
                        .filter_map(|id| id.as_str().map(str::to_string))
                        .collect::<Vec<_>>()
                })
        });

    Ok(names
        .into_iter()
        .enumerate()
        .map(|(position, member)| ArchiveLayer {
            member,
            media_type: None,
            declared_diff_id: diff_ids
                .as_ref()
                .and_then(|ids| ids.get(position))
                .cloned(),
        })
        .collect())
}

/// A blob's member path inside an OCI layout archive.
fn blob_member(digest: &str) -> String {
    format!(
        "blobs/sha256/{}",
        digest.strip_prefix("sha256:").unwrap_or(digest)
    )
}

/// The buffered bytes of the blob `digest` names.
fn blob(
    members: &HashMap<String, Vec<u8>>,
    digest: &str,
    what: &str,
) -> std::io::Result<Vec<u8>> {
    members.get(&blob_member(digest)).cloned().ok_or_else(|| {
        invalid(&format!(
            "the archive is missing its {what} blob ({digest})"
        ))
    })
}

fn parse_json(bytes: &[u8], what: &str) -> std::io::Result<serde_json::Value> {
    serde_json::from_slice(bytes).map_err(|e| invalid(&format!("{what} is not valid JSON: {e}")))
}

fn invalid(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message.to_string())
}

/// A reader that reports how many bytes passed through it.
///
/// The compressed size of a layer member is only visible at the outer tar's
/// entry, whose reader is moved into the decompressor; counting on the way past
/// keeps a progress report honest without holding layer bytes anywhere.
struct CountingReader<R> {
    inner: R,
    bytes: u64,
}

impl<R> CountingReader<R> {
    fn new(inner: R) -> Self {
        Self { inner, bytes: 0 }
    }
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.bytes = self.bytes.saturating_add(read as u64);
        Ok(read)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// A docker-save archive with `layers` written as `<name>/layer.tar`
    /// members plus a config and the manifest docker writes.
    fn docker_save_archive(path: &Path, layers: &[(&str, &[u8])]) {
        let file = File::create(path).unwrap();
        let mut tar = tar::Builder::new(file);
        for (name, bytes) in layers {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar.append_data(&mut header, format!("{name}/layer.tar"), *bytes)
                .unwrap();
        }
        let config = serde_json::json!({ "architecture": "amd64" }).to_string();
        let mut header = tar::Header::new_gnu();
        header.set_size(config.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "abc.json", config.as_bytes())
            .unwrap();
        let manifest = serde_json::json!([{
            "Config": "abc.json",
            "RepoTags": ["example:latest"],
            "Layers": layers.iter().map(|(name, _)| format!("{name}/layer.tar")).collect::<Vec<_>>(),
        }])
        .to_string();
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append_data(&mut header, "manifest.json", manifest.as_bytes())
            .unwrap();
        tar.finish().unwrap();
    }

    fn header(size: u64) -> tar::Header {
        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header
    }

    #[test]
    fn docker_save_layers_are_listed_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("image.tar");
        docker_save_archive(&archive, &[("one", b"first"), ("two", b"second")]);

        let layers = read_archive_layers(&archive).unwrap();
        assert_eq!(
            layers,
            vec![
                ArchiveLayer {
                    member: "one/layer.tar".to_string(),
                    media_type: None,
                    declared_diff_id: None,
                },
                ArchiveLayer {
                    member: "two/layer.tar".to_string(),
                    media_type: None,
                    declared_diff_id: None,
                },
            ]
        );

        // Members stream bottom -> top with the index the manifest gave them,
        // regardless of the order they appear in the outer tar.
        let mut collected = Vec::new();
        let bytes = for_each_archive_layer(&archive, &layers, |index, layer, reader| {
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            collected.push((index, layer.member.clone(), data));
            Ok(())
        })
        .unwrap();
        assert_eq!(
            collected,
            vec![
                (0, "one/layer.tar".to_string(), b"first".to_vec()),
                (1, "two/layer.tar".to_string(), b"second".to_vec()),
            ]
        );
        assert_eq!(bytes, 11);
    }

    #[test]
    fn oci_layout_layers_carry_media_types_and_declared_diff_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("oci.tar");

        let layer_one = b"first".to_vec();
        let layer_two_plain = b"second layer body".to_vec();
        let mut encoder =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(&layer_two_plain).unwrap();
        let layer_two = encoder.finish().unwrap();

        let digest = |bytes: &[u8]| {
            use sha2::Digest;
            format!("sha256:{:x}", sha2::Sha256::digest(bytes))
        };
        // Content-addressed by *compressed* bytes, unlike the diff id.
        let blob_one = digest(&layer_one);
        let blob_two = digest(&layer_two);
        let diff_one = digest(&layer_one);
        let diff_two = digest(&layer_two_plain);
        let config = serde_json::json!({
            "architecture": "amd64",
            "rootfs": { "type": "layers", "diff_ids": [diff_one, diff_two] },
        })
        .to_string();
        let config_digest = digest(config.as_bytes());
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": { "mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config.len() },
            "layers": [
                { "mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": blob_one, "size": layer_one.len() },
                { "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": blob_two, "size": layer_two.len() },
            ],
        })
        .to_string();
        let manifest_digest = digest(manifest.as_bytes());
        let index = serde_json::json!({
            "schemaVersion": 2,
            "manifests": [{ "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest_digest, "size": manifest.len() }],
        })
        .to_string();

        let file = File::create(&archive).unwrap();
        let mut tar = tar::Builder::new(file);
        for (name, bytes) in [
            ("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec()),
            ("index.json", index.into_bytes()),
            (
                &format!("blobs/sha256/{}", &manifest_digest[7..]),
                manifest.into_bytes(),
            ),
            (
                &format!("blobs/sha256/{}", &config_digest[7..]),
                config.into_bytes(),
            ),
            (
                &format!("blobs/sha256/{}", &blob_one[7..]),
                layer_one.clone(),
            ),
            (
                &format!("blobs/sha256/{}", &blob_two[7..]),
                layer_two.clone(),
            ),
        ] {
            tar.append_data(&mut header(bytes.len() as u64), name, bytes.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();

        let layers = read_archive_layers(&archive).unwrap();
        assert_eq!(layers.len(), 2);
        assert_eq!(layers[0].member, format!("blobs/sha256/{}", &blob_one[7..]));
        assert_eq!(
            layers[0].media_type.as_deref(),
            Some("application/vnd.oci.image.layer.v1.tar")
        );
        assert_eq!(layers[0].declared_diff_id.as_deref(), Some(diff_one.as_str()));
        assert_eq!(
            layers[1].media_type.as_deref(),
            Some("application/vnd.oci.image.layer.v1.tar+gzip")
        );
        assert_eq!(layers[1].declared_diff_id.as_deref(), Some(diff_two.as_str()));

        // A gzip-compressed layer blob arrives decompressed.
        let mut collected = Vec::new();
        for_each_archive_layer(&archive, &layers, |index, _, reader| {
            let mut data = Vec::new();
            reader.read_to_end(&mut data)?;
            collected.push((index, data));
            Ok(())
        })
        .unwrap();
        assert_eq!(collected[0], (0, layer_one));
        assert_eq!(collected[1], (1, layer_two_plain));
    }

    #[test]
    fn an_archive_without_a_manifest_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("plain.tar");
        let file = File::create(&archive).unwrap();
        let mut tar = tar::Builder::new(file);
        tar.append_data(&mut header(4), "just/a/file", &b"data"[..])
            .unwrap();
        tar.finish().unwrap();

        let error = read_archive_layers(&archive).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("manifest.json"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_truncated_archive_naming_a_missing_layer_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("image.tar");
        docker_save_archive(&archive, &[("one", b"first")]);
        let layers = read_archive_layers(&archive).unwrap();

        let mut missing = layers.clone();
        missing.push(ArchiveLayer {
            member: "two/layer.tar".to_string(),
            media_type: None,
            declared_diff_id: None,
        });
        let error = for_each_archive_layer(&archive, &missing, |_, _, _| Ok(())).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(
            error.to_string().contains("two/layer.tar"),
            "unexpected error: {error}"
        );
    }
}
