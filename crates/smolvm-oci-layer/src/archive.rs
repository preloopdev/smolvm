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
    read_archive_layers_for(archive, None)
}

/// [`read_archive_layers`] preferring the image manifest for `platform`
/// (`os/architecture`, e.g. `linux/arm64`) when the archive's index offers
/// several.
///
/// A `docker save` from a containerd-backed daemon can point `index.json` at a
/// multi-platform image index while packaging the blobs of only one platform,
/// so the first entry is not necessarily the one the archive carries. Selection
/// is by declared platform, then by which manifest's blobs are all present; an
/// archive that offers the wanted platform but lacks its blobs fails with an
/// error naming the platforms found rather than reading another architecture.
pub fn read_archive_layers_for(
    archive: &Path,
    platform: Option<&str>,
) -> std::io::Result<Vec<ArchiveLayer>> {
    let members = buffered_members(archive)?;
    if let Some(index) = members.buffered.get("index.json") {
        return oci_layout_layers(&members.buffered, &members.names, index, platform);
    }
    if let Some(manifest) = members.buffered.get("manifest.json") {
        return manifest_json_layers(&members.buffered, manifest);
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

/// Bytes the selected image's layers occupy once unpacked: the sum of their
/// uncompressed tar sizes, which is what a `--preserve-image-layers` import
/// writes onto the machine's storage disk.
///
/// Reads the archive's layer members through the same decompressing reader
/// [`for_each_archive_layer`] uses, so a compressed layer counts what it
/// expands to, and nothing is written to disk.
pub fn archive_layer_bytes(
    archive: &Path,
    platform: Option<&str>,
) -> std::io::Result<(u64, usize)> {
    let layers = read_archive_layers_for(archive, platform)?;
    let mut total = 0u64;
    for_each_archive_layer(archive, &layers, |_, _, reader| {
        total = total.saturating_add(std::io::copy(reader, &mut std::io::sink())?);
        Ok(())
    })?;
    Ok((total, layers.len()))
}

/// An archive's members: the JSON-sized ones buffered, and every name.
struct ArchiveMembers {
    /// Bytes of every JSON member, keyed by member path.
    buffered: HashMap<String, Vec<u8>>,
    /// Every regular member's path, so blob presence never depends on size.
    names: std::collections::HashSet<String>,
}

/// Every JSON member of the archive, keyed by member path, plus every member
/// name in it.
///
/// docker-save and OCI archives both put their manifests, index and config in
/// plain members; buffering by size and name keeps the layer payloads out of
/// memory without needing a second pass to find a blob the index names. Names
/// are recorded for *every* member, because whether an archive carries a layer
/// blob is a membership question and layer blobs are far larger than the buffer
/// cap.
fn buffered_members(archive: &Path) -> std::io::Result<ArchiveMembers> {
    let file = File::open(archive)?;
    let reader = decompress_layer_reader(file)?;
    let mut tar = tar::Archive::new(reader);
    let mut members = HashMap::new();
    let mut names = std::collections::HashSet::new();
    for entry in tar.entries()? {
        let mut entry = entry?;
        if entry.header().entry_type() != tar::EntryType::Regular {
            continue;
        }
        let path = entry.path()?.to_string_lossy().to_string();
        names.insert(path.clone());
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
    Ok(ArchiveMembers {
        buffered: members,
        names,
    })
}

/// One image manifest an OCI index offers, with the platform it declares.
struct ManifestChoice {
    digest: String,
    /// `os/architecture` as the index declares it, normalized for comparison;
    /// `None` when the descriptor carries no `platform`.
    platform: Option<String>,
}

/// Layers of an OCI layout archive: `index.json` → manifest blob → its layers
/// and config.
fn oci_layout_layers(
    members: &HashMap<String, Vec<u8>>,
    names: &std::collections::HashSet<String>,
    index: &[u8],
    want_platform: Option<&str>,
) -> std::io::Result<Vec<ArchiveLayer>> {
    let index: serde_json::Value = parse_json(index, "index.json")?;
    let manifest = select_image_manifest(members, names, &index, want_platform)?;
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
            declared_diff_id: diff_ids.as_ref().and_then(|ids| ids.get(position)).cloned(),
        });
    }
    if layers.is_empty() {
        return Err(invalid("the image manifest declares no layers"));
    }
    Ok(layers)
}

/// Choose the image manifest `index` names, for `want_platform` when given.
///
/// An index may describe several platforms, and a `docker save` from a
/// containerd-backed daemon can package the blobs of only one of them: its
/// `index.json` still points at the full multi-platform index, so taking the
/// first manifest downloads a platform the archive does not carry. A manifest
/// is a candidate only when its config and every layer blob are present; among
/// those, the one whose declared platform matches wins. If the wanted platform
/// is offered but its blobs are not in the archive, the error says so instead
/// of silently booting another architecture.
fn select_image_manifest(
    members: &HashMap<String, Vec<u8>>,
    names: &std::collections::HashSet<String>,
    index: &serde_json::Value,
    want_platform: Option<&str>,
) -> std::io::Result<serde_json::Value> {
    let mut candidates: Vec<ManifestChoice> = Vec::new();
    let mut offered: Vec<String> = Vec::new();
    collect_manifest_choices(members, index, 0, &mut candidates, &mut offered)?;
    if candidates.is_empty() {
        return Err(invalid("index.json names no image manifest digest"));
    }

    // A candidate is usable only when the archive actually carries everything
    // it names; docker save drops the blobs of platforms it did not save.
    let mut complete: Vec<(usize, serde_json::Value)> = Vec::new();
    for (position, candidate) in candidates.iter().enumerate() {
        let Some(bytes) = members.get(&blob_member(&candidate.digest)) else {
            continue;
        };
        let Ok(manifest) = parse_json(bytes, "image manifest blob") else {
            continue;
        };
        let has_layers = manifest
            .get("layers")
            .and_then(|value| value.as_array())
            .is_some_and(|layers| !layers.is_empty());
        if has_layers && manifest_blobs_present(names, &manifest) {
            complete.push((position, manifest));
        }
    }

    if let Some(want) = want_platform {
        if let Some((_, manifest)) = complete.iter().find(|(position, _)| {
            candidates[*position]
                .platform
                .as_deref()
                .is_some_and(|platform| platform_matches(platform, want))
        }) {
            return Ok(manifest.clone());
        }
        let wanted_is_offered = candidates.iter().any(|candidate| {
            candidate
                .platform
                .as_deref()
                .is_some_and(|platform| platform_matches(platform, want))
        });
        if wanted_is_offered {
            return Err(invalid(&format!(
                "index.json offers {} but the archive's blobs for {want} are missing; \
                 save the image for {want} (or pull a single-platform image) and retry",
                describe_platforms(&offered)
            )));
        }
    }

    if let Some((_, manifest)) = complete.into_iter().next() {
        return Ok(manifest);
    }
    Err(invalid(&format!(
        "index.json offers {} but no manifest it names has all of its blobs in the archive",
        describe_platforms(&offered)
    )))
}

/// Every image manifest an OCI index offers, descending one level into nested
/// indexes (the shape a containerd-backed `docker save` writes).
fn collect_manifest_choices(
    members: &HashMap<String, Vec<u8>>,
    index: &serde_json::Value,
    depth: usize,
    candidates: &mut Vec<ManifestChoice>,
    offered: &mut Vec<String>,
) -> std::io::Result<()> {
    let manifests = index
        .get("manifests")
        .and_then(|value| value.as_array())
        .ok_or_else(|| invalid("index.json has no manifests array"))?;
    for descriptor in manifests {
        let media_type = descriptor
            .get("mediaType")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let platform = descriptor.get("platform").and_then(|platform| {
            let os = platform.get("os").and_then(|value| value.as_str());
            let architecture = platform
                .get("architecture")
                .and_then(|value| value.as_str());
            match (os, architecture) {
                (Some(os), Some(architecture)) => Some(format!(
                    "{}/{}",
                    os.to_ascii_lowercase(),
                    normalize_architecture(architecture)
                )),
                (None, Some(architecture)) => {
                    Some(normalize_architecture(architecture).to_string())
                }
                _ => None,
            }
        });
        if let Some(platform) = &platform {
            if !offered.contains(platform) {
                offered.push(platform.clone());
            }
        }
        let digest = descriptor.get("digest").and_then(|value| value.as_str());
        // A nested index is one level above the manifests whose `layers` this
        // module needs; descend when its blob is in the archive.
        if media_type.contains("index") && depth < 2 {
            if let Some(digest) = digest {
                if let Some(bytes) = members.get(&blob_member(digest)) {
                    if let Ok(nested) = parse_json(bytes, "nested image index blob") {
                        collect_manifest_choices(members, &nested, depth + 1, candidates, offered)?;
                        continue;
                    }
                }
            }
            continue;
        }
        if let Some(digest) = digest {
            candidates.push(ManifestChoice {
                digest: digest.to_string(),
                platform,
            });
        }
    }
    Ok(())
}

/// Whether the archive holds the config and every layer a manifest names.
fn manifest_blobs_present(
    names: &std::collections::HashSet<String>,
    manifest: &serde_json::Value,
) -> bool {
    let config_present = manifest
        .get("config")
        .and_then(|config| config.get("digest"))
        .and_then(|value| value.as_str())
        .is_some_and(|digest| names.contains(&blob_member(digest)));
    if !config_present {
        return false;
    }
    manifest
        .get("layers")
        .and_then(|value| value.as_array())
        .is_some_and(|layers| {
            layers.iter().all(|layer| {
                layer
                    .get("digest")
                    .and_then(|value| value.as_str())
                    .is_some_and(|digest| names.contains(&blob_member(digest)))
            })
        })
}

/// OCI architecture names normalized to the labels descriptors use.
fn normalize_architecture(architecture: &str) -> &str {
    match architecture {
        "aarch64" => "arm64",
        "x86_64" | "x86-64" => "amd64",
        other => other,
    }
}

/// Whether a manifest's `os/architecture` (or bare architecture) is `want`
/// (`os/architecture`, normalized).
fn platform_matches(declared: &str, want: &str) -> bool {
    fn split(label: &str) -> (Option<&str>, &str) {
        match label.split_once('/') {
            Some((os, architecture)) => (
                (!os.is_empty()).then_some(os),
                normalize_architecture(architecture),
            ),
            None => (None, normalize_architecture(label)),
        }
    }
    let (declared_os, declared_arch) = split(declared);
    let (want_os, want_arch) = split(want);
    declared_arch == want_arch
        && match (declared_os, want_os) {
            (Some(declared_os), Some(want_os)) => declared_os.eq_ignore_ascii_case(want_os),
            _ => true,
        }
}

/// The platforms an index offers, for an error that names them.
fn describe_platforms(offered: &[String]) -> String {
    if offered.is_empty() {
        "no declared platform".to_string()
    } else {
        offered.join(", ")
    }
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
            declared_diff_id: diff_ids.as_ref().and_then(|ids| ids.get(position)).cloned(),
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
fn blob(members: &HashMap<String, Vec<u8>>, digest: &str, what: &str) -> std::io::Result<Vec<u8>> {
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
    use sha2::Digest;
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
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
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
        assert_eq!(
            layers[0].declared_diff_id.as_deref(),
            Some(diff_one.as_str())
        );
        assert_eq!(
            layers[1].media_type.as_deref(),
            Some("application/vnd.oci.image.layer.v1.tar+gzip")
        );
        assert_eq!(
            layers[1].declared_diff_id.as_deref(),
            Some(diff_two.as_str())
        );

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

    /// An OCI layout whose `index.json` points at a multi-platform image index.
    ///
    /// `order` is the descriptor order inside that index; blobs are written only
    /// for the platforms in `included`, which is what a `docker save` from a
    /// containerd-backed daemon produces for a multi-platform image: the index
    /// still names every platform, the archive carries one.
    fn multi_platform_oci_archive(
        path: &Path,
        order: &[&str],
        included: &[&str],
        layer_padding: usize,
    ) {
        use sha2::Digest;
        let digest = |bytes: &[u8]| format!("sha256:{:x}", sha2::Sha256::digest(bytes));
        let mut fixtures = std::collections::HashMap::new();
        let mut descriptors = Vec::new();
        for platform in order.iter().chain(included.iter()) {
            if fixtures.contains_key(*platform) {
                continue;
            }
            let (os, architecture) = platform.split_once('/').unwrap();
            let mut layer = format!("layer {platform}").into_bytes();
            // Padding stands in for a real layer blob larger than the JSON
            // buffer cap; membership must not depend on that cap.
            layer.resize(layer.len() + layer_padding, b'x');
            let layer_digest = digest(&layer);
            let config = serde_json::json!({
                "architecture": architecture,
                "os": os,
                "rootfs": { "type": "layers", "diff_ids": [layer_digest] },
            })
            .to_string();
            let config_digest = digest(config.as_bytes());
            let manifest = serde_json::json!({
                "schemaVersion": 2,
                "config": {
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": config_digest,
                    "size": config.len(),
                },
                "layers": [{
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": layer_digest,
                    "size": layer.len(),
                }],
            })
            .to_string();
            let manifest_digest = digest(manifest.as_bytes());
            descriptors.push(serde_json::json!({
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "digest": manifest_digest,
                "size": manifest.len(),
                "platform": { "os": os, "architecture": architecture },
            }));
            fixtures.insert(
                *platform,
                (
                    manifest_digest,
                    manifest.into_bytes(),
                    config_digest,
                    config.into_bytes(),
                    layer_digest,
                    layer,
                ),
            );
        }
        // `descriptors` now follows `order` first, then any extra included
        // platform; keep only the ordered ones.
        descriptors.retain(|descriptor| {
            let platform = format!(
                "{}/{}",
                descriptor["platform"]["os"].as_str().unwrap(),
                descriptor["platform"]["architecture"].as_str().unwrap()
            );
            order.contains(&platform.as_str())
        });
        let index = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": descriptors,
        })
        .to_string();
        let index_digest = digest(index.as_bytes());
        let top = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [{
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "digest": index_digest,
                "size": index.len(),
            }],
        })
        .to_string();

        let file = File::create(path).unwrap();
        let mut tar = tar::Builder::new(file);
        let mut members: Vec<(String, Vec<u8>)> = vec![
            (
                "oci-layout".to_string(),
                br#"{"imageLayoutVersion":"1.0.0"}"#.to_vec(),
            ),
            ("index.json".to_string(), top.into_bytes()),
            (
                format!("blobs/sha256/{}", &index_digest[7..]),
                index.into_bytes(),
            ),
        ];
        for platform in included {
            let Some((manifest_digest, manifest, config_digest, config, layer_digest, layer)) =
                fixtures.get(*platform)
            else {
                continue;
            };
            members.extend([
                (
                    format!("blobs/sha256/{}", &manifest_digest[7..]),
                    manifest.clone(),
                ),
                (
                    format!("blobs/sha256/{}", &config_digest[7..]),
                    config.clone(),
                ),
                (
                    format!("blobs/sha256/{}", &layer_digest[7..]),
                    layer.clone(),
                ),
            ]);
        }
        for (name, bytes) in members {
            tar.append_data(&mut header(bytes.len() as u64), name, bytes.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();
    }

    #[test]
    fn a_multi_platform_index_selects_the_platform_the_archive_carries() {
        let expected = format!("sha256:{:x}", sha2::Sha256::digest(b"layer linux/arm64"));
        for order in [
            ["linux/amd64", "linux/arm64"],
            ["linux/arm64", "linux/amd64"],
        ] {
            let tmp = tempfile::tempdir().unwrap();
            let archive = tmp.path().join("multi.tar");
            multi_platform_oci_archive(&archive, &order, &["linux/arm64"], 0);

            // Whatever order the index lists, selection follows the blobs the
            // archive actually carries, not the first entry.
            let layers = read_archive_layers_for(&archive, Some("linux/arm64")).unwrap();
            assert_eq!(layers.len(), 1, "order {order:?}");
            assert_eq!(
                layers[0].declared_diff_id.as_deref(),
                Some(expected.as_str())
            );
            // Without a requested platform the same manifest is the only
            // complete one.
            let default = read_archive_layers(&archive).unwrap();
            assert_eq!(default, layers, "order {order:?}");
            // Aarch64 is the same platform under its other OCI spelling.
            let normalized = read_archive_layers_for(&archive, Some("linux/aarch64")).unwrap();
            assert_eq!(normalized, layers);
        }
    }

    #[test]
    fn a_layer_blob_larger_than_the_json_buffer_still_counts_as_present() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("multi.tar");
        multi_platform_oci_archive(
            &archive,
            &["linux/amd64", "linux/arm64"],
            &["linux/arm64"],
            5 << 20,
        );
        let layers = read_archive_layers_for(&archive, Some("linux/arm64")).unwrap();
        assert_eq!(layers.len(), 1);
        assert!(layers[0].declared_diff_id.is_some());
    }

    #[test]
    fn a_multi_platform_index_that_lacks_the_requested_platform_names_it() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("multi.tar");
        multi_platform_oci_archive(
            &archive,
            &["linux/amd64", "linux/arm64"],
            &["linux/arm64"],
            0,
        );
        let error = read_archive_layers_for(&archive, Some("linux/amd64")).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let message = error.to_string();
        assert!(message.contains("linux/amd64"), "{message}");
        assert!(message.contains("linux/arm64"), "{message}");
    }

    #[test]
    fn a_multi_platform_index_with_every_platform_present_prefers_the_requested_one() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("multi.tar");
        multi_platform_oci_archive(
            &archive,
            &["linux/amd64", "linux/arm64"],
            &["linux/amd64", "linux/arm64"],
            0,
        );
        let layers = read_archive_layers_for(&archive, Some("linux/arm64")).unwrap();
        assert_eq!(
            layers[0].declared_diff_id,
            Some(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(b"layer linux/arm64")
            ))
        );
        let amd64 = read_archive_layers_for(&archive, Some("linux/amd64")).unwrap();
        assert_eq!(
            amd64[0].declared_diff_id,
            Some(format!(
                "sha256:{:x}",
                sha2::Sha256::digest(b"layer linux/amd64")
            ))
        );
    }

    #[test]
    fn an_oci_layout_reports_the_unpacked_bytes_of_the_selected_platform() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = tmp.path().join("multi.tar");
        multi_platform_oci_archive(
            &archive,
            &["linux/amd64", "linux/arm64"],
            &["linux/arm64"],
            0,
        );
        let (bytes, layers) = archive_layer_bytes(&archive, Some("linux/arm64")).unwrap();
        assert_eq!(bytes, b"layer linux/arm64".len() as u64);
        assert_eq!(layers, 1);
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
