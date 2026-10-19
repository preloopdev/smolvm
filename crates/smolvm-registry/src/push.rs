//! Push a `.smolmachine` artifact to an OCI registry.
//!
//! Two shapes are published:
//!
//! * [`push`] — the whole pack as one blob, the historical layout; and
//! * [`push_split`] — the pack's layers as one blob each, plus a base pack that
//!   names them.
//!
//! Both flows end the same way: a content-addressed per-platform manifest, a
//! platform tag beside it, and an image index at the reference so a tag fans out
//! by platform.

use crate::client::RegistryClient;
use crate::{
    OciDescriptor, OciIndex, OciIndexManifest, OciManifest, OciPlatform, Result, CONFIG_MEDIA_TYPE,
    INDEX_MEDIA_TYPE, LAYER_DIFF_ID_ANNOTATION, LAYER_MEDIA_TYPE, MANIFEST_MEDIA_TYPE,
    SPLIT_ARTIFACT_TYPE, SPLIT_BASE_MEDIA_TYPE, SPLIT_LAYER_MEDIA_TYPE,
};
use sha2::{Digest, Sha256};
use smolvm_pack::split::{split_pack, SplitCache};
use std::path::Path;
use tokio::io::AsyncReadExt;

/// Result of a successful push.
#[derive(Debug)]
pub struct PushResult {
    /// Digest of the uploaded sidecar blob.
    pub layer_digest: String,
    /// Size of the sidecar blob in bytes.
    pub layer_size: u64,
    /// Digest of the OCI manifest.
    pub manifest_digest: String,
    /// Host platform this artifact targets (e.g. `linux/amd64`).
    pub platform: String,
    /// The per-platform tag the manifest was also tagged under (e.g.
    /// `latest-linux-amd64`).
    pub platform_tag: String,
}

/// One layer of a split push, and what happened to its blob.
#[derive(Debug, Clone)]
pub struct PushedLayer {
    /// `sha256:<hex>` of the uncompressed tar (the layer's identity).
    pub diff_id: String,
    /// `sha256:<hex>` of the compressed blob.
    pub blob_digest: String,
    /// Size of the compressed blob in bytes.
    pub blob_size: u64,
    /// Whether this push uploaded the blob (false: the registry already had it).
    pub uploaded: bool,
}

/// Result of a successful split push.
#[derive(Debug)]
pub struct SplitPushResult {
    /// Digest of the base pack blob.
    pub base_digest: String,
    /// Size of the base pack blob in bytes.
    pub base_size: u64,
    /// Whether this push uploaded the base pack (false: already present).
    pub base_uploaded: bool,
    /// Layers in stacking order, bottom→top.
    pub layers: Vec<PushedLayer>,
    /// Digest of the OCI manifest.
    pub manifest_digest: String,
    /// Host platform this artifact targets (e.g. `linux/amd64`).
    pub platform: String,
    /// The per-platform tag the manifest was also tagged under.
    pub platform_tag: String,
}

impl SplitPushResult {
    /// Bytes this push actually sent, layer blobs included.
    pub fn bytes_uploaded(&self) -> u64 {
        let base = if self.base_uploaded {
            self.base_size
        } else {
            0
        };
        base + self
            .layers
            .iter()
            .filter(|layer| layer.uploaded)
            .map(|layer| layer.blob_size)
            .sum::<u64>()
    }

    /// How many layer blobs this push uploaded.
    pub fn layers_uploaded(&self) -> usize {
        self.layers.iter().filter(|layer| layer.uploaded).count()
    }

    /// How many layer blobs the registry already had.
    pub fn layers_skipped(&self) -> usize {
        self.layers.iter().filter(|layer| !layer.uploaded).count()
    }
}

/// Push a `.smolmachine` sidecar to the registry as one blob.
///
/// Uses a two-pass approach: pass 1 computes the SHA256 digest by streaming
/// through the file, pass 2 streams the file to the registry. The OS page
/// cache makes the second read essentially free.
pub async fn push(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    smolmachine_path: &Path,
) -> Result<PushResult> {
    // 1. Compute SHA256 digest (pass 1: stream through hasher, no full-file buffer).
    let file = tokio::fs::File::open(smolmachine_path).await?;
    let file_meta = file.metadata().await?;
    let layer_size = file_meta.len();

    let mut reader = tokio::io::BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 256 * 1024];
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let layer_digest = format!("sha256:{}", hex::encode(hasher.finalize()));

    tracing::info!(
        path = %smolmachine_path.display(),
        size = layer_size,
        digest = %layer_digest,
        "computed sidecar digest"
    );

    // 2. Parse PackManifest from the footer to use as OCI config.
    let manifest = smolvm_pack::read_manifest_from_sidecar(smolmachine_path)?;
    let config_json = serde_json::to_vec_pretty(&manifest)?;

    // 3. Upload the sidecar as the layer blob: a SINGLE streamed request first,
    // falling back to uniform chunked PATCHes when that is rejected.
    //
    // Monolithic is preferred because it lets the registry's storage driver
    // choose its own multipart part sizes — historically the safest shape for
    // S3-compatible backends (R2 rejects unequal non-trailing parts). But some
    // stacks cannot take a large blob in one request at all: proxies cap the
    // body (413), and a registry may deadline the body read (zot cuts the
    // connection ~60 s in, so a blob slower than that can never arrive whole).
    // `push_blob_file` handles the fallback; its chunks are uniform with only
    // the final one short, which S3-compatible backends accept.
    tracing::info!("uploading sidecar blob...");
    client
        .push_blob_file(repo, &layer_digest, smolmachine_path)
        .await?;

    // 4. Upload config blob (small, buffered is fine).
    tracing::info!("uploading config blob...");
    let config_digest = client.push_blob(repo, &config_json).await?;
    let config_size = config_json.len() as u64;

    // 5. Build OCI Image Manifest. `artifactType` + annotations make the
    // manifest a well-behaved OCI 1.1 artifact: any generic client (oras,
    // crane) can pull and classify it, while container runtimes still refuse
    // to run it because the layer media type is not an image layer.
    let annotations = std::collections::BTreeMap::from([
        (
            "org.opencontainers.image.title".to_string(),
            format!("{repo}:{reference}"),
        ),
        (
            "com.smolmachines.pack.mode".to_string(),
            format!("{:?}", manifest.mode).to_lowercase(),
        ),
    ]);
    let oci_manifest = OciManifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        artifact_type: Some(LAYER_MEDIA_TYPE.to_string()),
        config: OciDescriptor::new(CONFIG_MEDIA_TYPE, config_digest, config_size),
        layers: vec![OciDescriptor::new(
            LAYER_MEDIA_TYPE,
            layer_digest.clone(),
            layer_size,
        )],
        annotations: Some(annotations),
    };

    let platform = OciPlatform::parse(&manifest.platform);
    let manifest_digest =
        publish_manifest_and_index(client, repo, reference, &oci_manifest, &platform).await?;
    let platform_tag = platform_tag(reference, &platform);

    tracing::info!(digest = %manifest_digest, layer_size, "push complete");

    Ok(PushResult {
        layer_digest,
        layer_size,
        manifest_digest,
        platform: platform.label(),
        platform_tag,
    })
}

/// Push a `.smolmachine` as a base pack plus one blob per layer.
///
/// The pack is taken apart (see [`smolvm_pack::split`]) and every blob is
/// uploaded only if the registry does not already have it: a republish that
/// changed nothing sends no layer bytes at all, and a republish that changed one
/// layer sends that layer. Blobs are content-addressed by the compressed bytes,
/// so "already present" is decided by a `HEAD` against the digest, never by a
/// name that could drift.
pub async fn push_split(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    smolmachine_path: &Path,
    cache: &SplitCache,
) -> Result<SplitPushResult> {
    // The split itself is a synchronous pass over the pack (decompress, compress
    // the layers, re-pack the base), so it runs off the async runtime. The cache
    // is cloned into the task and kept here, because the blob files it produced
    // are read from it after the split returns.
    let pack = smolmachine_path.to_path_buf();
    let blobs_dir = cache.blobs_dir();
    let task_cache = cache.clone();
    let split = tokio::task::spawn_blocking(move || split_pack(&pack, &task_cache))
        .await
        .map_err(|error| crate::RegistryError::InvalidManifest(format!("split task: {error}")))??;
    tracing::info!(
        base = %split.base_digest,
        base_size = split.base_size,
        layers = split.layers.len(),
        cached = split.cached,
        "split the pack into a base and per-layer blobs"
    );

    // The base's own manifest is the artifact's config: it is what a consumer
    // reads to learn the layer order and the run parameters, exactly as the
    // single-blob artifact's config is.
    let base_manifest = smolvm_pack::read_manifest_from_sidecar(&split.base_path)?;
    let config_json = serde_json::to_vec_pretty(&base_manifest)?;

    let base_uploaded = !client.blob_exists(repo, &split.base_digest).await?;
    if base_uploaded {
        tracing::info!(digest = %split.base_digest, size = split.base_size, "uploading base pack...");
        client
            .push_blob_file(repo, &split.base_digest, &split.base_path)
            .await?;
    } else {
        tracing::info!(digest = %split.base_digest, "base pack already in the registry");
    }

    let mut pushed = Vec::with_capacity(split.layers.len());
    for layer in &split.layers {
        let uploaded = !client.blob_exists(repo, &layer.blob_digest).await?;
        if uploaded {
            let blob = layer.blob_path(&blobs_dir);
            tracing::info!(
                diff_id = %layer.diff_id,
                digest = %layer.blob_digest,
                size = layer.blob_size,
                "uploading layer blob..."
            );
            client
                .push_blob_file(repo, &layer.blob_digest, &blob)
                .await?;
        } else {
            tracing::info!(
                diff_id = %layer.diff_id,
                digest = %layer.blob_digest,
                "layer blob already in the registry"
            );
        }
        pushed.push(PushedLayer {
            diff_id: layer.diff_id.clone(),
            blob_digest: layer.blob_digest.clone(),
            blob_size: layer.blob_size,
            uploaded,
        });
    }

    let config_digest = client.push_blob(repo, &config_json).await?;
    let config_size = config_json.len() as u64;

    let annotations = std::collections::BTreeMap::from([
        (
            "org.opencontainers.image.title".to_string(),
            format!("{repo}:{reference}"),
        ),
        (
            "com.smolmachines.pack.mode".to_string(),
            format!("{:?}", base_manifest.mode).to_lowercase(),
        ),
        (
            "com.smolmachines.split.layers".to_string(),
            pushed.len().to_string(),
        ),
    ]);

    let mut descriptors = Vec::with_capacity(pushed.len() + 1);
    descriptors.push(OciDescriptor::new(
        SPLIT_BASE_MEDIA_TYPE,
        split.base_digest.clone(),
        split.base_size,
    ));
    for layer in &split.layers {
        descriptors.push(OciDescriptor {
            annotations: Some(std::collections::BTreeMap::from([(
                LAYER_DIFF_ID_ANNOTATION.to_string(),
                layer.diff_id.clone(),
            )])),
            ..OciDescriptor::new(
                SPLIT_LAYER_MEDIA_TYPE,
                layer.blob_digest.clone(),
                layer.blob_size,
            )
        });
    }

    let oci_manifest = OciManifest {
        schema_version: 2,
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        artifact_type: Some(SPLIT_ARTIFACT_TYPE.to_string()),
        config: OciDescriptor::new(CONFIG_MEDIA_TYPE, config_digest, config_size),
        layers: descriptors,
        annotations: Some(annotations),
    };

    let platform = OciPlatform::parse(&base_manifest.platform);
    let manifest_digest =
        publish_manifest_and_index(client, repo, reference, &oci_manifest, &platform).await?;
    let platform_tag = platform_tag(reference, &platform);

    tracing::info!(
        digest = %manifest_digest,
        layers_uploaded = pushed.iter().filter(|layer| layer.uploaded).count(),
        "split push complete"
    );

    Ok(SplitPushResult {
        base_digest: split.base_digest,
        base_size: split.base_size,
        base_uploaded,
        layers: pushed,
        manifest_digest,
        platform: platform.label(),
        platform_tag,
    })
}

/// Publish a manifest content-addressably, tag it per platform, and update the
/// reference's image index.
///
/// The index entry is keyed on the **guest** platform (`linux/<arch>`), not the
/// builder's host platform: the `.smolmachine` is selected on pull by guest arch
/// (`client.rs` matches `os == linux && arch == host arch`), and an artifact
/// pushed from macOS would otherwise index as `darwin/arm64`, which pull could
/// never select. On Linux builders the two are the same, so this is a no-op
/// there.
async fn publish_manifest_and_index(
    client: &RegistryClient,
    repo: &str,
    reference: &str,
    oci_manifest: &OciManifest,
    platform: &OciPlatform,
) -> Result<String> {
    let manifest_json = serde_json::to_vec_pretty(oci_manifest)?;
    let manifest_size = manifest_json.len() as u64;
    let manifest_digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest_json)));

    let platform_tag = platform_tag(reference, platform);
    tracing::info!(digest = %manifest_digest, platform = %platform.label(), "uploading manifest...");
    client
        .put_manifest(repo, &manifest_digest, &manifest_json)
        .await?;
    client
        .put_manifest(repo, &platform_tag, &manifest_json)
        .await?;

    // Merge with any existing index (replacing this platform's entry); a legacy
    // single-manifest tag is replaced by a fresh index.
    let entry = OciIndexManifest {
        media_type: MANIFEST_MEDIA_TYPE.to_string(),
        digest: manifest_digest.clone(),
        size: manifest_size,
        platform: Some(platform.clone()),
    };
    let mut manifests = match client.get_manifest_raw(repo, reference).await {
        Ok((bytes, ct)) if ct.contains(INDEX_MEDIA_TYPE) => {
            serde_json::from_slice::<OciIndex>(&bytes)
                .map(|index| index.manifests)
                .unwrap_or_default()
        }
        _ => Vec::new(),
    };
    manifests.retain(|entry| entry.platform.as_ref() != Some(platform));
    manifests.push(entry);
    let index = OciIndex {
        schema_version: 2,
        media_type: INDEX_MEDIA_TYPE.to_string(),
        manifests,
    };
    let index_json = serde_json::to_vec_pretty(&index)?;
    tracing::info!(reference = %reference, platforms = index.manifests.len(), "updating image index...");
    client.put_manifest(repo, reference, &index_json).await?;

    Ok(manifest_digest)
}

/// The per-platform tag a manifest is also published under.
fn platform_tag(reference: &str, platform: &OciPlatform) -> String {
    format!("{reference}-{}-{}", platform.os, platform.architecture)
}
