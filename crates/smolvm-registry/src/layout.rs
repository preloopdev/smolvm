//! What an OCI manifest describes, and what to do when it describes something
//! this build cannot consume.
//!
//! Two artifact shapes exist in the wild:
//!
//! * **single blob** (`application/vnd.smolmachines.smolmachine.v1`): the whole
//!   `.smolmachine` as one layer, exactly what `pack push` published before
//!   split artifacts; and
//! * **split** ([`SPLIT_ARTIFACT_TYPE`]): a base pack plus one blob per OCI
//!   layer, each annotated with the layer's uncompressed digest.
//!
//! Anything else fails closed. A manifest is untrusted input and the layer blobs
//! it points at are tens of GB; "pick the first descriptor whose media type we
//! half recognize" is how a client ends up downloading a blob it cannot use,
//! or mis-stacking layers it cannot verify. The error names the artifact type
//! and media types it saw, so an operator can tell "upgrade smolvm" from "this
//! is not a smolmachine at all".

use crate::{
    OciDescriptor, OciManifest, RegistryError, Result, LAYER_DIFF_ID_ANNOTATION, LAYER_MEDIA_TYPE,
    SPLIT_ARTIFACT_TYPE, SPLIT_BASE_MEDIA_TYPE, SPLIT_LAYER_MEDIA_TYPE,
};

/// One layer blob of a split artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitLayerDescriptor {
    /// Media type, always [`SPLIT_LAYER_MEDIA_TYPE`] for a well-formed manifest.
    pub media_type: String,
    /// `sha256:<hex>` of the **compressed** blob — what the registry is asked
    /// for, and what the transfer is verified against.
    pub digest: String,
    /// Size of the compressed blob in bytes.
    pub size: u64,
    /// `sha256:<hex>` of the **uncompressed** tar (OCI `diff_id`) — the identity
    /// a consumer's layer store is keyed by.
    pub diff_id: String,
}

/// A manifest this build can consume.
#[derive(Debug, Clone)]
pub enum ArtifactLayout {
    /// The whole `.smolmachine` is one blob.
    Single { layer: OciDescriptor },
    /// A base pack plus its layers, bottom→top.
    Split {
        base: OciDescriptor,
        layers: Vec<SplitLayerDescriptor>,
    },
}

impl ArtifactLayout {
    /// The blob a pull installs as the `.smolmachine` itself.
    pub fn pack_descriptor(&self) -> &OciDescriptor {
        match self {
            Self::Single { layer } => layer,
            Self::Split { base, .. } => base,
        }
    }

    /// The uncompressed layer identities this artifact installs, bottom→top.
    pub fn layer_diff_ids(&self) -> Vec<String> {
        match self {
            Self::Single { .. } => Vec::new(),
            Self::Split { layers, .. } => {
                layers.iter().map(|layer| layer.diff_id.clone()).collect()
            }
        }
    }
}

/// Classify a manifest, refusing anything this build cannot consume completely.
pub fn classify(manifest: &OciManifest) -> Result<ArtifactLayout> {
    match manifest.artifact_type.as_deref() {
        Some(SPLIT_ARTIFACT_TYPE) => classify_split(manifest),
        Some(LAYER_MEDIA_TYPE) | None => classify_single(manifest),
        Some(other) => Err(RegistryError::InvalidManifest(format!(
            "this artifact declares artifact type `{other}`, which this smolvm does not know how \
             to consume. Its layers are: {}. Upgrade smolvm, or pull the artifact with a client \
             that understands that type.",
            layer_types(manifest)
        ))),
    }
}

/// The single-blob shape: exactly one smolmachine layer and nothing else.
fn classify_single(manifest: &OciManifest) -> Result<ArtifactLayout> {
    let matches: Vec<&OciDescriptor> = manifest
        .layers
        .iter()
        .filter(|layer| layer.media_type == LAYER_MEDIA_TYPE)
        .collect();
    match matches.as_slice() {
        [layer] if manifest.layers.len() == 1 => Ok(ArtifactLayout::Single {
            layer: (*layer).clone(),
        }),
        [] => Err(RegistryError::InvalidManifest(format!(
            "no layer with media type {LAYER_MEDIA_TYPE} in manifest; layer types: {}",
            layer_types(manifest)
        ))),
        // A layer list longer than the one smolmachine layer is a shape this
        // build does not know: pulling the first match would silently drop
        // whatever else the manifest points at.
        _ => Err(RegistryError::InvalidManifest(format!(
            "this artifact carries {} layer(s) but declares no split artifact type; this smolvm \
             knows the single-blob layout (one {LAYER_MEDIA_TYPE} layer) and {SPLIT_ARTIFACT_TYPE}. \
             Layer types: {}",
            manifest.layers.len(),
            layer_types(manifest)
        ))),
    }
}

/// The split shape: one base pack plus one descriptor per layer, every layer
/// annotated with its uncompressed digest.
fn classify_split(manifest: &OciManifest) -> Result<ArtifactLayout> {
    let bases: Vec<usize> = manifest
        .layers
        .iter()
        .enumerate()
        .filter(|(_, layer)| layer.media_type == SPLIT_BASE_MEDIA_TYPE)
        .map(|(index, _)| index)
        .collect();
    let base_index = match bases.as_slice() {
        [index] => *index,
        [] => {
            return Err(RegistryError::InvalidManifest(format!(
                "this split artifact has no {SPLIT_BASE_MEDIA_TYPE} base blob; layer types: {}",
                layer_types(manifest)
            )))
        }
        _ => {
            return Err(RegistryError::InvalidManifest(
                "this split artifact has more than one base blob".into(),
            ))
        }
    };
    let base = manifest.layers[base_index].clone();

    let mut layers = Vec::new();
    let mut unknown = Vec::new();
    for (index, descriptor) in manifest.layers.iter().enumerate() {
        if index == base_index {
            continue;
        }
        match descriptor.media_type.as_str() {
            SPLIT_LAYER_MEDIA_TYPE => layers.push(split_layer(descriptor)?),
            other => unknown.push(other.to_string()),
        }
    }
    if !unknown.is_empty() {
        return Err(RegistryError::InvalidManifest(format!(
            "this split artifact carries layer types this smolvm does not know: {}; layer types: {}",
            unknown.join(", "),
            layer_types(manifest)
        )));
    }
    if layers.is_empty() {
        return Err(RegistryError::InvalidManifest(
            "this split artifact carries no layers".into(),
        ));
    }
    Ok(ArtifactLayout::Split { base, layers })
}

/// One split layer descriptor, with its digest identity checked.
fn split_layer(descriptor: &OciDescriptor) -> Result<SplitLayerDescriptor> {
    crate::client::validate_digest(&descriptor.digest)?;
    let diff_id = descriptor
        .annotations
        .as_ref()
        .and_then(|annotations| annotations.get(LAYER_DIFF_ID_ANNOTATION))
        .ok_or_else(|| {
            RegistryError::InvalidManifest(format!(
                "split layer {} carries no {LAYER_DIFF_ID_ANNOTATION} annotation, so it has no \
                 identity to install under",
                descriptor.digest
            ))
        })?;
    let normalized = smolvm_pack::layer_store::normalize_diff_id(diff_id).map_err(|_| {
        RegistryError::InvalidManifest(format!(
            "split layer {} declares `{diff_id}` as its uncompressed digest, which is not a \
             sha256 digest",
            descriptor.digest
        ))
    })?;
    Ok(SplitLayerDescriptor {
        media_type: descriptor.media_type.clone(),
        digest: descriptor.digest.clone(),
        size: descriptor.size,
        diff_id: normalized,
    })
}

/// The media types a manifest's layers declare, for an error message.
fn layer_types(manifest: &OciManifest) -> String {
    if manifest.layers.is_empty() {
        return "none".to_string();
    }
    manifest
        .layers
        .iter()
        .map(|layer| layer.media_type.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn manifest(artifact_type: Option<&str>, layers: Vec<OciDescriptor>) -> OciManifest {
        OciManifest {
            schema_version: 2,
            media_type: crate::MANIFEST_MEDIA_TYPE.to_string(),
            artifact_type: artifact_type.map(str::to_string),
            config: OciDescriptor::new(crate::CONFIG_MEDIA_TYPE, "sha256:cfg", 2),
            layers,
            annotations: None,
        }
    }

    fn layer_annotated(digest: &str, diff_id: &str) -> OciDescriptor {
        OciDescriptor {
            annotations: Some(BTreeMap::from([(
                LAYER_DIFF_ID_ANNOTATION.to_string(),
                diff_id.to_string(),
            )])),
            ..OciDescriptor::new(SPLIT_LAYER_MEDIA_TYPE, digest, 10)
        }
    }

    fn hex(byte: &str) -> String {
        byte.repeat(32)
    }

    /// A pre-split manifest is the single-blob layout, unchanged.
    #[test]
    fn a_single_blob_manifest_classifies_as_single() {
        let layout = classify(&manifest(
            Some(LAYER_MEDIA_TYPE),
            vec![OciDescriptor::new(LAYER_MEDIA_TYPE, "sha256:aa", 7)],
        ))
        .unwrap();
        match layout {
            ArtifactLayout::Single { layer } => {
                assert_eq!(layer.digest, "sha256:aa");
                assert_eq!(layer.size, 7);
            }
            other => panic!("expected a single blob, got {other:?}"),
        }
    }

    /// A split manifest resolves to its base plus one layer per descriptor,
    /// carrying each layer's uncompressed digest.
    #[test]
    fn a_split_manifest_classifies_with_layer_identities() {
        let manifest = manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![
                OciDescriptor::new(SPLIT_BASE_MEDIA_TYPE, "sha256:base", 99),
                layer_annotated("sha256:b1", &format!("sha256:{}", hex("11"))),
                layer_annotated("sha256:b2", &hex("22")),
            ],
        );
        let layout = classify(&manifest).unwrap();
        assert_eq!(layout.pack_descriptor().digest, "sha256:base");
        assert_eq!(
            layout.layer_diff_ids(),
            vec![
                format!("sha256:{}", hex("11")),
                format!("sha256:{}", hex("22")),
            ]
        );
    }

    /// The split pull installs layers in the order the manifest lists them: the
    /// order is the overlay stack, so reversing it would mis-stack the image.
    #[test]
    fn split_layer_order_is_the_manifest_order() {
        let first = format!("sha256:{}", hex("aa"));
        let second = format!("sha256:{}", hex("bb"));
        let layout = classify(&manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![
                OciDescriptor::new(SPLIT_BASE_MEDIA_TYPE, "sha256:base", 99),
                layer_annotated("sha256:b1", &first),
                layer_annotated("sha256:b2", &second),
            ],
        ))
        .unwrap();
        assert_eq!(layout.layer_diff_ids(), vec![first, second]);
    }

    /// An artifact type this build does not know fails closed with the types it
    /// saw, instead of taking the first descriptor that looks familiar.
    #[test]
    fn an_unknown_artifact_type_fails_closed() {
        let error = classify(&manifest(
            Some("application/vnd.smolmachines.smolmachine.v3+something"),
            vec![OciDescriptor::new(
                "application/vnd.smolmachines.smolmachine.v3",
                "sha256:aa",
                1,
            )],
        ))
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("v3+something"), "{message}");
        assert!(message.contains("smolmachine.v3"), "{message}");
    }

    /// A split layer without a diff_id annotation cannot be installed under any
    /// identity, so the artifact is refused rather than guessed at.
    #[test]
    fn a_split_layer_without_identity_fails_closed() {
        let error = classify(&manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![
                OciDescriptor::new(SPLIT_BASE_MEDIA_TYPE, "sha256:base", 99),
                OciDescriptor::new(SPLIT_LAYER_MEDIA_TYPE, "sha256:b1", 10),
            ],
        ))
        .unwrap_err();
        assert!(
            error.to_string().contains(LAYER_DIFF_ID_ANNOTATION),
            "{error}"
        );
    }

    /// A diff_id that is not a digest would name a path outside the store, so it
    /// is refused before any path is built from it.
    #[test]
    fn a_split_layer_with_a_malformed_identity_fails_closed() {
        let error = classify(&manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![
                OciDescriptor::new(SPLIT_BASE_MEDIA_TYPE, "sha256:base", 99),
                layer_annotated("sha256:b1", "sha256:../../etc/passwd"),
            ],
        ))
        .unwrap_err();
        assert!(error.to_string().contains("not a sha256 digest"), "{error}");
    }

    /// A split manifest with no base pack is unusable: there is nothing to boot
    /// from, and the layers alone are not a pack.
    #[test]
    fn a_split_manifest_without_a_base_fails_closed() {
        let error = classify(&manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![layer_annotated("sha256:b1", &hex("11"))],
        ))
        .unwrap_err();
        assert!(error.to_string().contains(SPLIT_BASE_MEDIA_TYPE), "{error}");
    }

    /// A manifest with an unknown layer type inside a split artifact is refused:
    /// ignoring the descriptor would ship a pack with a missing layer.
    #[test]
    fn an_unknown_split_layer_type_fails_closed() {
        let error = classify(&manifest(
            Some(SPLIT_ARTIFACT_TYPE),
            vec![
                OciDescriptor::new(SPLIT_BASE_MEDIA_TYPE, "sha256:base", 99),
                layer_annotated("sha256:b1", &hex("11")),
                OciDescriptor::new("application/vnd.example.layer", "sha256:b2", 3),
            ],
        ))
        .unwrap_err();
        assert!(error.to_string().contains("application/vnd.example.layer"), "{error}");
    }
}
