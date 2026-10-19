//! The streaming layer path: a host that unpacks a pack's layers itself unpacks
//! each `layers/<digest>.tar` member as it streams past, so the tar is never
//! written and read back, and the tree still only appears under its own name
//! once the whole archive and its digest have matched.
//!
//! Its own test binary: `set_host_layers_probe` is process-wide, and the other
//! integration tests must keep the decision of the engine that runs them.
#![cfg(target_os = "linux")]

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use smolvm_pack::assets::AssetCollector;
use smolvm_pack::extract::{extract_sidecar_shared, PARTIAL_DIR_SUFFIX};
use smolvm_pack::format::PackManifest;
use smolvm_pack::{read_footer_from_sidecar, sidecar_path_for, Packer};

fn layer_tar(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, filename, content).unwrap();
    builder.into_inner().unwrap()
}

/// A pack carrying one layer under the given digest name.
fn build_sidecar(dir: &Path, digest: &str, layer: &[u8]) -> PathBuf {
    fs::create_dir_all(dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    collector.add_layer(digest, layer).unwrap();
    let manifest = PackManifest::new(
        "test:latest".to_string(),
        digest.to_string(),
        "linux/x86_64".to_string(),
        "linux/x86_64".to_string(),
    );
    let output = dir.join("packed");
    Packer::new(manifest)
        .with_stub(&stub)
        .with_assets(collector)
        .pack(&output)
        .unwrap();
    sidecar_path_for(&output)
}

/// A host whose libkrun serves the override xattr — cpane's does
/// (`krun_add_virtiofs4` in the bundled libkrun.so).
fn host_that_unpacks_layers() {
    smolvm_pack::extract::set_host_layers_probe(|| true);
}

#[test]
fn a_streamed_layer_lands_without_staging_its_tar() {
    host_that_unpacks_layers();
    let tmp = tempfile::tempdir().unwrap();
    let layer = layer_tar("etc/streamed.conf", b"streamed layer bytes");
    let digest = format!("sha256:{:x}", Sha256::digest(&layer));
    let id = digest.trim_start_matches("sha256:").to_string();
    let sidecar = build_sidecar(&tmp.path().join("pack"), &digest, &layer);
    let footer = read_footer_from_sidecar(&sidecar).unwrap();

    let shared_root = tmp.path().join("_shared");
    let shared = extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();

    let layer_dir = shared.join("layers").join(&id);
    assert!(
        layer_dir.is_dir(),
        "the layer must land at layers/{id}/, got {:?}",
        fs::read_dir(shared.join("layers"))
            .map(|rd| rd.filter_map(|e| e.ok()).map(|e| e.file_name()).collect::<Vec<_>>())
    );
    assert!(
        !shared.join("layers").join(format!("{id}.tar")).exists(),
        "streaming must not stage the layer tar"
    );
    assert!(
        !shared
            .join("layers")
            .join(format!("{id}{PARTIAL_DIR_SUFFIX}"))
            .exists(),
        "the staging directory must be renamed, not left behind"
    );
    assert_eq!(
        fs::read(layer_dir.join("etc/streamed.conf")).unwrap(),
        b"streamed layer bytes"
    );

    // A warm hit reuses the entry and changes nothing.
    let again = extract_sidecar_shared(&sidecar, &shared_root, &footer, false).unwrap();
    assert_eq!(again, shared);
    assert!(layer_dir.join("etc/streamed.conf").is_file());
}

#[test]
fn a_streamed_layer_whose_name_lies_is_refused() {
    host_that_unpacks_layers();
    let tmp = tempfile::tempdir().unwrap();
    let layer = layer_tar("etc/streamed.conf", b"streamed layer bytes");
    let claimed = format!("sha256:{}", "0".repeat(64));
    let sidecar = build_sidecar(&tmp.path().join("pack"), &claimed, &layer);
    let footer = read_footer_from_sidecar(&sidecar).unwrap();

    let shared_root = tmp.path().join("_shared");
    let error = extract_sidecar_shared(&sidecar, &shared_root, &footer, false)
        .expect_err("a layer whose digest does not match its name must not be kept");
    assert!(
        error.to_string().contains("digest mismatch"),
        "unexpected error: {error}"
    );
    assert!(
        !shared_root
            .join(format!("{:08x}", footer.checksum))
            .join("layers")
            .join("0".repeat(64))
            .exists(),
        "nothing may be installed under the claimed name"
    );
}
