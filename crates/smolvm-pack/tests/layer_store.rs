//! The digest-keyed shared layer store: layers arrive as streams, land under
//! their diff_id, and a pack that carries a layer the store already has costs a
//! fan-out of hard links instead of another extraction.
//!
//! The store's own tests run on every Unix host an install can reach: an
//! install is just a zstd tar with a digest, and on macOS it lands in the
//! store's case-sensitive volume. The pack-level tests are Linux-only: that is
//! the one platform whose entries and store share a filesystem and an owner,
//! which is what makes linking a layer in sound rather than a copy.
#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use smolvm_pack::extract::{
    collect_layer_store, install_layer_from_stream, layer_present, shared_layers_dir,
    PARTIAL_DIR_SUFFIX, STREAMED_LAYERS_FILE,
};
#[cfg(target_os = "linux")]
use smolvm_pack::extract::{collect_layer_store_with, force_detach_layers_volume};

/// The staging name a layer is unpacked under before it takes its own.
fn staging_dir(layer_dir: &Path) -> PathBuf {
    layer_dir.with_file_name(format!(
        "{}{PARTIAL_DIR_SUFFIX}",
        layer_dir.file_name().unwrap().to_string_lossy()
    ))
}

fn scratch(prefix: &str) -> tempfile::TempDir {
    // macOS mounts the store's case-sensitive volume at a directory inside
    // this one, and only allows a mount point on the boot volume.
    let root = if cfg!(target_os = "macos") {
        std::env::temp_dir()
    } else {
        Path::new(env!("CARGO_TARGET_TMPDIR")).to_path_buf()
    };
    fs::create_dir_all(&root).unwrap();
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(root)
        .unwrap()
}

fn layer_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (filename, content) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, filename, *content)
            .unwrap();
    }
    builder.into_inner().unwrap()
}

/// A compressed layer blob and the diff_id of what it decompresses to: exactly
/// what a registry serves and annotates.
fn layer_blob(entries: &[(&str, &[u8])]) -> (Vec<u8>, String) {
    let tar = layer_tar(entries);
    let id = format!("{:x}", Sha256::digest(&tar));
    let blob = zstd::stream::encode_all(&tar[..], 3).unwrap();
    (blob, id)
}

#[test]
fn an_installed_layer_is_present_and_a_second_install_is_a_noop() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, id) = layer_blob(&[("etc/installed.conf", b"installed")]);

    assert!(!layer_present(&shared_root, &id));
    install_layer_from_stream(&shared_root, &id, &blob[..]).unwrap();
    assert!(layer_present(&shared_root, &id));

    let layer_dir = shared_layers_dir(&shared_root).unwrap().join(&id);
    let file = layer_dir.join("etc/installed.conf");
    assert_eq!(fs::read(&file).unwrap(), b"installed");
    assert!(
        !staging_dir(&layer_dir).exists(),
        "the staging directory must be renamed, not left behind"
    );
    let before = fs::metadata(&file).unwrap();

    // Installing a layer the store already holds is a no-op — the whole point
    // of a resumed pull re-doing only what it was interrupted on.
    install_layer_from_stream(&shared_root, &id, &blob[..]).unwrap();
    let after = fs::metadata(&file).unwrap();
    assert_eq!(
        before.modified().unwrap(),
        after.modified().unwrap(),
        "a second install must not rewrite a complete layer"
    );
    assert_eq!(before.len(), after.len());
}

#[test]
fn an_install_whose_digest_does_not_match_keeps_nothing() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, real_id) = layer_blob(&[("etc/layer.conf", b"real bytes")]);
    let claimed = "0".repeat(64);
    assert_ne!(claimed, real_id);

    let error = install_layer_from_stream(&shared_root, &claimed, &blob[..])
        .expect_err("a blob that does not hash to its diff_id must be refused");
    assert!(
        error.to_string().contains("digest mismatch"),
        "unexpected error: {error}"
    );
    assert!(!layer_present(&shared_root, &claimed));
    let layers = shared_layers_dir(&shared_root).unwrap();
    assert!(
        !layers.join(&claimed).exists(),
        "nothing may be installed under the claimed name"
    );
    assert!(
        !layers
            .join(format!("{claimed}{PARTIAL_DIR_SUFFIX}"))
            .exists(),
        "a refused layer must leave no staging directory"
    );
}

#[test]
fn a_resumed_pull_redoes_only_the_layer_that_was_interrupted() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (first_blob, first_id) = layer_blob(&[("etc/first.conf", b"first layer")]);
    let (second_blob, second_id) = layer_blob(&[("etc/second.conf", b"second layer")]);

    install_layer_from_stream(&shared_root, &first_id, &first_blob[..]).unwrap();
    let finished = shared_layers_dir(&shared_root)
        .unwrap()
        .join(&first_id)
        .join("etc/first.conf");
    let before = fs::metadata(&finished).unwrap();

    // A transfer cut short: the stream ends inside the compressed body, so the
    // layer never reaches its final name.
    let truncated = &second_blob[..second_blob.len() / 2];
    let error = install_layer_from_stream(&shared_root, &second_id, truncated)
        .expect_err("a truncated layer stream must not install");
    assert!(!error.to_string().is_empty());
    assert!(!layer_present(&shared_root, &second_id));

    // The layer that finished is untouched, and only the interrupted one is
    // fetched again.
    let after = fs::metadata(&finished).unwrap();
    assert_eq!(before.modified().unwrap(), after.modified().unwrap());
    install_layer_from_stream(&shared_root, &second_id, &second_blob[..]).unwrap();
    assert!(layer_present(&shared_root, &first_id));
    assert!(layer_present(&shared_root, &second_id));
}

#[test]
fn an_interrupted_install_is_replaced_not_resumed_into() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, id) = layer_blob(&[("etc/retry.conf", b"retried")]);
    let layers = shared_layers_dir(&shared_root).unwrap();
    fs::create_dir_all(&layers).unwrap();
    // What a kill mid-install leaves: a staging tree with junk in it.
    let staging = layers.join(format!("{id}{PARTIAL_DIR_SUFFIX}"));
    fs::create_dir_all(staging.join("etc")).unwrap();
    fs::write(staging.join("etc/retry.conf"), b"half written").unwrap();

    install_layer_from_stream(&shared_root, &id, &blob[..]).unwrap();
    assert_eq!(
        fs::read(layers.join(&id).join("etc/retry.conf")).unwrap(),
        b"retried",
        "the retried install must not inherit the interrupted tree"
    );
    assert!(
        !staging.exists(),
        "the stale staging tree must be discarded"
    );
}

#[test]
fn a_layer_id_that_is_not_a_digest_is_refused() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, _id) = layer_blob(&[("etc/layer.conf", b"bytes")]);
    for hostile in ["../../../etc/passwd", "/etc", "layers/../..", "", "zz"] {
        let error = install_layer_from_stream(&shared_root, hostile, &blob[..])
            .expect_err("a non-digest id must be refused before it becomes a path");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::InvalidInput,
            "for {hostile}"
        );
        assert!(!layer_present(&shared_root, hostile));
    }
}

/// An extracted pack entry that names a layer: its `layers/streamed-layers`
/// record is what a collection reads to know the layer is in use.
fn write_entry_record(shared_root: &Path, entry: &str, ids: &[&str]) {
    let layers = shared_root.join(entry).join("layers");
    fs::create_dir_all(&layers).unwrap();
    fs::write(
        layers.join(STREAMED_LAYERS_FILE),
        ids.iter().map(|id| format!("{id}\n")).collect::<String>(),
    )
    .unwrap();
}

/// A collection keeps what an entry still names and takes everything else: the
/// layers whose packs are gone, and the staging trees of interrupted installs.
#[test]
fn a_collection_keeps_referenced_layers_and_removes_the_rest() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (kept_blob, kept_id) = layer_blob(&[("etc/kept.conf", b"kept")]);
    let (unused_blob, unused_id) = layer_blob(&[("etc/unused.conf", b"unused")]);
    install_layer_from_stream(&shared_root, &kept_id, &kept_blob[..]).unwrap();
    install_layer_from_stream(&shared_root, &unused_id, &unused_blob[..]).unwrap();
    // The pulls are done and their holds released by an entry that names the
    // kept layer alone; the unused one's hold is gone with its process below.
    write_entry_record(&shared_root, "0123abcd", &[&kept_id]);
    fs::remove_dir_all(shared_root.join(".layer-holds")).unwrap();

    // An interrupted install of a layer nobody names.
    let layers = shared_layers_dir(&shared_root).unwrap();
    let orphan_partial = layers.join(format!("{}{PARTIAL_DIR_SUFFIX}", "b".repeat(64)));
    fs::create_dir_all(&orphan_partial).unwrap();

    let report = collect_layer_store(&shared_root, false).unwrap();
    assert_eq!(report.layers_removed, 1, "exactly the unreferenced layer");
    assert_eq!(report.partials_discarded, 1, "the orphaned staging tree");
    assert!(layer_present(&shared_root, &kept_id));
    assert!(!layer_present(&shared_root, &unused_id));
    assert!(!orphan_partial.exists());
}

/// A pulled layer that no entry names yet is protected by the pull's hold: a
/// collection that runs before the extraction that references it must keep it.
/// Once the holding process is gone the hold goes with it, and the layer is
/// collectable again.
#[test]
fn a_pulled_layer_is_held_until_its_process_is_gone() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, id) = layer_blob(&[("etc/pulled.conf", b"pulled")]);
    install_layer_from_stream(&shared_root, &id, &blob[..]).unwrap();

    let report = collect_layer_store(&shared_root, false).unwrap();
    assert_eq!(report.layers_removed, 0, "a pull's layer must survive");
    assert!(layer_present(&shared_root, &id));

    // A hold left behind by a process that has since died protects nothing.
    let dead = 2_147_483_000u32; // above any live pid on this host
    fs::write(
        shared_root
            .join(".layer-holds")
            .join(format!("{dead}.{id}")),
        b"",
    )
    .unwrap();
    // Our own hold is still there, so drop it to show the dead one alone.
    fs::remove_file(
        shared_root
            .join(".layer-holds")
            .join(format!("{}.{id}", std::process::id())),
    )
    .unwrap();
    let report = collect_layer_store(&shared_root, false).unwrap();
    assert_eq!(
        report.layers_removed, 1,
        "a dead holder's layer is collectable"
    );
    assert!(!layer_present(&shared_root, &id));
    assert!(
        !shared_root
            .join(".layer-holds")
            .join(format!("{dead}.{id}"))
            .exists(),
        "the dead holder's hold must be reclaimed"
    );
}

/// The race the lock exists for: an install in flight must not be collected.
///
/// An extraction writes the entry's reference to a layer *after* the layer
/// lands, and a pull may have no entry yet at all, so "nothing references it"
/// is true for a layer that is being installed right now. Collecting it then
/// would delete the tree out from under the rename.
#[test]
fn a_collection_never_takes_a_layer_an_install_is_writing() {
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let (blob, id) = layer_blob(&[("etc/racy.conf", b"racy bytes")]);

    let (chunks, stream) = std::sync::mpsc::channel();
    let (consumed, consumed_by_install) = std::sync::mpsc::channel();
    let installing_root = shared_root.clone();
    let installing_id = id.clone();
    let install = std::thread::spawn(move || {
        install_layer_from_stream(
            &installing_root,
            &installing_id,
            HeldStream {
                chunks: stream,
                current: Vec::new(),
                offset: 0,
                consumed,
                consumed_bytes: 0,
            },
        )
    });

    // First half: the install has taken the store's lock and is unpacking.
    chunks.send(blob[..blob.len() / 2].to_vec()).unwrap();
    consumed_by_install
        .recv_timeout(std::time::Duration::from_secs(10))
        .expect("the install must read the stream it was handed");

    // A collection started now must wait for the install, not run beside it.
    let collector_root = shared_root.clone();
    let collector = std::thread::spawn(move || collect_layer_store(&collector_root, false));
    std::thread::sleep(std::time::Duration::from_millis(250));
    assert!(
        !collector.is_finished(),
        "the collection ran while an install held the store's lock"
    );

    chunks.send(blob[blob.len() / 2..].to_vec()).unwrap();
    drop(chunks);
    install
        .join()
        .unwrap()
        .expect("the held install must succeed");

    // The collection runs after the install and finds the layer unnamed, but the
    // install's hold is alive in this process, so the layer survives.
    let report = collector.join().unwrap().unwrap();
    assert_eq!(
        report.layers_removed, 0,
        "a pulled layer must survive: {report:?}"
    );
    assert!(
        layer_present(&shared_root, &id),
        "the install must be intact"
    );
}

/// A stream whose bytes the test releases: an install handed one of these holds
/// the store's lock, and everything the install does, for as long as the stream
/// is unfinished.
struct HeldStream {
    chunks: std::sync::mpsc::Receiver<Vec<u8>>,
    current: Vec<u8>,
    offset: usize,
    /// Signalled as bytes are consumed, so the test knows the install is past
    /// the lock and inside the unpack.
    consumed: std::sync::mpsc::Sender<usize>,
    consumed_bytes: usize,
}

impl std::io::Read for HeldStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.current.len() {
            match self.chunks.recv() {
                Ok(chunk) => {
                    self.current = chunk;
                    self.offset = 0;
                }
                Err(_) => return Ok(0),
            }
        }
        let take = (self.current.len() - self.offset).min(buf.len());
        buf[..take].copy_from_slice(&self.current[self.offset..self.offset + take]);
        self.offset += take;
        self.consumed_bytes += take;
        let _ = self.consumed.send(self.consumed_bytes);
        Ok(take)
    }
}

/// Dry runs describe the same selection and remove nothing; a real run reports
/// the bytes it frees, which exclude any file an entry still links.
///
/// Linux-only: the entry links the store's file, and on macOS the store lives
/// in a different volume than the entry, so there is no link to test.
#[cfg(target_os = "linux")]
#[test]
fn a_collection_reports_the_bytes_it_frees_and_dry_runs_change_nothing() {
    use std::os::unix::fs::MetadataExt;
    let tmp = scratch("layer-store-");
    let shared_root = tmp.path().join("_shared");
    let shared_bytes = vec![7u8; 64 * 1024];
    let unique_bytes = vec![9u8; 256 * 1024];
    let (shared_blob, shared_id) = layer_blob(&[("data/shared.bin", &shared_bytes)]);
    let (unique_blob, unique_id) = layer_blob(&[("data/unique.bin", &unique_bytes)]);
    install_layer_from_stream(&shared_root, &shared_id, &shared_blob[..]).unwrap();
    install_layer_from_stream(&shared_root, &unique_id, &unique_blob[..]).unwrap();
    fs::remove_dir_all(shared_root.join(".layer-holds")).unwrap();

    // An entry that links the shared layer's file, as a fan-out does, and names
    // only that layer.
    let entry_layers = shared_root.join("0123abcd").join("layers");
    fs::create_dir_all(entry_layers.join(&shared_id).join("data")).unwrap();
    fs::hard_link(
        shared_layers_dir(&shared_root)
            .unwrap()
            .join(&shared_id)
            .join("data/shared.bin"),
        entry_layers.join(&shared_id).join("data/shared.bin"),
    )
    .unwrap();
    write_entry_record(&shared_root, "0123abcd", &[&shared_id]);

    let dry = collect_layer_store_with(&shared_root, false, true).unwrap();
    assert_eq!(dry.layers_removed, 1, "the unique layer would go");
    assert!(
        layer_present(&shared_root, &unique_id),
        "a dry run must not remove anything"
    );

    let report = collect_layer_store(&shared_root, false).unwrap();
    assert_eq!(report.layers_removed, 1);
    assert_eq!(report.bytes_reclaimed, dry.bytes_reclaimed);
    assert!(
        report.bytes_reclaimed >= unique_bytes.len() as u64,
        "the unique layer's data is freed: {report:?}"
    );
    let shared_file = shared_layers_dir(&shared_root)
        .unwrap()
        .join(&shared_id)
        .join("data/shared.bin");
    assert_eq!(
        fs::metadata(&shared_file).unwrap().nlink(),
        2,
        "the shared file is still linked from the entry, so it frees nothing"
    );
    assert_eq!(
        fs::read(entry_layers.join(&shared_id).join("data/shared.bin")).unwrap(),
        shared_bytes,
        "the entry's copy survives the collection"
    );
    assert!(!layer_present(&shared_root, &unique_id));
}

/// The digest a layer is known by: the sha256 of its uncompressed tar, which is
/// the diff_id a pack manifest names it by.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn digest_of(layer: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(layer))
}

/// [`digest_of`] as a bare, path-safe id.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn layer_id(layer: &[u8]) -> String {
    digest_of(layer).trim_start_matches("sha256:").to_string()
}

/// Build a `.smolmachine` sidecar carrying `layers` as its OCI image layers.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn build_sidecar(dir: &Path, layers: &[&[u8]]) -> PathBuf {
    use smolvm_pack::assets::AssetCollector;
    use smolvm_pack::format::PackManifest;
    use smolvm_pack::{sidecar_path_for, Packer};

    fs::create_dir_all(dir).unwrap();
    let stub = dir.join("stub");
    fs::write(&stub, b"#!/bin/sh\necho stub").unwrap();
    let mut collector = AssetCollector::new(dir.join("staging")).unwrap();
    for layer in layers {
        collector.add_layer(&digest_of(layer), layer).unwrap();
    }
    let manifest = PackManifest::new(
        "test:latest".to_string(),
        digest_of(layers[0]),
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

/// Two packs that share a layer: the second one references the store instead of
/// extracting the layer again, and an entry's trees are the store's inodes.
#[cfg(target_os = "linux")]
mod packs {
    use super::*;
    use smolvm_pack::read_footer_from_sidecar;

    struct Volume(PathBuf);

    impl Drop for Volume {
        fn drop(&mut self) {
            force_detach_layers_volume(&self.0);
        }
    }

    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().ino()
    }

    #[test]
    fn a_second_pack_links_the_layers_it_shares_instead_of_extracting_them() {
        smolvm_pack::extract::set_host_layers_probe(|| true);
        let tmp = scratch("layer-store-packs-");
        let shared_root = tmp.path().join("_shared");

        let shared_layer = layer_tar(&[("etc/shared.conf", b"shared layer")]);
        let first_only = layer_tar(&[("etc/first.conf", b"first only")]);
        let second_only = layer_tar(&[("etc/second.conf", b"second only")]);
        let (shared_id, first_id, second_id) = (
            layer_id(&shared_layer),
            layer_id(&first_only),
            layer_id(&second_only),
        );

        let sidecar_a = build_sidecar(&tmp.path().join("a"), &[&shared_layer, &first_only]);
        let sidecar_b = build_sidecar(&tmp.path().join("b"), &[&shared_layer, &second_only]);
        let footer_a = read_footer_from_sidecar(&sidecar_a).unwrap();
        let footer_b = read_footer_from_sidecar(&sidecar_b).unwrap();
        assert_ne!(footer_a.checksum, footer_b.checksum, "distinct packs");

        let store = shared_layers_dir(&shared_root).unwrap();
        let entry_a = shared_root.join(format!("{:08x}", footer_a.checksum));
        fs::create_dir_all(&entry_a).unwrap();
        if !smolvm_pack::extract::host_unpacks_layers(Some("1.30.1"), &entry_a) {
            eprintln!("SKIP: this host does not unpack pack layers itself");
            return;
        }
        let _volume = Volume(entry_a.clone());

        smolvm_pack::extract::extract_sidecar_shared(&sidecar_a, &shared_root, &footer_a, false)
            .unwrap();
        let shared_file = store.join(&shared_id).join("etc/shared.conf");
        assert!(shared_file.is_file(), "the layer must land in the store");
        assert!(store.join(&first_id).join("etc/first.conf").is_file());
        let store_inode = inode(&shared_file);
        let store_mtime = fs::metadata(&shared_file).unwrap().modified().unwrap();

        let entry_b = shared_root.join(format!("{:08x}", footer_b.checksum));
        smolvm_pack::extract::extract_sidecar_shared(&sidecar_b, &shared_root, &footer_b, false)
            .unwrap();

        // The shared layer was neither re-extracted nor copied: the second
        // entry's tree *is* the store's inode, and the store's copy is
        // untouched.
        assert_eq!(
            inode(&store.join(&shared_id).join("etc/shared.conf")),
            store_inode,
            "the store's copy of a shared layer must not be rewritten"
        );
        assert_eq!(
            fs::metadata(&shared_file).unwrap().modified().unwrap(),
            store_mtime
        );
        assert_eq!(
            inode(
                &entry_b
                    .join("layers")
                    .join(&shared_id)
                    .join("etc/shared.conf")
            ),
            store_inode,
            "the second entry must reference the layer, not own a copy"
        );
        assert!(
            store.join(&second_id).join("etc/second.conf").is_file(),
            "the layer only the second pack carries must be installed"
        );

        // Both entries are complete and readable exactly as before.
        for (entry, ids) in [
            (&entry_a, vec![shared_id.clone(), first_id.clone()]),
            (&entry_b, vec![shared_id.clone(), second_id.clone()]),
        ] {
            assert!(
                smolvm_pack::extract::cached_layers_usable(entry),
                "{} must read as usable",
                entry.display()
            );
            let order = fs::read_to_string(entry.join("layers").join("layer-order")).unwrap();
            assert_eq!(
                order.lines().collect::<Vec<_>>(),
                ids.iter().map(String::as_str).collect::<Vec<_>>(),
                "the stacking order must be the manifest's, bottom to top"
            );
            for id in &ids {
                assert!(
                    entry.join("layers").join(id).is_dir(),
                    "{} must hold layer {id} under its own name",
                    entry.display()
                );
            }
        }
    }
    /// A split artifact's base pack names its layers but carries no layer
    /// members: `pack pull` installed them into the shared store. Extracting
    /// that base with the store named must link those trees into the entry, or
    /// the machine boots with an empty `layers/` and fails in the guest.
    #[test]
    fn a_base_pack_with_named_layers_takes_them_from_the_shared_store() {
        use smolvm_pack::extract::extract_sidecar_with_store;
        use smolvm_pack::split::{split_pack, SplitCache};

        let tmp = scratch("layer-store-split-");
        let shared_root = tmp.path().join("_shared");
        let layer = layer_tar(&[("etc/split.conf", b"split layer")]);
        let id = layer_id(&layer);
        let sidecar = build_sidecar(&tmp.path().join("pack"), &[&layer]);

        // What `pack push` publishes: a base pack with the layer only named.
        let split = split_pack(&sidecar, &SplitCache::new(tmp.path().join("split-cache"))).unwrap();
        assert_eq!(split.layers.len(), 1);
        assert_eq!(split.layers[0].diff_id.trim_start_matches("sha256:"), id);

        // What `pack pull` does: install the layer into the store.
        let blob = zstd::stream::encode_all(&layer[..], 3).unwrap();
        install_layer_from_stream(&shared_root, &split.layers[0].diff_id, &blob[..]).unwrap();

        // What `machine run --from <pulled>.smolmachine` does: extract the base
        // pack, naming the store the pull installed into.
        let entry = tmp.path().join("entry");
        let footer = read_footer_from_sidecar(&split.base_path).unwrap();
        extract_sidecar_with_store(
            &split.base_path,
            &entry,
            &footer,
            false,
            false,
            &shared_root,
        )
        .unwrap();

        assert_eq!(
            fs::read(entry.join("layers").join(&id).join("etc/split.conf")).unwrap(),
            b"split layer",
            "the base pack's named layer must be linked from the store"
        );
        let record = fs::read_to_string(entry.join("layers").join(STREAMED_LAYERS_FILE)).unwrap();
        assert!(
            record.lines().any(|line| line == id),
            "the entry must name the layer it took from the store: {record:?}"
        );
    }
}

/// macOS: the store lives in a case-sensitive APFS volume that cannot share
/// inodes with the host volume, so an entry references a layer with APFS
/// clones. Two packs that share a layer therefore cost the layer's bytes once,
/// and the disk grows by the layers a pack does not share.
#[cfg(target_os = "macos")]
mod macos_packs {
    use super::*;
    use smolvm_pack::read_footer_from_sidecar;

    /// The store's volume, detached when the test ends: a temp directory that
    /// is still a mount point cannot be removed, and the mounts must not leak
    /// into the next test.
    struct StoreVolume(PathBuf);

    impl StoreVolume {
        fn image(&self) -> PathBuf {
            self.0.join("layers-cs.sparseimage")
        }

        fn mount(&self) -> PathBuf {
            self.0.join("layers-cs")
        }

        fn detach(&self) {
            let _ = std::process::Command::new("hdiutil")
                .args(["detach", "-quiet", "-force"])
                .arg(self.mount())
                .output();
        }

        /// Host bytes the volume actually holds, after a detach flushed it.
        fn allocated(&self) -> u64 {
            self.detach();
            allocated(&self.image())
        }
    }

    impl Drop for StoreVolume {
        fn drop(&mut self) {
            self.detach();
        }
    }

    /// The host disk a path actually consumes (`st_blocks`, not its length).
    fn allocated(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path)
            .map(|meta| meta.blocks().saturating_mul(512))
            .unwrap_or(0)
    }

    fn inode(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().ino()
    }

    fn links(path: &Path) -> u64 {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(path).unwrap().nlink()
    }

    /// One layer holding a single file of `size` incompressible bytes.
    fn layer_of(size: usize, seed: u8) -> Vec<u8> {
        let bytes: Vec<u8> = (0..size).map(|i| (i as u8) ^ seed).collect();
        layer_tar(&[("data/blob.bin", &bytes)])
    }

    const MIB: usize = 1024 * 1024;

    /// Two packs sharing an 8 MiB layer, each with a 4 MiB layer of its own.
    /// With the store the second pack adds only its own layer; without it, each
    /// pack unpacks the whole set again into its own volume.
    #[test]
    fn a_second_pack_adds_only_the_layers_it_does_not_share() {
        let tmp = scratch("layer-store-macos-");
        let store_root = tmp.path().join("_layers");
        let store = StoreVolume(store_root.clone());

        let shared_layer = layer_of(8 * MIB, 0x11);
        let first_only = layer_of(4 * MIB, 0x22);
        let second_only = layer_of(4 * MIB, 0x33);
        let (shared_id, first_id, second_id) = (
            layer_id(&shared_layer),
            layer_id(&first_only),
            layer_id(&second_only),
        );
        let sidecar_a = build_sidecar(&tmp.path().join("build-a"), &[&shared_layer, &first_only]);
        let sidecar_b = build_sidecar(&tmp.path().join("build-b"), &[&shared_layer, &second_only]);
        let footer_a = read_footer_from_sidecar(&sidecar_a).unwrap();
        let footer_b = read_footer_from_sidecar(&sidecar_b).unwrap();
        assert_ne!(footer_a.checksum, footer_b.checksum, "distinct packs");

        // With the store: one volume for both packs.
        let entry_a = tmp.path().join("a");
        let entry_b = tmp.path().join("b");
        smolvm_pack::extract::extract_sidecar_with_store(
            &sidecar_a,
            &entry_a,
            &footer_a,
            false,
            false,
            &store_root,
        )
        .unwrap();
        let after_a = store.allocated();
        smolvm_pack::extract::extract_sidecar_with_store(
            &sidecar_b,
            &entry_b,
            &footer_b,
            false,
            false,
            &store_root,
        )
        .unwrap();
        let after_b = store.allocated();

        // Both entries see their layers, and the trees are clones: same bytes,
        // separate inodes, no link between the store's copy and the entry's.
        let store_layers = shared_layers_dir(&store_root).unwrap();
        for (entry, ids) in [
            (&entry_a, [&shared_id, &first_id]),
            (&entry_b, [&shared_id, &second_id]),
        ] {
            assert!(
                smolvm_pack::extract::cached_layers_usable(entry),
                "{} must read as usable",
                entry.display()
            );
            for id in ids {
                let entry_file = smolvm_pack::extract::layer_store_entry_dir(&store_layers, entry)
                    .join(id)
                    .join("data/blob.bin");
                let store_file = store_layers.join(id).join("data/blob.bin");
                assert_eq!(
                    fs::read(&entry_file).unwrap(),
                    fs::read(&store_file).unwrap(),
                    "the entry's clone must hold the layer's bytes"
                );
                assert_ne!(
                    inode(&entry_file),
                    inode(&store_file),
                    "macOS entries clone, they cannot share the store's inodes"
                );
                assert_eq!(links(&entry_file), 1, "a clone is its own inode");
            }
        }

        // Without the store: each pack unpacks its own copy of every layer,
        // which is what the store exists to avoid.
        let plain_a = tmp.path().join("plain-a");
        let plain_b = tmp.path().join("plain-b");
        smolvm_pack::extract::extract_sidecar(&sidecar_a, &plain_a, &footer_a, false, false)
            .unwrap();
        smolvm_pack::extract::force_detach_layers_volume(&plain_a);
        smolvm_pack::extract::extract_sidecar(&sidecar_b, &plain_b, &footer_b, false, false)
            .unwrap();
        smolvm_pack::extract::force_detach_layers_volume(&plain_b);
        let plain_bytes = allocated(&plain_a.join("layers-cs.sparseimage"))
            + allocated(&plain_b.join("layers-cs.sparseimage"));

        let second_growth = after_b.saturating_sub(after_a);
        let shared_bytes = (8 * MIB) as u64;
        eprintln!(
            "store: {after_a} bytes after pack A, {after_b} after pack B \
             (second pack added {second_growth}); without the store: {plain_bytes} bytes"
        );
        // The second pack adds its own 4 MiB layer and clone metadata for the
        // 8 MiB one — well under the shared layer it must not unpack again.
        assert!(
            second_growth < shared_bytes,
            "the second pack re-stored the shared layer: it added {second_growth} bytes \
             for a pack whose unique layer is {} bytes",
            second_only.len()
        );
        assert!(
            second_growth >= (4 * MIB) as u64,
            "the second pack's own layer did not land: {second_growth} bytes added"
        );
        assert!(
            second_growth < (6 * MIB) as u64,
            "the second pack added more than its own layer and clone metadata: \
             {second_growth} bytes"
        );
        // The whole store holds the three layers once (~16 MiB); the plain
        // extractions hold the shared layer a second time (~32 MiB).
        assert!(
            after_b + shared_bytes / 2 < plain_bytes,
            "the store did not save the shared layer: {after_b} bytes with it, \
             {plain_bytes} without"
        );
        assert!(store_layers.join(&first_id).join("data/blob.bin").is_file());
        assert!(store_layers
            .join(&second_id)
            .join("data/blob.bin")
            .is_file());
    }

    /// A collection reads references from the entries' records, not from link
    /// counts: a clone shares no inode with the store, so only the record can
    /// keep its layer alive. An entry whose extraction is gone stops protecting
    /// anything, and the layers nothing else names are collected.
    #[test]
    fn a_collection_keeps_the_layers_a_store_entry_names() {
        let tmp = scratch("layer-store-macos-gc-");
        let store_root = tmp.path().join("_layers");
        let _store = StoreVolume(store_root.clone());

        let shared_layer = layer_tar(&[("etc/shared.conf", b"shared")]);
        let first_only = layer_tar(&[("etc/first.conf", b"first")]);
        let second_only = layer_tar(&[("etc/second.conf", b"second")]);
        let (shared_id, first_id, second_id) = (
            layer_id(&shared_layer),
            layer_id(&first_only),
            layer_id(&second_only),
        );
        let sidecar_a = build_sidecar(&tmp.path().join("build-a"), &[&shared_layer, &first_only]);
        let sidecar_b = build_sidecar(&tmp.path().join("build-b"), &[&shared_layer, &second_only]);
        let footer_a = read_footer_from_sidecar(&sidecar_a).unwrap();
        let footer_b = read_footer_from_sidecar(&sidecar_b).unwrap();
        let entry_a = tmp.path().join("a");
        let entry_b = tmp.path().join("b");
        smolvm_pack::extract::extract_sidecar_with_store(
            &sidecar_a,
            &entry_a,
            &footer_a,
            false,
            false,
            &store_root,
        )
        .unwrap();
        smolvm_pack::extract::extract_sidecar_with_store(
            &sidecar_b,
            &entry_b,
            &footer_b,
            false,
            false,
            &store_root,
        )
        .unwrap();

        let store_layers = shared_layers_dir(&store_root).unwrap();
        let clone = smolvm_pack::extract::layer_store_entry_dir(&store_layers, &entry_a)
            .join(&shared_id)
            .join("etc/shared.conf");
        assert_eq!(links(&clone), 1, "the entry holds a clone, not a link");
        assert_ne!(
            inode(&clone),
            inode(&store_layers.join(&shared_id).join("etc/shared.conf"))
        );

        // Both entries name their layers: nothing may go while they exist.
        let report = collect_layer_store(&store_root, false).unwrap();
        assert_eq!(report.layers_removed, 0, "both entries reference the store");
        assert_eq!(report.entries_removed, 0);
        for id in [&shared_id, &first_id, &second_id] {
            assert!(layer_present(&store_root, id), "layer {id} must be kept");
        }

        // Pack A's extraction is gone (a deleted machine): its entry directory
        // stops protecting anything, and only the layer only it named goes.
        fs::remove_dir_all(&entry_a).unwrap();
        let report = collect_layer_store(&store_root, false).unwrap();
        assert_eq!(report.entries_removed, 1, "the stale entry is discarded");
        assert_eq!(report.layers_removed, 1, "only pack A's unique layer");
        assert!(layer_present(&store_root, &shared_id));
        assert!(layer_present(&store_root, &second_id));
        assert!(!layer_present(&store_root, &first_id));

        // With pack B gone too, nothing references the store any more.
        fs::remove_dir_all(&entry_b).unwrap();
        let report = collect_layer_store(&store_root, false).unwrap();
        assert_eq!(report.entries_removed, 1);
        assert_eq!(report.layers_removed, 2);
        for id in [&shared_id, &first_id, &second_id] {
            assert!(!layer_present(&store_root, id), "layer {id} must be gone");
        }
    }
}
