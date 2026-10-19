//! The digest-keyed shared layer store: layers arrive as streams, land under
//! their diff_id, and a pack that carries a layer the store already has costs a
//! fan-out of hard links instead of another extraction.
//!
//! The store's own tests run everywhere (an install is just a zstd tar with a
//! digest). The pack-level tests are Linux-only: that is the one platform whose
//! entries and store share a filesystem and an owner, which is what makes
//! linking a layer in sound rather than a copy.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use smolvm_pack::extract::{
    collect_layer_store, collect_layer_store_with, force_detach_layers_volume,
    install_layer_from_stream, layer_present, shared_layers_dir, PARTIAL_DIR_SUFFIX,
    STREAMED_LAYERS_FILE,
};

/// The staging name a layer is unpacked under before it takes its own.
fn staging_dir(layer_dir: &Path) -> PathBuf {
    layer_dir.with_file_name(format!(
        "{}{PARTIAL_DIR_SUFFIX}",
        layer_dir.file_name().unwrap().to_string_lossy()
    ))
}

fn scratch(prefix: &str) -> tempfile::TempDir {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"));
    fs::create_dir_all(root).unwrap();
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
#[cfg(unix)]
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

/// Two packs that share a layer: the second one references the store instead of
/// extracting the layer again, and an entry's trees are the store's inodes.
#[cfg(target_os = "linux")]
mod packs {
    use super::*;
    use smolvm_pack::assets::AssetCollector;
    use smolvm_pack::format::PackManifest;
    use smolvm_pack::{read_footer_from_sidecar, sidecar_path_for, Packer};

    fn digest_of(layer: &[u8]) -> String {
        format!("sha256:{:x}", Sha256::digest(layer))
    }

    fn layer_id(layer: &[u8]) -> String {
        digest_of(layer).trim_start_matches("sha256:").to_string()
    }

    fn build_sidecar(dir: &Path, layers: &[&[u8]]) -> PathBuf {
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
}
