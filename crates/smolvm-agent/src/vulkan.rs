//! Guest-side Vulkan (Venus) driver injection for the workload container.
//!
//! A `--gpu` VM exposes `/dev/dri` into every container
//! (`oci::add_gpu_devices_if_available`), but the container can only use
//! Vulkan if its image ships a Mesa with the virtio ICD — which stock images
//! don't, and on macOS hosts even a stock Mesa fails Venus blob negotiation
//! (16 KiB pages; needs the mesa-krunkit patch). The agent rootfs bundles the
//! patched driver, its shared-library closure, and the Vulkan loader
//! (`scripts/fetch-vulkan-guest-driver.sh`); this module bind-mounts the
//! bundle into the container and points the Vulkan loader at it, mirroring
//! [`crate::cuda`]'s shim staging.
//!
//! Every gate degrades to a silent no-op, so behavior without the bundle (or
//! on non-GPU VMs) is exactly today's.

/// Where the bundle ships inside the VM rootfs (from the agent rootfs).
const GUEST_BUNDLE_DIR: &str = "/usr/local/lib/smolvm-vulkan";
/// Where the bundle is bind-mounted inside the workload container. The ICD
/// manifest's `library_path` points here, so the two must stay in sync with
/// `scripts/fetch-vulkan-guest-driver.sh`.
const CONTAINER_BUNDLE_DIR: &str = "/opt/smolvm-vulkan";
/// The Venus driver inside the bundle — its presence is the "bundled" gate.
const DRIVER: &str = "libvulkan_virtio.so";
/// The ICD manifest inside the bundle.
const ICD_JSON: &str = "virtio_icd.json";
/// Request-level opt-out (set via `--env`).
const OPT_OUT_ENV: &str = "SMOLVM_NO_VULKAN_INJECT";

/// Stage the bundled Venus driver into the workload container spec so an
/// unmodified image gets working Vulkan on a `--gpu` VM with no setup: the
/// bundle rides a read-only bind mount, `VK_DRIVER_FILES` pins the loader to
/// our ICD (unless the user chose a driver themselves), and `LD_LIBRARY_PATH`
/// resolves the loader for images that ship none. No-op unless the VM has a
/// GPU, the bundle is present, and the image's libc can load it (glibc).
pub fn inject_into_container(spec: &mut crate::oci::OciSpec, rootfs: &std::path::Path) {
    inject_into_container_if(
        spec,
        rootfs,
        std::path::Path::new("/dev/dri").exists(),
        std::path::Path::new(GUEST_BUNDLE_DIR),
    );
}

/// Testable core of [`inject_into_container`].
fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    rootfs: &std::path::Path,
    gpu_present: bool,
    bundle_dir: &std::path::Path,
) {
    if !gpu_present {
        return; // not a --gpu VM
    }
    if !bundle_dir.join(DRIVER).is_file() || !bundle_dir.join(ICD_JSON).is_file() {
        return; // bundle not shipped in this rootfs — manual setup still works
    }
    if env_set(&spec.process.env, OPT_OUT_ENV) {
        return; // user opted out for this workload
    }
    if is_musl_image(rootfs) {
        // The bundled driver is glibc; a musl image can't load it. Skip until
        // a musl bundle ships rather than surface a confusing dlopen error.
        return;
    }

    spec.add_bind_mount(&bundle_dir.to_string_lossy(), CONTAINER_BUNDLE_DIR, true);

    // Pin the loader to our ICD unless the image or request already chose a
    // driver — an explicit user choice always wins. Pinning one ICD also
    // sidesteps multi-ICD probe failures (unrelated ICDs crashing the probe,
    // or a swapchain-less device being picked over Venus).
    if !env_set(&spec.process.env, "VK_DRIVER_FILES")
        && !env_set(&spec.process.env, "VK_ICD_FILENAMES")
    {
        spec.add_env(
            "VK_DRIVER_FILES",
            &format!("{}/{}", CONTAINER_BUNDLE_DIR, ICD_JSON),
        );
    }

    // Loader fallback for images without libvulkan.so.1 — appended, so an
    // image-provided loader earlier on the path still wins.
    append_ld_library_path(&mut spec.process.env, CONTAINER_BUNDLE_DIR);
}

/// Append the Vulkan loader pin (and the bundle's loader path) to an explicit
/// exec env. Used on the `crun exec` path (joining a persistent machine's
/// keep-alive container), where the workload env is passed via `--env` rather
/// than inherited from the container spec, so the spec injection above doesn't
/// reach it. The bind mount itself was established when the container was
/// created. Gates mirror the inject path as seen from the AGENT's namespace
/// (GPU present + bundle shipped); a container that skipped the mount (musl,
/// opt-out) merely gets env pointing at a path that doesn't exist there — the
/// loader finds no driver, exactly today's behavior. A user-provided driver
/// choice in the exec env still wins.
pub fn augment_exec_env(mut env: Vec<(String, String)>) -> Vec<(String, String)> {
    if !std::path::Path::new("/dev/dri").exists()
        || !std::path::Path::new(GUEST_BUNDLE_DIR)
            .join(DRIVER)
            .is_file()
    {
        return env;
    }
    if !env
        .iter()
        .any(|(k, v)| (k == "VK_DRIVER_FILES" || k == "VK_ICD_FILENAMES") && !v.is_empty())
    {
        env.push((
            "VK_DRIVER_FILES".to_string(),
            format!("{}/{}", CONTAINER_BUNDLE_DIR, ICD_JSON),
        ));
    }
    match env.iter_mut().find(|(k, _)| k == "LD_LIBRARY_PATH") {
        Some((_, v)) => {
            if !v.split(':').any(|p| p == CONTAINER_BUNDLE_DIR) {
                *v = format!("{v}:{CONTAINER_BUNDLE_DIR}");
            }
        }
        None => env.push((
            "LD_LIBRARY_PATH".to_string(),
            CONTAINER_BUNDLE_DIR.to_string(),
        )),
    }
    env
}

/// Whether `name` is set (to anything non-empty) in the container env.
fn env_set(env: &[String], name: &str) -> bool {
    let prefix = format!("{}=", name);
    env.iter()
        .any(|e| e.strip_prefix(&prefix).is_some_and(|v| !v.is_empty()))
}

/// A musl-libc image can't load the bundled glibc driver. Musl distros ship
/// their dynamic loader as /lib/ld-musl-<arch>.so.1.
fn is_musl_image(rootfs: &std::path::Path) -> bool {
    std::fs::read_dir(rootfs.join("lib"))
        .map(|entries| {
            entries
                .flatten()
                .any(|e| e.file_name().to_string_lossy().starts_with("ld-musl-"))
        })
        .unwrap_or(false)
}

/// Append `dir` to the spec's `LD_LIBRARY_PATH`, preserving an image-provided
/// value; creates the variable if absent, skips if already present.
fn append_ld_library_path(env: &mut Vec<String>, dir: &str) {
    for e in env.iter_mut() {
        if let Some(v) = e.strip_prefix("LD_LIBRARY_PATH=") {
            if v.split(':').any(|p| p == dir) {
                return;
            }
            *e = format!("LD_LIBRARY_PATH={v}:{dir}");
            return;
        }
    }
    env.push(format!("LD_LIBRARY_PATH={dir}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn spec() -> OciSpec {
        OciSpec::new(
            &["true".to_string()],
            &[],
            "/",
            false,
            &ProcessIdentity::root(),
            false,
        )
    }

    fn bundle_mounted(s: &OciSpec) -> bool {
        s.mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR)
    }

    fn bundle_fixture() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(DRIVER), b"").unwrap();
        std::fs::write(dir.path().join(ICD_JSON), b"{}").unwrap();
        dir
    }

    fn glibc_rootfs() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("lib")).unwrap();
        dir
    }

    #[test]
    fn injects_when_gpu_and_bundle_present() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(s
            .mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR));
        assert!(s
            .process
            .env
            .iter()
            .any(|e| e == "VK_DRIVER_FILES=/opt/smolvm-vulkan/virtio_icd.json"));
        assert!(s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("LD_LIBRARY_PATH=") && e.contains(CONTAINER_BUNDLE_DIR)));
    }

    #[test]
    fn noop_without_gpu() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), false, bundle.path());
        assert!(!bundle_mounted(&s));
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("VK_DRIVER_FILES=")));
    }

    #[test]
    fn noop_without_bundle() {
        let empty = tempfile::tempdir().unwrap();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, empty.path());
        assert!(!bundle_mounted(&s));
    }

    #[test]
    fn user_driver_choice_wins() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        s.add_env("VK_ICD_FILENAMES", "/usr/share/vulkan/icd.d/mine.json");
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!s
            .process
            .env
            .iter()
            .any(|e| e.starts_with("VK_DRIVER_FILES=")));
        // The bundle is still mounted — only the loader pin defers to the user.
        assert!(s
            .mounts
            .iter()
            .any(|m| m.destination == CONTAINER_BUNDLE_DIR));
    }

    #[test]
    fn opt_out_env_skips_entirely() {
        let bundle = bundle_fixture();
        let rootfs = glibc_rootfs();
        let mut s = spec();
        s.add_env(OPT_OUT_ENV, "1");
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!bundle_mounted(&s));
    }

    #[test]
    fn musl_image_skips() {
        let bundle = bundle_fixture();
        let rootfs = tempfile::tempdir().unwrap();
        std::fs::create_dir(rootfs.path().join("lib")).unwrap();
        std::fs::write(rootfs.path().join("lib/ld-musl-aarch64.so.1"), b"").unwrap();
        let mut s = spec();
        inject_into_container_if(&mut s, rootfs.path(), true, bundle.path());
        assert!(!bundle_mounted(&s));
    }

    #[test]
    fn ld_library_path_appends_and_dedupes() {
        let mut env = vec!["LD_LIBRARY_PATH=/usr/lib".to_string()];
        append_ld_library_path(&mut env, CONTAINER_BUNDLE_DIR);
        assert_eq!(
            env[0],
            format!("LD_LIBRARY_PATH=/usr/lib:{CONTAINER_BUNDLE_DIR}")
        );
        append_ld_library_path(&mut env, CONTAINER_BUNDLE_DIR);
        assert_eq!(env.len(), 1);
        assert_eq!(env[0].matches(CONTAINER_BUNDLE_DIR).count(), 1);
    }
}
