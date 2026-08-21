//! Shared machine-workload launch: run an image machine's persistent
//! container (its ENTRYPOINT+CMD) after the VM boots.
//!
//! Every front-end that starts machines (the engine CLI, the HTTP API, the
//! smol CLI) must launch the workload the same way — a front-end that skips
//! it boots a bare agent VM whose published ports forward to nothing. Keeping
//! the launch here, in the lib, is what stops front-ends from drifting apart.

use crate::agent::{AgentClient, RunConfig};
use crate::config::VmRecord;
use crate::data::storage::HostMount;

/// Convert a `VmRecord` mount list (`(host_source, guest_target, read_only)`
/// triples) to the agent's virtiofs binding format. The host source is
/// dropped — the agent only needs the guest-facing target and the positional
/// `smolvm{i}` tag.
pub fn record_mounts_to_bindings(mounts: &[(String, String, bool)]) -> Vec<(String, String, bool)> {
    mounts
        .iter()
        .enumerate()
        .map(|(i, (_host, target, ro))| (HostMount::mount_tag(i), target.clone(), *ro))
        .collect()
}

/// The id under which a machine's persistent exec overlay lives on its
/// `/storage` disk. Normally the machine's own name; for a fork clone it is
/// the GOLDEN's name: a fork CoW-clones the golden's disks, so the inherited
/// overlay — everything the golden wrote via exec — sits at
/// `/storage/overlays/persistent-<golden>` inside the clone's own disk, and
/// the restored guest may still hold that overlay *mounted* (or a restored
/// workload container running from it). Aliasing the lookup, instead of
/// renaming the directory on disk, keeps that live mount valid while making
/// the clone's execs land in the inherited state.
pub fn persistent_overlay_owner(name: &str, golden: Option<&str>) -> String {
    golden.unwrap_or(name).to_string()
}

/// Launch an image machine's workload container in the background.
///
/// `exec_env` is the record env with secrets already resolved — resolution is
/// a host-side concern the caller owns. An empty entrypoint+cmd makes the
/// agent resolve the image's own ENTRYPOINT+CMD, so service-style images
/// start as their authors intended. The persistent overlay is keyed by
/// [`persistent_overlay_owner`] (the machine name, or the golden's for a fork
/// clone) so filesystem state survives restarts and forks.
///
/// Returns `Ok(false)` (no launch) for machines without an image, and for
/// image machines where neither the record nor the image supplies a command —
/// a bare rootfs directory has no OCI config at all, so failing the whole
/// start over a missing ENTRYPOINT would make such images unusable as
/// machines. They boot to the bare agent instead; `exec`/`shell` provide the
/// commands.
pub fn launch_image_workload(
    client: &mut AgentClient,
    machine_name: &str,
    record: &VmRecord,
    exec_env: Vec<(String, String)>,
) -> crate::Result<bool> {
    let Some(ref image) = record.image else {
        return Ok(false);
    };
    let mut command = record.entrypoint.clone();
    command.extend(record.cmd.clone());
    match client.run_container_detached(
        RunConfig::new(image, command)
            .with_env(exec_env)
            .with_workdir(record.workdir.clone())
            .with_user(record.user.clone())
            .with_mounts(record_mounts_to_bindings(&record.mounts))
            .with_persistent_overlay(Some(persistent_overlay_owner(
                machine_name,
                record.golden.as_deref(),
            ))),
    ) {
        Ok(_) => Ok(true),
        Err(e) if is_missing_launch_metadata(&e.to_string()) => {
            tracing::info!(
                machine = machine_name,
                image = %image,
                "image defines no entrypoint or cmd and none was given; booting bare agent without a workload"
            );
            Ok(false)
        }
        Err(e) => Err(crate::Error::agent("start background CMD", format!("{e}"))),
    }
}

/// Whether a detached-run failure means "nothing to launch" rather than a
/// real error. The image is only known inside the guest (it may be imported
/// during the run request itself), so the agent's error message — kept stable
/// on its side for this match — is the reliable signal.
fn is_missing_launch_metadata(message: &str) -> bool {
    message.contains("defines no entrypoint or cmd")
}

#[cfg(test)]
mod tests {
    use super::*;

    // A plain machine's overlay is keyed by its own name; a fork clone's by
    // its golden's name, so clone execs land in the CoW-inherited overlay
    // (and its still-live restored mount) instead of a fresh empty one.
    #[test]
    fn overlay_owner_aliases_fork_clones_to_their_golden() {
        assert_eq!(persistent_overlay_owner("m1", None), "m1");
        assert_eq!(
            persistent_overlay_owner("clone-a", Some("golden-a")),
            "golden-a"
        );
    }

    // Only the agent's metadata-less-image failure downgrades a machine start
    // to a bare-agent boot; every other launch failure must stay fatal.
    #[test]
    fn only_the_missing_metadata_error_is_downgraded() {
        assert!(is_missing_launch_metadata(
            "agent operation failed: run container detached: no command given \
             and image 'local-dir:/images/ubuntu' defines no entrypoint or cmd"
        ));
        assert!(!is_missing_launch_metadata("image not found: whatever"));
        assert!(!is_missing_launch_metadata(
            "run container detached: crun exited with status 1"
        ));
    }
}
