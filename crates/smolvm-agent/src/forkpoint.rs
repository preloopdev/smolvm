//! Workload-facing live-branch coordination.
//!
//! A workload calls `smolvm-branch-ready` after initialization. The helper writes
//! a marker and blocks, so the application cannot mutate training state while
//! the host captures the source. Restored children are released independently by
//! the host through a VM-private directory bind-mounted into the container.

use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::time::Duration;

const AGENT_BINARY: &str = "/usr/local/bin/smolvm-agent";
use smolvm_protocol::forkpoint::{
    ARMED_PATH, ARMED_PREFIX, ARM_PATH, ARM_PREFIX, BRANCH_ENV_PATH, BRANCH_HELPER_PATH,
    CONTAINER_INIT_ARG, CONTAINER_INIT_NAME, CUDA_PRELOAD_MODULES_HINT, FORK_ENV_PATH,
    GENERATION_PREFIX, HELPER_PATH, READY_LEASE_HINT, READY_PATH, READY_VERSION, RELEASE_PATH,
    RELEASE_PREFIX, RESTORED_CONTAINER_PATH, RESTORED_PATH, STATE_DIR, WORKER_READY_HELPER_PATH,
    WORKER_READY_PATH, WORKER_READY_TOKEN_ENV,
};

fn enabled() -> bool {
    std::env::var(smolvm_protocol::guest_env::FORKABLE).as_deref()
        == Ok(smolvm_protocol::guest_env::VALUE_ON)
}

/// Whether this process invocation is the workload-facing helper rather than
/// the PID-1 guest agent.
pub fn helper_requested() -> bool {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    let helper_argv0 = Path::new(&argv0)
        .file_name()
        .is_some_and(|name| name == "smolvm-fork-ready" || name == "smolvm-branch-ready");
    helper_argv0
        || args
            .next()
            .is_some_and(|arg| arg == "fork-ready" || arg == "branch-ready")
}

/// Whether this invocation is the post-restore worker-readiness helper.
pub fn worker_ready_helper_requested() -> bool {
    let mut args = std::env::args_os();
    let argv0 = args.next().unwrap_or_default();
    let helper_argv0 = Path::new(&argv0)
        .file_name()
        .is_some_and(|name| name == "smolvm-worker-ready");
    helper_argv0 || args.next().is_some_and(|arg| arg == "worker-ready")
}

/// Prepare the VM-private coordination directory and the bare-VM helper name.
/// Container workloads receive the same directory and binary through OCI bind
/// mounts in [`inject_into_container`].
pub fn setup() {
    if !enabled() {
        return;
    }
    if let Err(error) = std::fs::create_dir_all(STATE_DIR) {
        tracing::warn!(%error, "failed to create forkpoint state directory");
        return;
    }
    if let Err(error) = std::fs::set_permissions(STATE_DIR, std::fs::Permissions::from_mode(0o1777))
    {
        tracing::warn!(%error, "failed to set forkpoint state permissions");
    }
    let _ = std::fs::remove_file(READY_PATH);
    let _ = std::fs::remove_file(RESTORED_CONTAINER_PATH);
    let _ = std::fs::remove_file(RESTORED_PATH);
    let _ = std::fs::remove_file(RELEASE_PATH);
    let _ = std::fs::remove_file(WORKER_READY_PATH);
    let _ = std::fs::remove_file(ARM_PATH);
    let _ = std::fs::remove_file(ARMED_PATH);

    for helper in [BRANCH_HELPER_PATH, HELPER_PATH, WORKER_READY_HELPER_PATH] {
        if !Path::new(helper).exists() {
            if let Err(error) = std::os::unix::fs::symlink(AGENT_BINARY, helper) {
                tracing::warn!(%error, helper, "failed to install bare-VM forkpoint helper");
            }
        }
    }
}

/// Expose the forkpoint helper and its VM-private state directory inside a
/// workload container. No-op for ordinary machines.
pub fn inject_into_container(spec: &mut crate::oci::OciSpec) {
    inject_into_container_if(spec, enabled(), AGENT_BINARY, STATE_DIR);
}

/// Keep a `crun exec` process on the same footing as the container it joins.
///
/// `crun exec --env` builds a fresh process environment instead of inheriting
/// the container spec. Without restoring this internal variable, a
/// `smolvm-branch-ready` helper launched through `machine exec` could not tell
/// that the machine is branchable.
pub fn augment_exec_env(mut env: Vec<(String, String)>) -> Vec<(String, String)> {
    augment_exec_env_if(&mut env, enabled());
    env
}

fn augment_exec_env_if(env: &mut Vec<(String, String)>, branchable: bool) {
    let key = smolvm_protocol::guest_env::FORKABLE;
    env.retain(|(existing, _)| existing != key);
    if branchable {
        env.push((
            key.to_string(),
            smolvm_protocol::guest_env::VALUE_ON.to_string(),
        ));
    }
}

fn inject_into_container_if(
    spec: &mut crate::oci::OciSpec,
    enabled: bool,
    agent_binary: &str,
    state_dir: &str,
) {
    if !enabled || !Path::new(agent_binary).is_file() || !Path::new(state_dir).is_dir() {
        return;
    }
    spec.add_bind_mount(agent_binary, HELPER_PATH, true);
    spec.add_bind_mount(agent_binary, BRANCH_HELPER_PATH, true);
    spec.add_bind_mount(agent_binary, WORKER_READY_HELPER_PATH, true);
    spec.add_bind_mount(state_dir, STATE_DIR, false);
    spec.add_env(
        smolvm_protocol::guest_env::FORKABLE,
        smolvm_protocol::guest_env::VALUE_ON,
    );
}

/// Reap exited children while parked, when the helper is the container's
/// PID 1.
///
/// A parked source can sit at its branchpoint for a long time; if the
/// workload `exec`'d the helper, every background job is its child, and a job
/// that exits would otherwise stay a zombie — then be captured into every
/// clone. Non-blocking, so it never delays the branch protocol; a no-op when
/// some other process is PID 1.
fn reap_children_if_init() {
    if std::process::id() != 1 {
        return;
    }
    // SAFETY: WNOHANG waitpid on any child only collects already-exited
    // children; it blocks nothing and touches no memory of ours.
    while unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } > 0 {}
}

/// Mark the workload ready and block until this VM is a released clone.
///
/// Returns 0 once released so the workload can continue — unless the helper
/// is the container's PID 1 (the workload `exec`'d it), in which case it never
/// returns: it becomes the container's init instead, so the clone keeps the
/// processes the branch preserved.
pub fn run_helper() -> i32 {
    let (preload_modules, command) = parse_helper_args(std::env::args_os().skip(1));
    if let Err(error) = run_helper_inner(preload_modules) {
        eprintln!("smolvm-branch-ready: {error}");
        return 1;
    }
    // Released. The helper is the one mechanism in both directions: the
    // workload declared the branchpoint by running it, and it hands the
    // child's identity back the same way — as this command's result.
    let identity = load_identity(Path::new(RELEASE_PATH));
    if let Some(command) = command {
        // `smolvm-branch-ready -- prog args…`: become the child's program, with
        // its identity in the environment. If the helper was `exec`'d as PID 1,
        // the program takes over PID 1 and every background job started before
        // the branchpoint stays its child.
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new(&command[0])
            .args(&command[1..])
            .envs(identity.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .exec();
        eprintln!(
            "smolvm-branch-ready: exec {}: {error}",
            command[0].to_string_lossy()
        );
        return if error.kind() == std::io::ErrorKind::NotFound {
            127
        } else {
            126
        };
    }
    if std::process::id() == 1 {
        // The workload `exec`'d the helper with nothing to run after the
        // branchpoint, so it is now the container's PID 1. Returning would end
        // PID 1 and the runtime would tear the container down with the very
        // processes the branch preserved. Become the container's init instead
        // — the same reaper every workload container runs — by `exec`ing into
        // it: exec keeps this PID and its children but replaces the process
        // image, so the init starts single-threaded whatever this helper had
        // running, which its per-thread signal mask depends on.
        // This helper is the agent binary invoked by name, and the same binary
        // in `container-init` mode is the reaper; `/proc/self/exe` is always
        // it, whatever is or is not mounted into this container.
        use std::os::unix::process::CommandExt;
        let error = std::process::Command::new("/proc/self/exe")
            .arg0(CONTAINER_INIT_NAME)
            .arg(CONTAINER_INIT_ARG)
            .exec();
        // Only reachable if exec itself failed; fall back to the in-process
        // reaper rather than end PID 1.
        eprintln!("smolvm-branch-ready: exec container-init: {error}; reaping in-process");
        return crate::process::run_container_init();
    }
    // Inline use from a shell: `eval "$(smolvm-branch-ready)"` exports the
    // identity into the calling script. Same rendering the host installs, so
    // every value is quoted correctly.
    print!("{}", render_identity_exports(&identity));
    let _ = std::io::Write::flush(&mut std::io::stdout());
    0
}

/// Split the helper's arguments: the optional `--cuda-preload-modules` flag,
/// and everything after `--` as the program to exec once released.
fn parse_helper_args<I: Iterator<Item = std::ffi::OsString>>(
    args: I,
) -> (bool, Option<Vec<std::ffi::OsString>>) {
    let mut preload = false;
    let mut command: Option<Vec<std::ffi::OsString>> = None;
    for argument in args {
        if let Some(rest) = &mut command {
            rest.push(argument);
        } else if argument == "--" {
            command = Some(Vec::new());
        } else if argument == "--cuda-preload-modules" {
            preload = true;
        }
    }
    let command = command.filter(|c| !c.is_empty());
    (preload, command)
}

/// The child's identity as installed by the host, read from the dotenv form
/// (`KEY=VALUE`, one per line, values never contain newlines). Absent for a
/// source or a single branch, which carry no per-child parameters.
/// The child's identity: the `KEY=VALUE` lines the release marker carries,
/// delivered in the same atomic rename as the go-ahead. A clone released with
/// no parameters (a plain single branch) has none.
fn load_identity(release_path: &Path) -> Vec<(String, String)> {
    std::fs::read_to_string(release_path)
        .map(|marker| parse_dotenv(marker.lines().skip(1)))
        .unwrap_or_default()
}

fn parse_dotenv<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    lines
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Render the identity as `export KEY='VALUE'` lines, quoted so a shell can
/// `eval` them for any value the host admits.
fn render_identity_exports(identity: &[(String, String)]) -> String {
    let mut out = String::new();
    for (k, v) in identity {
        out.push_str("export ");
        out.push_str(k);
        out.push_str("='");
        out.push_str(&v.replace('\'', "'\\''"));
        out.push_str("'\n");
    }
    out
}

fn run_helper_inner(preload_modules: bool) -> Result<(), String> {
    if !enabled() {
        return Err(
            "this machine is not branchable; start it with `smolvm machine start --branchable`"
                .to_string(),
        );
    }
    run_helper_at(
        ForkpointPaths {
            state_dir: Path::new(STATE_DIR),
            ready_path: Path::new(READY_PATH),
            restored_path: Path::new(RESTORED_PATH),
            release_path: Path::new(RELEASE_PATH),
            arm_path: Path::new(ARM_PATH),
            armed_path: Path::new(ARMED_PATH),
        },
        Duration::from_millis(20),
        preload_modules,
    )
}

struct ForkpointPaths<'a> {
    state_dir: &'a Path,
    ready_path: &'a Path,
    restored_path: &'a Path,
    release_path: &'a Path,
    arm_path: &'a Path,
    armed_path: &'a Path,
}

fn run_helper_at(
    paths: ForkpointPaths<'_>,
    poll_interval: Duration,
    preload_modules: bool,
) -> Result<(), String> {
    let ForkpointPaths {
        state_dir,
        ready_path,
        restored_path,
        release_path,
        arm_path,
        armed_path,
    } = paths;
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("create {}: {error}", state_dir.display()))?;
    let _ = std::fs::remove_file(release_path);

    let generation = forkpoint_generation()?;
    let ready_temp = state_dir.join(format!(".ready.{}.tmp", std::process::id()));
    let mut ready = std::fs::File::create(&ready_temp)
        .map_err(|error| format!("create {}: {error}", ready_temp.display()))?;
    let ready_content = ready_content(preload_modules, &generation);
    ready
        .write_all(ready_content.as_bytes())
        .map_err(|error| format!("write {}: {error}", ready_temp.display()))?;
    ready
        .sync_all()
        .map_err(|error| format!("sync {}: {error}", ready_temp.display()))?;
    // The ready marker is a lease, not merely a file. Keeping this lock for
    // the entire parked lifetime lets the agent reject a stale marker after a
    // helper is killed, including after restoring a portable checkpoint.
    if unsafe { libc::flock(std::os::fd::AsRawFd::as_raw_fd(&ready), libc::LOCK_EX) } != 0 {
        let error = std::io::Error::last_os_error();
        let _ = std::fs::remove_file(&ready_temp);
        return Err(format!("lock {}: {error}", ready_temp.display()));
    }
    std::fs::rename(&ready_temp, ready_path).map_err(|error| {
        let _ = std::fs::remove_file(&ready_temp);
        format!(
            "publish {} as {}: {error}",
            ready_temp.display(),
            ready_path.display()
        )
    })?;
    eprintln!("smolvm branch point ready; waiting for child release");
    let _ = std::io::stdout().flush();

    let mut watcher = crate::dirwatch::DirWatcher::new(state_dir).ok();

    // The host arms the source immediately before capture and parks it again
    // afterwards. While parked the helper sleeps on directory events
    // (bounded, so a PID-1 helper still reaps); while armed it sleeps on the
    // same events with no time limit, which holds no kernel timer and so wakes
    // correctly in the source and in every restored clone once its own state
    // directory changes.
    while !restored_path.is_file() {
        // Every wake reaps first — including the wake for the arm marker,
        // so a job that exited while parked is collected before capture and
        // never baked into a clone as a zombie.
        reap_children_if_init();
        if release_matches(release_path, &generation) {
            acknowledge_release(ready_path, restored_path, &generation);
            return Ok(());
        }
        if arm_matches(arm_path, &generation) {
            publish_generation_marker(armed_path, ARMED_PREFIX, &generation)?;
            while !restored_path.is_file() && arm_matches(arm_path, &generation) {
                if release_matches(release_path, &generation) {
                    let _ = std::fs::remove_file(armed_path);
                    acknowledge_release(ready_path, restored_path, &generation);
                    return Ok(());
                }
                match watcher.as_ref().map(|w| w.wait(None)) {
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {
                        watcher = None;
                        std::thread::yield_now();
                    }
                }
            }
            let _ = std::fs::remove_file(armed_path);
        } else if !wait_for_change(&mut watcher, poll_interval) {
            std::thread::sleep(poll_interval);
        }
    }

    // A restored clone waits here for its release; a held slot may wait a
    // long time, so this is the bounded event wait again, not a poll.
    loop {
        if release_matches(release_path, &generation) {
            acknowledge_release(ready_path, restored_path, &generation);
            return Ok(());
        }
        reap_children_if_init();
        if !wait_for_change(&mut watcher, poll_interval) {
            std::thread::sleep(poll_interval);
        }
    }
}

/// The bounded parked wait: sleep on directory events for at most a second so
/// a PID-1 helper reaps promptly; a timeout counts as a wake. Returns false
/// when no watch is available (and drops a failed one), so the caller polls.
fn wait_for_change(watcher: &mut Option<crate::dirwatch::DirWatcher>, floor: Duration) -> bool {
    let bound = Duration::from_secs(1).max(floor);
    match watcher.as_ref().map(|w| w.wait(Some(bound))) {
        Some(Ok(_)) => true,
        Some(Err(_)) => {
            *watcher = None;
            false
        }
        None => false,
    }
}

/// Publish the host-issued activation token after clone-local setup completes.
pub fn run_worker_ready_helper() -> i32 {
    let env_path = if Path::new(BRANCH_ENV_PATH).is_file() {
        BRANCH_ENV_PATH
    } else {
        FORK_ENV_PATH
    };
    if let Err(error) = write_worker_ready_at(
        Path::new(STATE_DIR),
        Path::new(env_path),
        Path::new(WORKER_READY_PATH),
    ) {
        eprintln!("smolvm-worker-ready: {error}");
        return 1;
    }
    0
}

/// The value of `key` on a fork/branch env line, in either form the host
/// writes: dotenv `KEY=VALUE` (the `fork-env` file) or the sourceable
/// `export KEY='VALUE'` (the `branch-env` file, single-quoted with `'\''`
/// escapes so a shell can `.`-source it).
fn env_line_value(line: &str, key: &str) -> Option<String> {
    let line = line.strip_prefix("export ").unwrap_or(line);
    let rest = line.strip_prefix(key)?.strip_prefix('=')?;
    let value = match rest.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        Some(quoted) => quoted.replace("'\\''", "'"),
        None => rest.to_string(),
    };
    Some(value)
}

fn worker_ready_token(env_path: &Path) -> Result<String, String> {
    let contents = std::fs::read_to_string(env_path)
        .map_err(|error| format!("read {}: {error}", env_path.display()))?;
    let mut matches = contents
        .lines()
        .filter_map(|line| env_line_value(line, WORKER_READY_TOKEN_ENV));
    let token: String = matches
        .next()
        .ok_or_else(|| format!("{WORKER_READY_TOKEN_ENV} is not configured for this lease"))?;
    if matches.next().is_some() {
        return Err(format!("{WORKER_READY_TOKEN_ENV} is duplicated"));
    }
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{WORKER_READY_TOKEN_ENV} must be 64 hexadecimal characters"
        ));
    }
    Ok(token.to_ascii_lowercase())
}

fn write_worker_ready_at(
    state_dir: &Path,
    env_path: &Path,
    worker_ready_path: &Path,
) -> Result<(), String> {
    std::fs::create_dir_all(state_dir)
        .map_err(|error| format!("create {}: {error}", state_dir.display()))?;
    let token = worker_ready_token(env_path)?;
    let temporary = state_dir.join(format!(".worker-ready.{}", std::process::id()));
    let _ = std::fs::remove_file(&temporary);
    let mut marker = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    if let Err(error) = marker
        .write_all(format!("{token}\n").as_bytes())
        .and_then(|()| marker.sync_all())
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("write {}: {error}", temporary.display()));
    }
    std::fs::rename(&temporary, worker_ready_path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("publish {}: {error}", worker_ready_path.display())
    })
}

fn forkpoint_generation() -> Result<String, String> {
    let mut bytes = [0_u8; 16];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(&mut bytes))
        .map_err(|error| format!("generate forkpoint token: {error}"))?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn ready_content(preload_modules: bool, generation: &str) -> String {
    if preload_modules {
        format!(
            "{READY_VERSION}\n{GENERATION_PREFIX}{generation}\n{READY_LEASE_HINT}\n\
             {CUDA_PRELOAD_MODULES_HINT}\n"
        )
    } else {
        format!("{READY_VERSION}\n{GENERATION_PREFIX}{generation}\n{READY_LEASE_HINT}\n")
    }
}

/// The marker's first line is the token; identity lines may follow it.
fn release_matches(release_path: &Path, generation: &str) -> bool {
    std::fs::read_to_string(release_path).is_ok_and(|release| {
        let token = release.lines().next().unwrap_or("").trim();
        token == format!("{RELEASE_PREFIX}{generation}")
    })
}

fn arm_matches(arm_path: &Path, generation: &str) -> bool {
    marker_matches(arm_path, ARM_PREFIX, generation)
}

fn marker_matches(path: &Path, prefix: &str, generation: &str) -> bool {
    std::fs::read_to_string(path)
        .is_ok_and(|marker| marker.trim() == format!("{prefix}{generation}"))
}

fn publish_generation_marker(path: &Path, prefix: &str, generation: &str) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent", path.display()))?;
    let temporary = parent.join(format!(".armed.{}.tmp", std::process::id()));
    let mut marker = std::fs::File::create(&temporary)
        .map_err(|error| format!("create {}: {error}", temporary.display()))?;
    if let Err(error) = marker
        .write_all(format!("{prefix}{generation}\n").as_bytes())
        .and_then(|()| marker.sync_all())
    {
        let _ = std::fs::remove_file(&temporary);
        return Err(format!("write {}: {error}", temporary.display()));
    }
    std::fs::rename(&temporary, path).map_err(|error| {
        let _ = std::fs::remove_file(&temporary);
        format!("publish {}: {error}", path.display())
    })
}

fn acknowledge_generation(ready_path: &Path, generation: &str) {
    let is_current = std::fs::read_to_string(ready_path).is_ok_and(|ready| {
        ready
            .lines()
            .any(|line| line == format!("{GENERATION_PREFIX}{generation}"))
    });
    if is_current {
        let _ = std::fs::remove_file(ready_path);
    }
}

fn acknowledge_release(ready_path: &Path, restored_path: &Path, generation: &str) {
    acknowledge_generation(ready_path, generation);
    // `restored` describes only the inherited helper's first wait. Once that
    // helper is released, leaving the marker behind would make every future
    // branchpoint helper ignore capture-arm requests, preventing a restored
    // machine from becoming a branch source itself.
    let _ = std::fs::remove_file(restored_path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oci::{OciSpec, ProcessIdentity};

    fn wait_for_marker(path: &Path) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !path.is_file() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            path.is_file(),
            "marker was not published: {}",
            path.display()
        );
    }

    fn marker_generation(path: &Path) -> String {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix(GENERATION_PREFIX))
            .unwrap()
            .to_string()
    }

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

    #[test]
    fn ordinary_container_does_not_receive_helper() {
        let mut spec = spec();
        inject_into_container_if(&mut spec, false, "/missing-agent", "/missing-state");
        assert!(spec
            .mounts
            .iter()
            .all(|mount| mount.destination != HELPER_PATH
                && mount.destination != BRANCH_HELPER_PATH
                && mount.destination != WORKER_READY_HELPER_PATH));
    }

    #[test]
    fn forkable_container_mounts_helper_and_state() {
        let temp = tempfile::tempdir().unwrap();
        let agent = temp.path().join("smolvm-agent");
        let state = temp.path().join("forkpoint");
        std::fs::write(&agent, b"agent").unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(&state).unwrap();
        let mut spec = spec();
        inject_into_container_if(
            &mut spec,
            true,
            agent.to_str().unwrap(),
            state.to_str().unwrap(),
        );
        let helper = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == HELPER_PATH)
            .unwrap();
        assert_eq!(helper.source, agent.to_str().unwrap());
        assert!(helper.options.iter().any(|option| option == "ro"));
        let branch_helper = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == BRANCH_HELPER_PATH)
            .unwrap();
        assert_eq!(branch_helper.source, agent.to_str().unwrap());
        assert!(branch_helper.options.iter().any(|option| option == "ro"));
        let worker_ready_helper = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == WORKER_READY_HELPER_PATH)
            .unwrap();
        assert_eq!(worker_ready_helper.source, agent.to_str().unwrap());
        assert!(worker_ready_helper
            .options
            .iter()
            .any(|option| option == "ro"));
        assert!(spec.process.env.contains(&format!(
            "{}={}",
            smolvm_protocol::guest_env::FORKABLE,
            smolvm_protocol::guest_env::VALUE_ON
        )));
        let state_mount = spec
            .mounts
            .iter()
            .find(|mount| mount.destination == STATE_DIR)
            .unwrap();
        assert_eq!(state_mount.source, state.to_str().unwrap());
        assert!(!state_mount.options.iter().any(|option| option == "ro"));
    }

    #[test]
    fn exec_env_carries_the_branchable_flag_exactly_once() {
        let key = smolvm_protocol::guest_env::FORKABLE;
        let mut env = vec![
            ("USER_VALUE".to_string(), "kept".to_string()),
            (key.to_string(), "stale".to_string()),
        ];

        augment_exec_env_if(&mut env, true);
        assert!(env.contains(&("USER_VALUE".to_string(), "kept".to_string())));
        assert_eq!(
            env.iter().filter(|(existing, _)| existing == key).count(),
            1
        );
        assert!(env.contains(&(
            key.to_string(),
            smolvm_protocol::guest_env::VALUE_ON.to_string()
        )));

        augment_exec_env_if(&mut env, false);
        assert!(env.iter().all(|(existing, _)| existing != key));
    }

    #[test]
    fn helper_blocks_until_release_marker() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let ready = state.join("ready");
        let restored = state.join("restored");
        let release = state.join("release");
        let arm = state.join("arm");
        let armed = state.join("armed");
        std::fs::create_dir(&state).unwrap();

        let state_thread = state.clone();
        let ready_thread = ready.clone();
        let release_thread = release.clone();
        let helper = std::thread::spawn(move || {
            run_helper_at(
                ForkpointPaths {
                    state_dir: &state_thread,
                    ready_path: &ready_thread,
                    restored_path: &state_thread.join("restored"),
                    release_path: &release_thread,
                    arm_path: &state_thread.join("arm"),
                    armed_path: &state_thread.join("armed"),
                },
                Duration::from_millis(1),
                false,
            )
        });
        wait_for_marker(&ready);
        let generation = marker_generation(&ready);
        assert_eq!(
            std::fs::read_to_string(&ready).unwrap(),
            ready_content(false, &generation)
        );
        assert!(!helper.is_finished());
        std::fs::write(&restored, b"restored\n").unwrap();
        std::fs::write(&release, format!("{RELEASE_PREFIX}{generation}\n")).unwrap();
        helper.join().unwrap().unwrap();
        assert!(!ready.exists());
        assert!(!restored.exists());
        assert!(!arm.exists());
        assert!(!armed.exists());
    }

    #[test]
    fn helper_can_release_before_restored_waits_are_armed() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let ready = state.join("ready");
        let restored = state.join("restored");
        let release = state.join("release");
        std::fs::create_dir(&state).unwrap();

        let state_thread = state.clone();
        let ready_thread = ready.clone();
        let restored_thread = restored.clone();
        let release_thread = release.clone();
        let helper = std::thread::spawn(move || {
            run_helper_at(
                ForkpointPaths {
                    state_dir: &state_thread,
                    ready_path: &ready_thread,
                    restored_path: &restored_thread,
                    release_path: &release_thread,
                    arm_path: &state_thread.join("arm"),
                    armed_path: &state_thread.join("armed"),
                },
                Duration::from_secs(60),
                false,
            )
        });
        wait_for_marker(&ready);
        let generation = marker_generation(&ready);
        assert!(!restored.exists());
        std::fs::write(&release, format!("{RELEASE_PREFIX}{generation}\n")).unwrap();
        helper.join().unwrap().unwrap();
        assert!(!ready.exists());
    }

    #[test]
    fn armable_helper_sleeps_until_capture_and_parks_again_after_disarm() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let ready = state.join("ready");
        let restored = state.join("restored");
        let release = state.join("release");
        let arm = state.join("arm");
        let armed = state.join("armed");
        std::fs::create_dir(&state).unwrap();

        let state_thread = state.clone();
        let ready_thread = ready.clone();
        let restored_thread = restored.clone();
        let release_thread = release.clone();
        let arm_thread = arm.clone();
        let armed_thread = armed.clone();
        let helper = std::thread::spawn(move || {
            run_helper_at(
                ForkpointPaths {
                    state_dir: &state_thread,
                    ready_path: &ready_thread,
                    restored_path: &restored_thread,
                    release_path: &release_thread,
                    arm_path: &arm_thread,
                    armed_path: &armed_thread,
                },
                Duration::from_millis(1),
                false,
            )
        });
        wait_for_marker(&ready);
        let generation = marker_generation(&ready);
        assert!(!armed.exists());

        std::fs::write(&arm, format!("{ARM_PREFIX}{generation}\n")).unwrap();
        wait_for_marker(&armed);
        assert!(marker_matches(&armed, ARMED_PREFIX, &generation));
        std::fs::remove_file(&arm).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while armed.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!armed.exists());
        assert!(!helper.is_finished());

        std::fs::write(&arm, format!("{ARM_PREFIX}{generation}\n")).unwrap();
        wait_for_marker(&armed);
        std::fs::write(&restored, b"restored\n").unwrap();
        std::fs::write(&release, format!("{RELEASE_PREFIX}{generation}\n")).unwrap();
        helper.join().unwrap().unwrap();
        assert!(!ready.exists());
        assert!(!restored.exists());
        assert!(!armed.exists());
    }

    /// Both files the host writes must yield the same value: the dotenv
    /// `fork-env` and the sourceable `branch-env`, quotes and escapes included.
    #[test]
    fn env_line_value_reads_dotenv_and_sourceable_forms() {
        assert_eq!(env_line_value("K=abc", "K").as_deref(), Some("abc"));
        assert_eq!(
            env_line_value("export K='abc'", "K").as_deref(),
            Some("abc")
        );
        assert_eq!(
            env_line_value("export K='a=b c'", "K").as_deref(),
            Some("a=b c")
        );
        assert_eq!(
            env_line_value("export Q='it'\\''s'", "Q").as_deref(),
            Some("it's")
        );
        assert_eq!(env_line_value("KX=abc", "K"), None);
        assert_eq!(env_line_value("export OTHER='1'", "K"), None);
    }

    /// `--` starts the program to exec on release; flags before it are the
    /// helper's own; a bare `--` means no program.
    #[test]
    fn helper_args_split_flags_from_the_program() {
        let os = |v: &[&str]| v.iter().map(std::ffi::OsString::from).collect::<Vec<_>>();
        assert_eq!(parse_helper_args(os(&[]).into_iter()), (false, None));
        assert_eq!(
            parse_helper_args(os(&["--cuda-preload-modules"]).into_iter()),
            (true, None)
        );
        assert_eq!(
            parse_helper_args(os(&["--", "python3", "run.py", "--flag"]).into_iter()),
            (false, Some(os(&["python3", "run.py", "--flag"])))
        );
        // a flag after `--` belongs to the program, not to us
        assert_eq!(
            parse_helper_args(os(&["--", "prog", "--cuda-preload-modules"]).into_iter()),
            (false, Some(os(&["prog", "--cuda-preload-modules"])))
        );
        assert_eq!(parse_helper_args(os(&["--"]).into_iter()), (false, None));
    }

    /// Identity comes from the release marker's own lines, rendered as
    /// `export` lines a shell can eval with quoting intact; a marker without
    /// them falls back to the dotenv file, and no file is simply no identity.
    #[test]
    fn identity_loads_from_dotenv_and_renders_for_eval() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release");
        std::fs::write(
            &release,
            format!("{RELEASE_PREFIX}abc\nSMOLVM_BRANCH_NAME=agent-3\nNOTE=a=b c\nQ=it's\n"),
        )
        .unwrap();
        let identity = load_identity(&release);
        assert_eq!(
            identity,
            vec![
                ("SMOLVM_BRANCH_NAME".to_string(), "agent-3".to_string()),
                ("NOTE".to_string(), "a=b c".to_string()),
                ("Q".to_string(), "it's".to_string()),
            ]
        );
        assert_eq!(
            render_identity_exports(&identity),
            "export SMOLVM_BRANCH_NAME='agent-3'\nexport NOTE='a=b c'\nexport Q='it'\\''s'\n"
        );
        // A marker with only its token line is a clone with no parameters.
        std::fs::write(&release, format!("{RELEASE_PREFIX}abc\n")).unwrap();
        assert!(load_identity(&release).is_empty());
        assert!(load_identity(&temp.path().join("absent")).is_empty());
        assert_eq!(render_identity_exports(&[]), "");
    }

    #[test]
    fn worker_ready_helper_atomically_publishes_the_lease_token() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let env = temp.path().join("fork-env");
        let marker = state.join("worker-ready");
        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        std::fs::write(
            &env,
            format!("LEARNER=3\n{WORKER_READY_TOKEN_ENV}={token}\n"),
        )
        .unwrap();

        write_worker_ready_at(&state, &env, &marker).unwrap();

        assert_eq!(
            std::fs::read_to_string(marker).unwrap(),
            format!("{token}\n")
        );
        assert!(std::fs::read_dir(state).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with('.')));
    }

    #[test]
    fn worker_ready_helper_rejects_missing_duplicate_or_invalid_tokens() {
        let temp = tempfile::tempdir().unwrap();
        let state = temp.path().join("forkpoint");
        let env = temp.path().join("fork-env");
        let marker = state.join("worker-ready");
        for contents in [
            "LEARNER=3\n".to_string(),
            format!(
                "{WORKER_READY_TOKEN_ENV}={}\n{WORKER_READY_TOKEN_ENV}={}\n",
                "a".repeat(64),
                "b".repeat(64)
            ),
            format!("{WORKER_READY_TOKEN_ENV}=not-a-token\n"),
        ] {
            std::fs::write(&env, contents).unwrap();
            assert!(write_worker_ready_at(&state, &env, &marker).is_err());
            assert!(!marker.exists());
        }
    }

    #[test]
    fn helper_records_cuda_module_preload_hint() {
        assert_eq!(
            ready_content(true, "0123"),
            "smolvm-forkpoint-v1\ngeneration=0123\nready-lease=flock-v1\n\
             cuda-preload-modules\n"
        );
        assert_eq!(
            ready_content(false, "0123"),
            "smolvm-forkpoint-v1\ngeneration=0123\nready-lease=flock-v1\n"
        );
    }

    #[test]
    fn release_requires_its_generation() {
        let temp = tempfile::tempdir().unwrap();
        let release = temp.path().join("release");
        std::fs::write(&release, format!("{RELEASE_PREFIX}old\n")).unwrap();
        assert!(!release_matches(&release, "new"));
        assert!(release_matches(&release, "old"));

        // Identity lines after the token do not disturb the match.
        std::fs::write(&release, format!("{RELEASE_PREFIX}new\nLR=3e-4\n")).unwrap();
        assert!(release_matches(&release, "new"));
        assert!(!release_matches(&release, "old"));
    }
}
