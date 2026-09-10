//! Stable guest paths used to coordinate a live branch.

/// Directory privately inherited by each restored VM.
pub const STATE_DIR: &str = "/run/smolvm/forkpoint";

/// Marker written by the workload when it reaches a safe fork boundary.
pub const READY_PATH: &str = "/run/smolvm/forkpoint/ready";

/// First line of every supported forkpoint readiness marker.
pub const READY_VERSION: &str = "smolvm-forkpoint-v1";

/// Prefix of the per-invocation token in a readiness marker. The token lets a
/// releaser distinguish a new forkpoint from the previous helper's marker.
pub const GENERATION_PREFIX: &str = "generation=";

/// Readiness-marker capability indicating that the helper holds an advisory
/// lock on the marker for its entire parked lifetime. The agent uses the lock
/// to distinguish a live helper from a marker left behind by a killed process.
pub const READY_LEASE_HINT: &str = "ready-lease=flock-v1";

/// Optional readiness-marker capability requesting eager clone module loading.
pub const CUDA_PRELOAD_MODULES_HINT: &str = "cuda-preload-modules";

/// The agent capability the branch protocol requires: the branchpoint
/// handshake is driven by typed requests (`AgentRequest::Branchpoint*`) the
/// agent executes natively. A host refuses to branch a machine whose agent
/// does not advertise it, rather than degrading to an older mechanism.
pub const TYPED_BRANCHPOINT_CAPABILITY: &str = "branchpoint-typed-v1";

/// Error codes the agent returns for branchpoint requests, so the host can
/// act on the cause rather than parse a message.
pub mod typed_error {
    /// No `ready` marker: the workload has not declared a branchpoint.
    pub const NOT_READY: &str = "branchpoint.not_ready";
    /// The `ready` marker carries no usable generation.
    pub const BAD_GENERATION: &str = "branchpoint.bad_generation";
    /// The helper did not acknowledge within the protocol's window.
    pub const NO_ACK: &str = "branchpoint.no_ack";
    /// Another activation token already claimed this clone.
    pub const TOKEN_MISMATCH: &str = "branchpoint.token_mismatch";
    /// A filesystem step failed; the message names it.
    pub const IO: &str = "branchpoint.io";
}

/// Host marker that asks the branchpoint helper to enter its capture-safe loop.
pub const ARM_PATH: &str = "/run/smolvm/forkpoint/arm";

/// Helper acknowledgement that it is safe for the host to capture the vCPU.
pub const ARMED_PATH: &str = "/run/smolvm/forkpoint/armed";

/// Generation-addressed arm marker prefix.
pub const ARM_PREFIX: &str = "smolvm-forkpoint-arm-v1:";

/// Generation-addressed arm acknowledgement prefix.
pub const ARMED_PREFIX: &str = "smolvm-forkpoint-armed-v1:";

/// Marker written after a restored clone can safely enter ordinary timed waits.
pub const RESTORED_PATH: &str = "/run/smolvm/forkpoint/restored";

/// Container ID inherited with a live VM snapshot.
///
/// The restored container remains the owner of the workload's live process
/// state, but new commands must join its namespaces directly: a post-restore
/// `crun exec` can fail after trivial commands have already succeeded.
pub const RESTORED_CONTAINER_PATH: &str = "/run/smolvm/forkpoint/restored-container";

/// Marker written by the host after a clone is ready to resume.
///
/// Its first line is the release token (see [`RELEASE_PREFIX`]). A typed
/// agent appends the clone's identity as `KEY=VALUE` lines, so the helper
/// receives the go-ahead and the identity in one atomic rename and never has
/// to order this file against [`FORK_ENV_PATH`]; a marker with no such lines
/// is a clone with no parameters, such as a plain single branch.
pub const RELEASE_PATH: &str = "/run/smolvm/forkpoint/release";

/// Prefix of a generation-addressed release marker.
pub const RELEASE_PREFIX: &str = "smolvm-forkpoint-release-v2:";

/// Marker written after a released worker finishes clone-local preparation.
pub const WORKER_READY_PATH: &str = "/run/smolvm/forkpoint/worker-ready";

/// Per-clone environment installed by the host before workload release, as
/// plain dotenv (`KEY=VALUE` per line) for machine readers.
pub const FORK_ENV_PATH: &str = "/etc/smolvm/fork-env";

/// The same parameters as a shell-sourceable file (`export KEY='VALUE'`,
/// single-quoted). A workload that continues past `smolvm-branch-ready` runs
/// `. /etc/smolvm/branch-env` to take its identity into its environment.
pub const BRANCH_ENV_PATH: &str = "/etc/smolvm/branch-env";

/// Host-generated readiness token delivered through [`FORK_ENV_PATH`].
pub const WORKER_READY_TOKEN_ENV: &str = "SMOLVM_WORKER_READY_TOKEN";

/// Workload-facing helper installed in bare VMs and workload containers.
pub const HELPER_PATH: &str = "/usr/local/bin/smolvm-fork-ready";

/// Preferred branch-lifecycle alias for [`HELPER_PATH`].
pub const BRANCH_HELPER_PATH: &str = "/usr/local/bin/smolvm-branch-ready";

/// Argument that puts the agent binary into container-init mode: the reaper
/// every workload container runs as PID 1. A branch helper that finds itself
/// as PID 1 `exec`s its own binary with this argument on release, so it
/// becomes that init by construction — a fresh, single-threaded image — rather
/// than calling the reaper in-process and relying on no thread having been
/// spawned.
pub const CONTAINER_INIT_ARG: &str = "container-init";
/// `argv[0]` the helper gives that init, so it reads clearly in `ps`.
pub const CONTAINER_INIT_NAME: &str = "smolvm-container-init";

/// Helper used by a released workload after clone-local preparation finishes.
pub const WORKER_READY_HELPER_PATH: &str = "/usr/local/bin/smolvm-worker-ready";
