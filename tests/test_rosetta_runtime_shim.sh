#!/usr/bin/env bash
#
# crun-rosetta dockerd default-runtime shim tests (no VM required).
#
# Unit-tests scripts/rosetta/crun-rosetta against synthetic OCI bundles with
# the host's sh + jq. The shim is baked into the agent rootfs by
# scripts/build-agent-rootfs.sh and wired as dockerd's default-runtime via
# scripts/rosetta/docker-daemon.json; its only job is editing the bundle's
# config.json before exec'ing crun, so a stub crun + a scratch bundle pin the
# whole contract without a VM.
#
#   ./tests/test_rosetta_runtime_shim.sh   # run directly
#   ./tests/run_tests.sh rosetta-shim      # via the orchestrator

source "$(dirname "$0")/common.sh"

SHIM="$PROJECT_ROOT/scripts/rosetta/crun-rosetta"
DAEMON_JSON="$PROJECT_ROOT/scripts/rosetta/docker-daemon.json"

if ! command -v jq >/dev/null 2>&1; then
    log_skip "jq not found on host; crun-rosetta suite needs it"
    exit 0
fi
if [[ ! -x "$SHIM" ]]; then
    log_fail "shim missing or not executable: $SHIM"
    exit 1
fi

echo ""
echo "=========================================="
echo "  crun-rosetta Runtime Shim Tests"
echo "=========================================="
echo ""

# Per-suite scratch space: a stub crun (records argv, configurable exit code)
# plus one bundle dir per test.
SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

CRUN_STUB="$SCRATCH/crun-stub"
STUB_ARGV="$SCRATCH/stub-argv"
cat > "$CRUN_STUB" <<'EOF'
#!/bin/sh
printf '%s\n' "$@" > "$CRUN_STUB_ARGV"
exit "${CRUN_STUB_EXIT:-0}"
EOF
chmod 755 "$CRUN_STUB"

# Empty stand-in for a machine without Rosetta, so negative tests don't depend
# on whether the HOST happens to have /mnt/rosetta/rosetta populated.
NO_ROSETTA="$SCRATCH/no-rosetta"
mkdir -p "$NO_ROSETTA"

# A bundle shaped like the ones dockerd/containerd write: pretty-printed
# config.json with a populated mounts array.
make_bundle() {
    local dir="$1"
    mkdir -p "$dir"
    cat > "$dir/config.json" <<'EOF'
{
    "ociVersion": "1.2.0",
    "process": {
        "user": {"uid": 0, "gid": 0},
        "args": ["/bin/sh"],
        "env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
        "cwd": "/"
    },
    "root": {"path": "rootfs"},
    "hostname": "c123",
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs",
         "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
        {"destination": "/sys", "type": "sysfs", "source": "sysfs",
         "options": ["nosuid", "noexec", "nodev", "ro"]}
    ],
    "linux": {
        "namespaces": [
            {"type": "pid"}, {"type": "network"}, {"type": "mount"}
        ]
    }
}
EOF
}

# Run the shim with a clean, explicit environment.
run_shim() {
    env CRUN_ROSETTA_PATH="$NO_ROSETTA" CRUN_ROSETTA_CRUN="$CRUN_STUB" \
        CRUN_STUB_ARGV="$STUB_ARGV" "$SHIM" "$@"
}

# Number of mounts in $1's config.json claiming /mnt/rosetta as destination.
rosetta_mount_count() {
    jq '[.mounts[]? | select(.destination == "/mnt/rosetta")] | length' "$1"
}

test_adds_readonly_mount_when_enabled() {
    local bundle="$SCRATCH/enabled"
    make_bundle "$bundle"

    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        "$SHIM" create --bundle "$bundle" ctr1 || return 1

    [[ "$(rosetta_mount_count "$bundle/config.json")" == "1" ]] || {
        echo "expected exactly one /mnt/rosetta mount, got:"
        jq '.mounts' "$bundle/config.json"
        return 1
    }
    local ro_src ro_opts
    ro_src="$(jq -r '.mounts[] | select(.destination == "/mnt/rosetta") | .source' "$bundle/config.json")"
    [[ "$ro_src" == "/mnt/rosetta" ]] || { echo "bad source: $ro_src"; return 1; }
    ro_opts="$(jq -c '[.mounts[] | select(.destination == "/mnt/rosetta") | .options[]]' "$bundle/config.json")"
    [[ "$ro_opts" == *'"bind"'* && "$ro_opts" == *'"ro"'* ]] || {
        echo "expected bind+ro options, got: $ro_opts"
        return 1
    }
    # Pre-existing mounts must survive the rewrite.
    [[ "$(jq '.mounts | length' "$bundle/config.json")" == "4" ]] || {
        echo "pre-existing mounts lost:"
        jq '.mounts' "$bundle/config.json"
        return 1
    }
    # The real runtime must be exec'd with the original argv.
    [[ "$(cat "$STUB_ARGV")" == $'create\n--bundle\n'"$bundle"$'\nctr1' ]] || {
        echo "stub crun argv mismatch:"
        cat "$STUB_ARGV"
        return 1
    }
}

test_noop_when_sentinel_unset() {
    local bundle="$SCRATCH/disabled"
    make_bundle "$bundle"
    cp "$bundle/config.json" "$SCRATCH/disabled.orig"

    run_shim create --bundle "$bundle" ctr2 || return 1

    # jq rewrites the doc in passing (formatting); the spec content must be
    # unchanged. -S canonicalizes key order for a semantic compare.
    [[ "$(jq -S . "$SCRATCH/disabled.orig")" == "$(jq -S . "$bundle/config.json")" ]] || {
        echo "config.json modified with SMOLVM_ROSETTA unset"
        return 1
    }
}

test_noop_when_sentinel_wrong_value() {
    local bundle="$SCRATCH/wrongval"
    make_bundle "$bundle"
    cp "$bundle/config.json" "$SCRATCH/wrongval.orig"

    # is_enabled() in crates/smolvm-agent/src/rosetta.rs requires exactly
    # VALUE_ON ("1"); anything else must leave the bundle alone.
    env SMOLVM_ROSETTA=0 CRUN_ROSETTA_PATH="$NO_ROSETTA" CRUN_ROSETTA_CRUN="$CRUN_STUB" \
        CRUN_STUB_ARGV="$STUB_ARGV" "$SHIM" create --bundle "$bundle" ctr3 || return 1

    [[ "$(jq -S . "$SCRATCH/wrongval.orig")" == "$(jq -S . "$bundle/config.json")" ]] || {
        echo "config.json modified with SMOLVM_ROSETTA=0"
        return 1
    }
}

test_translator_presence_alone_enables_injection() {
    # Exec'd (image) containers don't inherit PID 1's env, so SMOLVM_ROSETTA
    # is absent there even when Rosetta is on; the agent-injected runtime mount
    # is the signal instead. With the translator visible and the sentinel
    # unset, injection must still happen.
    local fake_share="$SCRATCH/rosetta-share"
    mkdir -p "$fake_share"
    touch "$fake_share/rosetta"
    local bundle="$SCRATCH/presence"
    make_bundle "$bundle"

    env CRUN_ROSETTA_PATH="$fake_share" CRUN_ROSETTA_CRUN="$CRUN_STUB" \
        CRUN_STUB_ARGV="$STUB_ARGV" "$SHIM" create --bundle "$bundle" ctr9 || return 1

    local opts
    opts="$(jq -c --arg d "$fake_share" \
        '[.mounts[] | select(.destination == $d) | .options[]]' "$bundle/config.json")"
    [[ "$opts" == *'"bind"'* && "$opts" == *'"ro"'* ]] || {
        echo "no ro bind mount injected for visible translator at $fake_share:"
        jq '.mounts' "$bundle/config.json"
        return 1
    }
}

test_user_mount_wins_no_duplicate() {
    local bundle="$SCRATCH/dup"
    make_bundle "$bundle"
    # The user's explicit `-v /mnt/rosetta:...` (here rw) already claims the
    # path; injection must not add a second mount or rewrite its options.
    jq '.mounts += [{
            destination: "/mnt/rosetta",
            type: "bind",
            source: "/mnt/rosetta",
            options: ["bind", "rw"]
        }]' "$bundle/config.json" > "$SCRATCH/dup.tmp" \
        && mv "$SCRATCH/dup.tmp" "$bundle/config.json"
    cp "$bundle/config.json" "$SCRATCH/dup.orig"

    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        "$SHIM" create --bundle "$bundle" ctr4 || return 1

    [[ "$(rosetta_mount_count "$bundle/config.json")" == "1" ]] || {
        echo "duplicate /mnt/rosetta mount injected:"
        jq '.mounts' "$bundle/config.json"
        return 1
    }
    cmp -s "$SCRATCH/dup.orig" "$bundle/config.json" || {
        echo "user mount rewritten:"
        jq '.mounts' "$bundle/config.json"
        return 1
    }
}

test_bundle_equals_form() {
    local bundle="$SCRATCH/eq"
    make_bundle "$bundle"

    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        "$SHIM" --log-format json create "--bundle=$bundle" ctr5 || return 1

    [[ "$(rosetta_mount_count "$bundle/config.json")" == "1" ]] || {
        echo "--bundle=PATH form not honored"
        return 1
    }
    [[ "$(cat "$STUB_ARGV")" == $'--log-format\njson\ncreate\n'"--bundle=$bundle"$'\nctr5' ]] || {
        echo "stub crun argv mismatch for --bundle= form:"
        cat "$STUB_ARGV"
        return 1
    }
}

test_no_bundle_is_passthrough() {
    # Runtime invocations without a bundle (state/kill/delete/features) must
    # reach crun untouched; run in an empty dir so any config.json write would
    # show up.
    local dir="$SCRATCH/nobundle"
    mkdir -p "$dir"

    run_shim --root /run/docker/runtime-runc kill ctr6 SIGKILL || return 1

    [[ "$(cat "$STUB_ARGV")" == $'--root\n/run/docker/runtime-runc\nkill\nctr6\nSIGKILL' ]] || {
        echo "stub crun argv mismatch on passthrough:"
        cat "$STUB_ARGV"
        return 1
    }
    [[ -z "$(ls -A "$dir")" ]] || { echo "bundle-less invocation created files"; return 1; }
}

test_invalid_json_never_blocks() {
    local bundle="$SCRATCH/badjson"
    mkdir -p "$bundle"
    printf 'not json' > "$bundle/config.json"

    # jq failing on the bundle must not stop the exec: container startup still
    # reaches crun (degraded translation, never a hard failure).
    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        "$SHIM" create --bundle "$bundle" ctr7 || return 1

    [[ "$(cat "$STUB_ARGV")" == $'create\n--bundle\n'"$bundle"$'\nctr7' ]] || {
        echo "crun not exec'd despite invalid config.json"
        return 1
    }
    [[ "$(cat "$bundle/config.json")" == "not json" ]] || {
        echo "invalid config.json was rewritten"
        return 1
    }
}

# Give $1's bundle dockerd's exact resources block: default device rules plus
# the always-present EMPTY blockIO section (see shim header).
add_docker_resources() {
    jq '.linux.resources = {
            devices: [{allow: false, access: "rwm"}],
            blockIO: {}
        }' "$1/config.json" > "$1/config.tmp" && mv "$1/config.tmp" "$1/config.json"
}

test_strips_empty_blockio_and_injects_when_enabled() {
    # dockerd-authored bundles always carry "blockIO": {}. crun errors on it
    # (`open `io.max``) because the libkrunfw kernel has no io.max/io.weight
    # files, so the shim must drop it while injecting the mount.
    local bundle="$SCRATCH/blockio"
    make_bundle "$bundle"
    add_docker_resources "$bundle"

    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        "$SHIM" create --bundle "$bundle" ctrA || return 1

    jq -e 'has("linux") and (.linux.resources.blockIO == null)' "$bundle/config.json" >/dev/null || {
        echo "empty blockIO not stripped:"
        jq '.linux.resources' "$bundle/config.json"
        return 1
    }
    # Device rules and the injected mount must both survive.
    jq -e '.linux.resources.devices | length == 1' "$bundle/config.json" >/dev/null || {
        echo "device rules lost:"
        jq '.linux.resources' "$bundle/config.json"
        return 1
    }
    [[ "$(rosetta_mount_count "$bundle/config.json")" == "1" ]] || {
        echo "rosetta mount missing alongside resources rewrite"
        return 1
    }
}

test_strips_empty_blockio_even_when_disabled() {
    # The strip is dockerd-vs-kernel normalization, not Rosetta behavior: a
    # non-Rosetta VM runs crun under dockerd too, and must start containers.
    local bundle="$SCRATCH/blockio-off"
    make_bundle "$bundle"
    add_docker_resources "$bundle"

    run_shim create --bundle "$bundle" ctrB || return 1

    jq -e '.linux.resources.blockIO == null' "$bundle/config.json" >/dev/null || {
        echo "empty blockIO kept when sentinel unset"
        return 1
    }
    [[ "$(rosetta_mount_count "$bundle/config.json")" == "0" ]] || {
        echo "mount injected without rosetta enabled"
        return 1
    }
}

test_preserves_non_empty_blockio() {
    # Real IO limits are the operator's intent, not normalization fodder.
    local bundle="$SCRATCH/blockio-real"
    make_bundle "$bundle"
    jq '.linux.resources = {blockIO: {weight: 500}}' "$bundle/config.json" \
        > "$SCRATCH/blockio-real.tmp" && mv "$SCRATCH/blockio-real.tmp" "$bundle/config.json"

    run_shim create --bundle "$bundle" ctrC || return 1

    jq -e '.linux.resources.blockIO.weight == 500' "$bundle/config.json" >/dev/null || {
        echo "non-empty blockIO rewritten:"
        jq '.linux.resources' "$bundle/config.json"
        return 1
    }
}

test_crun_exit_code_propagates() {
    local bundle="$SCRATCH/exitcode"
    make_bundle "$bundle"

    local exit_code=0
    env SMOLVM_ROSETTA=1 CRUN_ROSETTA_CRUN="$CRUN_STUB" CRUN_STUB_ARGV="$STUB_ARGV" \
        CRUN_STUB_EXIT=42 "$SHIM" start ctr8 2>/dev/null || exit_code=$?
    [[ "$exit_code" == "42" ]] || {
        echo "crun exit code 42 became $exit_code"
        return 1
    }
}

test_baked_daemon_json_wiring() {
    # The engine config baked to /etc/docker/daemon.json must parse, point
    # dockerd's default-runtime at the shim, and resolve that runtime to the
    # path the build script installs it at.
    jq -e '
        .["default-runtime"] == "crun-rosetta"
        and .runtimes["crun-rosetta"].path == "/usr/local/bin/crun-rosetta"
    ' "$DAEMON_JSON" >/dev/null || {
        echo "docker-daemon.json wiring mismatch:"
        cat "$DAEMON_JSON"
        return 1
    }
}

run_test "inject: adds ro /mnt/rosetta bind mount when SMOLVM_ROSETTA=1" test_adds_readonly_mount_when_enabled || true
run_test "inject: no-op when sentinel unset" test_noop_when_sentinel_unset || true
run_test "inject: no-op when sentinel is not \"1\"" test_noop_when_sentinel_wrong_value || true
run_test "inject: visible translator enables injection without env sentinel" test_translator_presence_alone_enables_injection || true
run_test "inject: user mount at /mnt/rosetta wins, no duplicate" test_user_mount_wins_no_duplicate || true
run_test "argv: --bundle=PATH form honored" test_bundle_equals_form || true
run_test "argv: bundle-less invocation passes through untouched" test_no_bundle_is_passthrough || true
run_test "shim: invalid config.json never blocks the exec" test_invalid_json_never_blocks || true
run_test "blockIO: dockerd's empty blockIO stripped + mount injected" test_strips_empty_blockio_and_injects_when_enabled || true
run_test "blockIO: stripped even when rosetta disabled (dockerd-under-crun works)" test_strips_empty_blockio_even_when_disabled || true
run_test "blockIO: real IO limits preserved" test_preserves_non_empty_blockio || true
run_test "shim: crun exit code propagates" test_crun_exit_code_propagates || true
run_test "wiring: baked daemon.json default-runtime points at the shim" test_baked_daemon_json_wiring || true

print_summary "crun-rosetta Runtime Shim Tests"
