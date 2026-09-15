#!/usr/bin/env bash
# Export a prepared registry image without registry access, then restore it.
set -euo pipefail
source "$(dirname "$0")/common.sh"
init_smolvm

source_name="cached-export-source-$$"
restored_name="cached-export-restored-$$"
result_dir=$(mktemp -d)
cleanup() {
    local result=$?
    "$SMOLVM" machine delete --name "$restored_name" --force || result=1
    "$SMOLVM" machine delete --name "$source_name" --force || result=1
    echo "Cached export test artifacts: $result_dir"
    exit "$result"
}
trap cleanup EXIT

"$SMOLVM" machine create --name "$source_name" --image alpine:3.21 --net --cpus 2 --mem 512 --storage 4
"$SMOLVM" machine start --name "$source_name"
"$SMOLVM" machine exec --name "$source_name" -- sh -ec '
    test -f /etc/alpine-release
    rm /etc/alpine-release
    printf changed > /etc/issue
    printf private > /root/export-marker
    chmod 640 /root/export-marker
    chown 1234:1234 /root/export-marker
    ln /root/export-marker /root/export-hardlink
    ln -s export-marker /root/export-symlink
    printf workspace > /workspace/export-marker
'
"$SMOLVM" machine stop --name "$source_name"
source_dir=$("$SMOLVM" machine data-dir --name "$source_name")
source_disk="$source_dir/storage.raw"
if [[ ! -f "$source_disk" ]]; then
    source_disk="$source_dir/storage.qcow2"
fi
sha256() {
    if command -v sha256sum >/dev/null; then
        sha256sum "$1"
    else
        shasum -a 256 "$1"
    fi
}
before=$(sha256 "$source_disk")

# The export helper disables networking. Invalid explicit proxies also make
# accidental re-pulls fail instead of letting this test pass online.
"$SMOLVM" pack create --from-vm "$source_name" --include-workspace \
    --proxy http://127.0.0.1:1 --no-proxy '' -o "$result_dir/machine" \
    > "$result_dir/export.log" 2>&1
grep -q "Reusing the machine's cached image layers" "$result_dir/export.log"
if grep -q 'Pulling .* in export VM' "$result_dir/export.log"; then
    echo "Unexpected registry pull"
    exit 1
fi
after=$(sha256 "$source_disk")
[[ "$before" == "$after" ]] || { echo "Export changed the source disk"; exit 1; }
"$SMOLVM" machine create --name "$restored_name" --from "$result_dir/machine.smolmachine"
"$SMOLVM" machine start --name "$restored_name"
verify_state() {
    "$SMOLVM" machine exec --name "$restored_name" -- sh -ec '
    test ! -e /etc/alpine-release
    test "$(cat /etc/issue)" = changed
    test "$(cat /root/export-symlink)" = private
    test "$(stat -c %a:%u:%g /root/export-marker)" = 640:1234:1234
    test "$(stat -c %i /root/export-marker)" = "$(stat -c %i /root/export-hardlink)"
    test "$(cat /workspace/export-marker)" = workspace
'
}
verify_state
# Artifact-sourced exports use the same helper and must keep working too.
"$SMOLVM" machine stop --name "$restored_name"
"$SMOLVM" pack create --from-vm "$restored_name" --include-workspace \
    -o "$result_dir/repacked" > "$result_dir/repack.log" 2>&1
"$SMOLVM" machine delete --name "$restored_name" --force
"$SMOLVM" machine create --name "$restored_name" --from "$result_dir/repacked.smolmachine"
"$SMOLVM" machine start --name "$restored_name"
verify_state
echo CACHED_EXPORT_RESTORE_PASS
