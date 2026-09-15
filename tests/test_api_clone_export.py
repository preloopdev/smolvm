#!/usr/bin/env python3
"""Export a stopped child and verify its imported state and source disk.

Run locally beside a dedicated serve, with QA_API, QA_BIN and SMOLVM_DATA_DIR
pointing to that instance. Both the server and this command must enforce Landlock.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.error
import urllib.request
import uuid


def main():
    base = os.environ["QA_API"].rstrip("/") + "/api/v1/machines"
    binary = os.environ["QA_BIN"]
    data_dir = Path(os.environ["SMOLVM_DATA_DIR"])
    assert os.environ.get("SMOLVM_LANDLOCK") == "enforce"
    source = "qa-export-parent-" + uuid.uuid4().hex[:8]
    child, restored = source + "-child", source + "-import"

    def call(method, path, body=None):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body or {}).encode() if method == "POST" else None,
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=600) as response:
            return json.load(response)

    def execute(name, command):
        result = call("POST", "/" + name + "/exec", {"command": ["sh", "-ec", command]})
        assert result["exitCode"] == 0, result
        return result["stdout"]

    try:
        call("POST", "", {"name": source, "image": "ubuntu:24.04", "network": True,
            "cpus": 2, "memoryMb": 1024, "storageGb": 4, "cmd": ["sleep", "infinity"]})
        call("POST", "/" + source + "/start?branchable=true")
        if os.environ.get("QA_REQUIRE_UID"):
            pid = call("GET", "/" + source)["pid"]
            status = Path(f"/proc/{pid}/status").read_text()
            uid = next(line for line in status.splitlines() if line.startswith("Uid:")).split()[2]
            assert int(uid) >= 2_000_000, status
            assert "smolvm-vm-" in Path(f"/proc/{pid}/cgroup").read_text()
            print("PASS source uses per-VM UID and systemd scope", flush=True)
        execute(source, "echo parent >/root/export-witness; echo remove >/root/delete-in-child")
        call("POST", "/" + source + "/branches", {"name": child, "branchable": True})
        execute(child, "echo child >/root/export-witness; rm /root/delete-in-child; "
                      "echo workspace >/workspace/export-witness")
        call("POST", "/" + child + "/stop")
        disk = (data_dir / ".cache/smolvm/vms" /
                hashlib.sha256(child.encode()).hexdigest()[:16] / "storage.qcow2")

        def digest():
            with disk.open("rb") as stream:
                return hashlib.file_digest(stream, "sha256").hexdigest()

        before = digest()
        uid_cache = disk.parent / ".vm-uid"
        uid_before = uid_cache.read_bytes() if uid_cache.exists() else None
        helpers_before = set(disk.parent.parent.glob("*/export-source.qcow2"))
        with tempfile.TemporaryDirectory(prefix="clone-export-") as directory:
            output = directory + "/child"
            subprocess.run([binary, "pack", "create", "--from-vm", child,
                "--include-workspace", "-o", output], check=True, timeout=600)
            assert digest() == before, "export changed the source disk"
            assert (uid_cache.read_bytes() if uid_cache.exists() else None) == uid_before, \
                "export changed the source UID allocation"
            assert set(disk.parent.parent.glob("*/export-source.qcow2")) == helpers_before, \
                "export left a scratch disk behind"
            call("POST", "", {"name": restored, "from": output + ".smolmachine", "network": True})
            call("POST", "/" + restored + "/start")
            assert execute(restored, "test ! -e /root/delete-in-child; "
                "cat /root/export-witness /workspace/export-witness") == "child\nworkspace\n"
            call("DELETE", "/" + restored + "?force=true")
        assert execute(source, "test -e /root/delete-in-child; cat /root/export-witness") == "parent\n"
        call("POST", "/" + child + "/start")
        assert execute(child, "test ! -e /root/delete-in-child; cat /root/export-witness") == "child\n"
        print("PASS clone export, import, source immutability and parent isolation")
    finally:
        for name in [restored, child, source]:
            try:
                call("DELETE", "/" + name + "?force=true")
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    raise


if __name__ == "__main__":
    main()
