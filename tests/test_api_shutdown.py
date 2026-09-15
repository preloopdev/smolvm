#!/usr/bin/env python3
"""Verify graceful stop/drain failures preserve a live VM and allow retry.

Runs a dedicated local server with temporary data, using SMOLVM_AGENT_ROOTFS
and SMOLVM_LIB_DIR from the environment; pass the smolvm binary as argv[1].
Requires a working local VM backend, but no image pull or external service.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def free_port():
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def main():
    with tempfile.TemporaryDirectory(prefix="shut-") as directory:
        root = Path(directory)
        port, rollout_port = free_port(), free_port()
        while rollout_port == port:
            rollout_port = free_port()
        base = f"http://127.0.0.1:{port}"
        env = dict(os.environ, SMOLVM_DATA_DIR=directory,
                   SMOLVM_GUEST_ROLLOUT_HOST_PORT=str(rollout_port))
        name = "shutdown-acceptance"
        machine = "/api/v1/machines/" + name

        def call(method, path, payload=None):
            request = urllib.request.Request(base + path, method=method,
                data=json.dumps(payload or {}).encode() if method == "POST" else None,
                headers={"Content-Type": "application/json"})
            try:
                response = urllib.request.urlopen(request, timeout=150)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                body = response.read()
                return response.status, json.loads(body) if body else None

        def raw_exec(command):
            path = root / ".cache/smolvm/vms" / hashlib.sha256(name.encode()).hexdigest()[:16]
            with socket.socket(socket.AF_UNIX) as stream:
                stream.settimeout(15)
                stream.connect(str(path / "agent.sock"))
                payload = json.dumps({"method": "vm_exec", "command": command,
                                      "timeout_ms": 10000}).encode()
                stream.sendall(struct.pack(">I", len(payload)) + payload)

                def exact(size):
                    data = b""
                    while len(data) < size:
                        part = stream.recv(size - len(data))
                        assert part, "agent closed response early"
                        data += part
                    return data

                result = json.loads(exact(struct.unpack(">I", exact(4))[0]))
                assert result.get("exit_code") == 0, result
                return result

        with (root / "serve.log").open("w+") as log:
            server = subprocess.Popen([sys.argv[1], "serve", "start", "--listen",
                f"127.0.0.1:{port}"], env=env, stdout=log, stderr=log)
            created = False
            try:
                for _ in range(100):
                    assert server.poll() is None, "isolated server exited"
                    try:
                        if call("GET", "/api/v1/machines")[0] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(0.1)
                else:
                    raise AssertionError("isolated server did not become ready")
                status, result = call("POST", "/api/v1/machines", {
                    "name": name, "cpus": 2, "memoryMb": 512, "storageGb": 1})
                assert status < 300, result
                created = True
                assert call("POST", machine + "/start")[0] == 200
                raw_exec(["sh", "-ec", "echo witness >/storage/shutdown-witness"])
                pid = call("GET", machine)[1]["pid"]
                raw_exec(["fsfreeze", "-f", "/storage"])
                assert call("POST", machine + "/stop")[0] >= 400
                assert call("POST", "/drain")[0] == 503
                os.kill(pid, 0)
                assert call("GET", machine)[1]["pid"] == pid
                raw_exec(["fsfreeze", "-u", "/storage"])
                raw_exec(["sh", "-ec", "echo retry >/storage/after-thaw"])
                assert call("POST", "/drain")[0] == 200
                assert call("GET", machine)[1].get("pid") is None
                assert call("POST", machine + "/start")[0] == 200
                raw_exec(["sh", "-ec", "test $(cat /storage/shutdown-witness) = witness; "
                          "test $(cat /storage/after-thaw) = retry"])
                assert call("POST", machine + "/stop")[0] == 200
                print("PASS stop/drain reject failed quiescence, preserve the VM, and retry safely")
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read(), file=sys.stderr)
                raise
            finally:
                try:
                    if created:
                        call("DELETE", machine + "?force=true")
                finally:
                    server.terminate()
                    server.wait(timeout=30)


if __name__ == "__main__":
    main()
