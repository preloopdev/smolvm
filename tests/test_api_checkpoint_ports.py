#!/usr/bin/env python3
"""Checkpoint a live branch and restore two independently reachable services.

Run against a dedicated privileged local serve:
    python3 tests/test_api_checkpoint_ports.py http://127.0.0.1:8080
Only uniquely named test machines are deleted. Requires registry access.
"""
import json
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def main():
    base = sys.argv[1].rstrip('/') + '/api/v1/machines'
    prefix = 'checkpoint-ports-' + uuid.uuid4().hex[:10]
    names = [prefix + suffix for suffix in ('-source', '-child', '-one', '-two', '-bad')]
    source, child, first, second, bad = names

    def call(method, path, payload=None):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(payload or {}).encode() if method == 'POST' else None,
            headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, timeout=300) as response:
            return json.load(response)

    def execute(name, command):
        result = call('POST', '/' + name + '/exec', {'command': ['sh', '-c', command]})
        assert result['exitCode'] == 0, result
        return result['stdout']

    def http_marker(name, expected):
        port = call('GET', '/' + name)['ports'][0]['host']
        deadline = time.monotonic() + 10
        while True:
            try:
                with urllib.request.urlopen(f'http://127.0.0.1:{port}/marker', timeout=2) as response:
                    assert response.read().decode() == expected
                return
            except (urllib.error.URLError, TimeoutError, ConnectionResetError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.1)

    try:
        call('POST', '', {'name': source, 'image': 'python:3.12-alpine',
            'network': True, 'networkBackend': 'virtio-net', 'cpus': 2,
            'memoryMb': 1024, 'storageGb': 4, 'overlayGb': 2,
            'cmd': ['python3', '-m', 'http.server', '8080', '--directory', '/root'],
            'ports': [{'host': free_port(), 'guest': 8080}]})
        call('POST', '/' + source + '/start?branchable=true')
        execute(source, 'echo source >/root/marker; echo ram >/dev/shm/marker')
        http_marker(source, 'source\n')
        call('POST', '/' + source + '/branches', {'name': child, 'branchable': True})
        execute(child, 'echo child >/root/marker')
        http_marker(child, 'child\n')
        with tempfile.TemporaryFile() as artifact:
            request = urllib.request.Request(base + '/' + child + '/checkpoint', method='POST')
            with urllib.request.urlopen(request, timeout=300) as response:
                while block := response.read(1024 * 1024):
                    artifact.write(block)

            def upload(name, ports):
                artifact.seek(0)
                query = urllib.parse.urlencode({'ports': json.dumps(ports)})
                request = urllib.request.Request(base + '/' + name + '/checkpoint?' + query,
                    method='PUT', data=artifact.read(), headers={
                        'Content-Type': 'application/vnd.smolmachines.checkpoint'})
                with urllib.request.urlopen(request, timeout=300) as response:
                    return json.load(response)

            try:
                upload(bad, [{'host': free_port(), 'guest': 9090}])
                raise AssertionError('accepted changed guest port')
            except urllib.error.HTTPError as error:
                assert error.code == 400, error.read()

            occupied = call('GET', '/' + child)['ports']
            upload(bad, occupied)
            try:
                call('POST', '/' + bad + '/start?forkable=true')
                raise AssertionError('accepted occupied host port')
            except urllib.error.HTTPError as error:
                detail = json.load(error)
                assert error.code == 409 and detail['code'] == 'PORT_IN_USE', detail
                assert str(occupied[0]['host']) in detail['error'], detail
                assert '8080' in detail['error'], detail
            call('DELETE', '/' + bad + '?force=true')

            for name in (first, second):
                assigned = [{'host': free_port(), 'guest': 8080}]
                info = upload(name, assigned)
                assert info['ports'] == assigned, info['ports']
                call('POST', '/' + name + '/start?forkable=true')
                assert execute(name, 'cat /dev/shm/marker') == 'ram\n'
                execute(name, f'echo {name} >/root/marker')
                http_marker(name, name + '\n')
            http_marker(source, 'source\n')
            http_marker(child, 'child\n')
            http_marker(first, first + '\n')
            http_marker(second, second + '\n')
        print('PASS: source, child, and two live restores retain isolated RAM/disk and HTTP services')
    finally:
        for name in reversed(names):
            try:
                call('DELETE', '/' + name + '?force=true')
            except urllib.error.HTTPError as error:
                if error.code != 404:
                    print('cleanup failed:', name, error.read().decode(), file=sys.stderr)


if __name__ == '__main__':
    main()
