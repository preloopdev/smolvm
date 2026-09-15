#!/usr/bin/env python3
"""A failed image pull must not strand the cached manager's launch lock.

Run against a dedicated local serve: python3 tests/test_api_pull_retry.py URL
The loopback discard port is intentionally not a registry; no image is downloaded.
"""
import json
import sys
import urllib.error
import urllib.request
import uuid


def main():
    base = sys.argv[1].rstrip('/') + '/api/v1/machines'

    def call(method, path, body=None):
        request = urllib.request.Request(base + path, method=method,
            data=json.dumps(body or {}).encode() if method == 'POST' else None,
            headers={'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    for branchable in [False, True]:
        name = 'pull-retry-' + uuid.uuid4().hex[:10]
        try:
            status, result = call('POST', '', {'name': name,
                'image': '127.0.0.1:9/qa/retry:' + uuid.uuid4().hex,
                'network': True, 'cpus': 2, 'memoryMb': 512, 'storageGb': 2,
                'cmd': ['sleep', 'infinity']})
            assert status == 200, result
            for attempt in range(3):
                suffix = '?branchable=true' if branchable else ''
                status, result = call('POST', '/' + name + '/start' + suffix)
                assert status >= 400, result
                assert 'crane manifest failed' in result['error'], (attempt, result)
                assert 'already starting or running' not in result['error'], result
            status, result = call('GET', '/' + name)
            assert status == 200 and result['state'] == 'stopped', result
            assert result.get('pid') is None, result
            print('PASS repeated failed pulls', 'branchable' if branchable else 'ordinary', flush=True)
        finally:
            status, result = call('DELETE', '/' + name + '?force=true')
            assert status == 200, result


if __name__ == '__main__':
    main()
