import json
import os
from pathlib import Path
import subprocess
import sys


def test_real_stdio_dispatch_and_profile_separation(tmp_path):
    from modules.storage import ScanStore
    ScanStore(tmp_path, 'selected').save('evidence-one', {'status': 'completed'},
        {'domain': 'example.invalid', 'http_headers': {'status': 200, 'headers': {}},
         'module_status': {'headers': 'completed'}})
    root = Path(__file__).resolve().parents[1]
    messages = [{'jsonrpc': '2.0', 'id': 1, 'method': 'initialize'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'},
                {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                 'params': {'name': 'flame_assess', 'arguments': {'assessment_id': 'evidence-one'}}},
                {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call',
                 'params': {'name': 'flame_scan_start', 'arguments': {}}},
                {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': []}]
    env = {'PATH': os.getenv('PATH', ''), 'HERMES_HOME': str(tmp_path / 'profile'),
           'FLAME_STATE_DIR': str(tmp_path), 'FLAME_PROFILE': 'selected'}
    result = subprocess.run([sys.executable, str(root / 'scripts/flame.py'), 'mcp'],
                            input=''.join(json.dumps(m) + '\n' for m in messages), text=True,
                            capture_output=True, env=env, timeout=10, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows[0]['result']['serverInfo']['name'] == 'flame-sword'
    assert len(rows[1]['result']['tools']) == 4
    data = json.loads(rows[2]['result']['content'][0]['text'])
    assert data['findings'][0]['rule'] == 'HEADER_NOSNIFF'
    assert rows[3]['result']['isError'] is True
    assert rows[4]['error']['code'] == -32600
    messages = [{'id': 1, 'method': 'tools/call', 'params': {
        'name': 'flame_runtime_status', 'arguments': {}}},
        {'id': 2, 'method': 'tools/call', 'params': {
         'name': 'flame_evidence_read', 'arguments': {'assessment_id': 'evidence-one'}}}]
    env['FLAME_PROFILE'] = 'different-profile'
    result = subprocess.run([sys.executable, str(root / 'scripts/flame.py'), 'mcp'],
                            input=''.join(json.dumps(m) + '\n' for m in messages), text=True,
                            capture_output=True, env=env, timeout=10, check=True)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert json.loads(rows[0]['result']['content'][0]['text'])['mithril_configured'] is False
    assert rows[1]['result']['isError'] is True
