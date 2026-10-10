#!/usr/bin/env python3
"""Local CLI and bounded MCP stdio surface for evidence and Code proposals."""
from pathlib import Path
import argparse
import json
import os
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from modules.evidence import normalize, assess
from modules.storage import ScanStore
from modules.coding import propose, validate_task

TOOLS = [
    {'name': 'flame_runtime_status', 'description': 'Read local readiness; performs no scan or inference.',
     'inputSchema': {'type': 'object', 'properties': {}, 'additionalProperties': False}},
    {'name': 'flame_evidence_read', 'description': 'Read bounded evidence owned by this configured profile.',
     'inputSchema': {'type': 'object', 'properties': {'assessment_id': {'type': 'string'}},
                     'required': ['assessment_id'], 'additionalProperties': False}},
    {'name': 'flame_assess', 'description': 'Evaluate measured header presence; no network or AI call.',
     'inputSchema': {'type': 'object', 'properties': {'assessment_id': {'type': 'string'}},
                     'required': ['assessment_id'], 'additionalProperties': False}},
    {'name': 'flame_code_propose', 'description': 'Explicitly send selected source to the fixed Code service. '
     'New requests incur inference. Returns an unverified proposal; never writes source.',
     'inputSchema': {'type': 'object', 'properties': {'task': {'type': 'object'}, 'request_id': {'type': 'string'},
                      'lookup_only': {'type': 'boolean'}}, 'required': ['task', 'request_id'], 'additionalProperties': False}},
]


def configure():
    from dotenv import load_dotenv
    from modules.secrets import load_mithril_key
    # Owning native profiles must supply their own config; never inherit this checkout's root key.
    path = os.getenv('FLAME_CONFIG_FILE')
    if path or not os.getenv('HERMES_HOME'):
        load_dotenv(path or ROOT / '.env', override=False)
    load_mithril_key()


def dispatch(name, args):
    tool = next((t for t in TOOLS if t['name'] == name), None)
    if not tool or not isinstance(args, dict):
        raise ValueError('Unknown tool or invalid arguments.')
    schema = tool['inputSchema']
    if set(args) - set(schema['properties']) or any(k not in args for k in schema.get('required', [])):
        raise ValueError('Invalid tool fields.')
    if name == 'flame_runtime_status':
        import shutil
        return {'format': 'flame.runtime/v1', 'profile': os.getenv('FLAME_PROFILE', 'local'),
                'nmap_available': bool(shutil.which('nmap')),
                'mithril_configured': bool(os.getenv('MITHRIL_API_KEY')),
                'capabilities': [t['name'] for t in TOOLS], 'native_scan_dispatch': False}
    if name == 'flame_code_propose':
        if not isinstance(args.get('lookup_only', False), bool):
            raise ValueError('lookup_only must be Boolean.')
        return propose(validate_task(args['task']), args['request_id'], args.get('lookup_only', False))
    scan_id = args['assessment_id']
    if not isinstance(scan_id, str) or not 1 <= len(scan_id) <= 128:
        raise ValueError('Invalid assessment ID.')
    _, report = ScanStore().read(scan_id)
    evidence = normalize(report)
    return evidence if name == 'flame_evidence_read' else assess(evidence)


def mcp():
    while True:
        line = sys.stdin.buffer.readline(1024 * 1024 + 1)
        if not line:
            break
        if len(line) > 1024 * 1024:
            while line and not line.endswith(b'\n'):
                line = sys.stdin.buffer.readline(1024 * 1024 + 1)
            continue
        request = None
        try:
            request = json.loads(line)
            if not isinstance(request, dict) or 'id' not in request:
                continue
            method = request.get('method')
            if method == 'initialize':
                result = {'protocolVersion': '2024-11-05', 'capabilities': {'tools': {}},
                          'serverInfo': {'name': 'flame-sword', 'version': '0.1.0'}}
            elif method == 'tools/list':
                result = {'tools': TOOLS}
            elif method == 'ping':
                result = {}
            elif method == 'tools/call':
                params = request.get('params', {})
                if not isinstance(params, dict):
                    raise ValueError('Invalid tool request.')
                try:
                    data = dispatch(params.get('name'), params.get('arguments', {}))
                    result = {'content': [{'type': 'text', 'text': json.dumps(data)}]}
                except (ValueError, TypeError, KeyError):
                    result = {'isError': True, 'content': [{'type': 'text', 'text': 'Tool refused; inspect local configuration and input scope.'}]}
            else:
                raise ValueError('Unsupported method.')
            response = {'jsonrpc': '2.0', 'id': request['id'], 'result': result}
        except (ValueError, TypeError, KeyError):
            response = {'jsonrpc': '2.0', 'id': request.get('id') if isinstance(request, dict) else None,
                        'error': {'code': -32600, 'message': 'Invalid or unsupported request.'}}
        print(json.dumps(response), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['status', 'import', 'evidence', 'assess', 'propose', 'mcp'])
    parser.add_argument('--assessment-id')
    parser.add_argument('--request-id')
    parser.add_argument('--lookup-only', action='store_true')
    args = parser.parse_args()
    configure()
    if args.action == 'mcp':
        mcp()
        return
    if args.action == 'import':
        raw = sys.stdin.buffer.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError('Report import exceeds 1 MiB.')
        report = json.loads(raw)
        if not isinstance(report, dict):
            raise ValueError('Report must be an object.')
        report['scan_id'] = str(uuid.uuid4())
        report['provenance'] = 'caller-supplied'
        report['execution'] = 'import'
        evidence = normalize(report)
        ScanStore().save(report['scan_id'], {'status': 'imported'}, report)
        result = {'assessment_id': report['scan_id'], 'source_sha256': evidence['source_sha256']}
    elif args.action == 'propose':
        raw = sys.stdin.buffer.read(98305)
        if len(raw) > 98304:
            raise ValueError('Task exceeds 96 KiB.')
        result = dispatch('flame_code_propose', {'task': json.loads(raw), 'request_id': args.request_id,
                                               'lookup_only': args.lookup_only})
    else:
        name = {'status': 'flame_runtime_status', 'evidence': 'flame_evidence_read', 'assess': 'flame_assess'}[args.action]
        result = dispatch(name, {} if args.action == 'status' else {'assessment_id': args.assessment_id})
    print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, TypeError, KeyError) as error:
        print(json.dumps({'error': str(error)}), file=sys.stderr)
        sys.exit(1)
