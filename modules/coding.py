"""Fixed Code-service refactor adapter; proposals never execute on the host."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import uuid

import requests

ORIGIN = 'https://code.mithril.fund'


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def valid_path(path):
    return (isinstance(path, str) and len(path) <= 240
            and re.fullmatch(r'([a-zA-Z0-9_.-]+/)*[a-zA-Z0-9_.-]+', path)
            and not any(p in ('.', '..', '.git', '.github', '.venv', 'node_modules')
                        or re.match(r'^(\.env|\.npmrc|\.netrc|credentials|secrets?|id_rsa|id_ed25519)', p, re.I)
                        for p in path.split('/'))
            and not re.search(r'\.(pem|key|p12|pfx)$', path, re.I))


def validate_task(task):
    if (not isinstance(task, dict) or set(task) != {'format', 'goal', 'files', 'editable_paths'}
            or task['format'] != 'mithril.code-refactor-task/v1'
            or not isinstance(task['goal'], str) or not 1 <= len(task['goal'].strip()) <= 4000
            or not isinstance(task['files'], list) or not 1 <= len(task['files']) <= 32
            or not isinstance(task['editable_paths'], list) or not 1 <= len(task['editable_paths']) <= 32):
        raise ValueError('Invalid selected-source task.')
    files, paths = [], set()
    for file in task['files']:
        if (not isinstance(file, dict) or set(file) != {'path', 'encoding', 'content'}
                or not valid_path(file['path']) or file['path'] in paths or file['encoding'] != 'utf-8'
                or not isinstance(file['content'], str) or '\0' in file['content']):
            raise ValueError('Invalid or private source file.')
        paths.add(file['path'])
        files.append({k: file[k] for k in ('path', 'encoding', 'content')})
    editable = task['editable_paths']
    if (not all(valid_path(p) for p in editable) or len(set(editable)) != len(editable)
            or len(paths | set(editable)) > 40):
        raise ValueError('Invalid edit scope.')
    result = {'format': task['format'], 'goal': task['goal'], 'files': files, 'editable_paths': editable}
    if len(json.dumps(result, ensure_ascii=False, separators=(',', ':')).encode()) > 98304:
        raise ValueError('Selected-source input exceeds 96 KiB.')
    return result


def task_identity(task):
    return sha(json.dumps(validate_task(task), ensure_ascii=False, separators=(',', ':')))


def candidate(task, proposal):
    task = validate_task(task)
    if (not isinstance(proposal, dict) or proposal.get('format') != 'mithril.code-refactor-proposal/v1'
            or proposal.get('verified') is not False or proposal.get('input_sha256') != task_identity(task)
            or not isinstance(proposal.get('changes'), list) or not 1 <= len(proposal['changes']) <= 32
            or len(json.dumps(proposal['changes'], ensure_ascii=False).encode()) > 49152):
        raise ValueError('Invalid or stale unverified proposal.')
    files = {f['path']: f['content'] for f in task['files']}
    seen = set()
    for change in proposal['changes']:
        if not isinstance(change, dict) or set(change) != {'path', 'before_sha256', 'content'}:
            raise ValueError('Invalid change shape.')
        path, content = change['path'], change['content']
        before = sha(files[path]) if path in files else None
        if (path not in task['editable_paths'] or path in seen or change['before_sha256'] != before
                or not (content is None or isinstance(content, str) and '\0' not in content)
                or content == files.get(path)):
            raise ValueError('Change is outside scope, duplicated or based on stale source.')
        seen.add(path)
        if content is None:
            files.pop(path, None)
        else:
            files[path] = content
    if len(files) > 40:
        raise ValueError('Candidate file budget exceeded.')
    return files


def propose(task, request_id, lookup_only=False):
    task = validate_task(task)
    if not isinstance(request_id, str):
        raise ValueError('A UUID request ID is required.')
    uuid.UUID(request_id)
    key = os.getenv('MITHRIL_API_KEY', '').strip()
    if not key:
        raise ValueError('Mithril credentials are unavailable in this runtime.')
    try:
        response = requests.post(ORIGIN + '/api/refactors',
            headers={'x-mithril-token': key, 'origin': ORIGIN, 'content-type': 'application/json'},
            json={'task': task, 'request_id': request_id, 'lookup_only': lookup_only},
            timeout=(5, 190), allow_redirects=False, stream=True)
        with response:
            if response.status_code != 200:
                raise ValueError(f'Code service HTTP {response.status_code}; no automatic retry.')
            chunks, size = [], 0
            for chunk in response.iter_content(4096):
                size += len(chunk)
                if size > 200000:
                    raise ValueError('Code service response exceeds budget; outcome unknown.')
                chunks.append(chunk)
            proposal = json.loads(b''.join(chunks))
    except requests.RequestException:
        raise ValueError('Code service outcome unknown; retrieve the same request ID before retrying.') from None
    candidate(task, proposal)
    return proposal


def verify(task_file, proposal_file, plan_file, receipt_file):
    output = Path(receipt_file)
    if output.exists() or output.is_symlink():
        raise ValueError('Independent verification requires a new receipt path.')
    verifier = os.getenv('FLAME_CODE_VERIFIER', '')
    expected = os.getenv('FLAME_CODE_VERIFIER_SHA256', '')
    contract_expected = os.getenv('FLAME_CODE_CONTRACT_SHA256', '')
    path = Path(verifier)
    contract = path.parent / '../../../packages/workspace/src/code-refactor.ts'
    if (not verifier or not expected or not path.is_file()
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected
            or not contract_expected or not contract.is_file()
            or hashlib.sha256(contract.read_bytes()).hexdigest() != contract_expected):
        raise ValueError('An owner-configured, digest-qualified Code verifier is required.')
    # This trusted verifier runs only Docker on the host; source and check commands stay in containers.
    # The qualified verifier owns per-check deadlines and container cleanup.
    # Do not kill it with an outer deadline that could leave its containers behind.
    result = subprocess.run(['node', str(path), str(task_file), str(proposal_file), str(plan_file), str(receipt_file)],
                            capture_output=True,
                            env={k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR', 'DOCKER_HOST')})
    if not output.is_file():
        raise ValueError('Independent verification failed without a receipt.')
    receipt = json.loads(output.read_text())
    if receipt.get('verified') and result.returncode != 0:
        raise ValueError('Verifier exited unsuccessfully after writing a receipt.')
    if (hashlib.sha256(path.read_bytes()).hexdigest() != expected
            or hashlib.sha256(contract.read_bytes()).hexdigest() != contract_expected):
        raise ValueError('Trusted verifier source changed during verification.')
    return {'verifier_sha256': expected, 'contract_sha256': contract_expected,
            'receipt': receipt, 'exit_code': result.returncode}
