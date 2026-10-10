#!/usr/bin/env python3
"""Opt-in live Code-service qualification over one controlled Flask fixture."""
from pathlib import Path
import argparse
import json
import os
import socket
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import requests
from modules.coding import propose, candidate, sha, verify, task_identity
from modules.evidence import normalize, assess
from modules.storage import ScanStore
from flame import configure


def write(path, data):
    path.write_text(json.dumps(data, indent=2) + '\n')
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--control', action='store_true', help='Use a deterministic patch; no secret resolution or inference.')
    args = parser.parse_args()
    if args.control:
        from dotenv import load_dotenv
        load_dotenv(os.getenv('FLAME_CONFIG_FILE', ROOT / '.env'), override=False)
    else:
        configure()
    image = os.getenv('FLAME_VERIFY_IMAGE', '')
    if not image.startswith('sha256:') or len(image) != 71:
        raise ValueError('Build and explicitly configure a digest-pinned verification image first.')
    run_id = str(uuid.uuid4())
    directory = ROOT / '.local/qualification' / run_id
    directory.mkdir(parents=True, mode=0o700)
    fixture = ROOT / 'examples/header-repair'
    source = (fixture / 'application.py').read_text()
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen([sys.executable, str(fixture / 'application.py')],
                               env={'PATH': os.getenv('PATH', ''), 'FIXTURE_PORT': str(port)},
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for attempt in range(40):
            try:
                response = requests.get(f'http://127.0.0.1:{port}/', timeout=1, allow_redirects=False)
                break
            except requests.RequestException:
                time.sleep(0.1)
        else:
            raise ValueError('Controlled fixture did not start.')
        report = {'scan_id': run_id, 'domain': '127.0.0.1', 'timestamp': time.time(),
                  'execution': 'controlled-loopback-fixture', 'provenance': 'local-measured-response',
                  'http_headers': {'status': response.status_code, 'headers': {
                      k.lower(): v for k, v in response.headers.items()
                      if k.lower() in ('content-type', 'x-content-type-options')}},
                  'module_status': {'headers': 'completed'}}
    finally:
        process.terminate()
        process.wait(timeout=5)
    evidence = normalize(report)
    assessment = assess(evidence)
    if len(assessment['findings']) != 1:
        raise ValueError('Baseline did not reproduce the controlled missing-header condition.')
    ScanStore().save(run_id, {'status': 'completed'}, report)
    write(directory / 'evidence.json', evidence)
    write(directory / 'baseline-assessment.json', assessment)
    task = {'format': 'mithril.code-refactor-task/v1',
            'goal': 'Add X-Content-Type-Options: nosniff to every Flask response, including 404. '
                    'Preserve existing route bodies/statuses and local startup. Change application.py only. '
                    'Measured response evidence: ' + json.dumps(evidence),
            'files': [{'path': name, 'encoding': 'utf-8', 'content': (fixture / name).read_text()}
                      for name in ('application.py', 'check_contract.py')],
            'editable_paths': ['application.py']}
    write(directory / 'task.json', task)
    request_id = str(uuid.uuid4())
    write(directory / 'request.json', {'request_id': request_id, 'status': 'started'})
    print(json.dumps({'stage': 'code-proposal', 'request_id': request_id, 'directory': str(directory)}), flush=True)
    # Exactly one hosted request. On unknown failure the saved request ID enables lookup-only reconciliation.
    if args.control:
        marker = "\n\n@app.route('/')"
        repair = "\n\n@app.after_request\ndef response_headers(response):\n    response.headers['X-Content-Type-Options'] = 'nosniff'\n    return response\n"
        if source.count(marker) != 1:
            raise ValueError('Trusted control fixture changed; review the deterministic patch.')
        proposal = {'format': 'mithril.code-refactor-proposal/v1', 'verified': False,
                    'input_sha256': task_identity(task), 'receipt': {'method': 'deterministic-control'},
                    'changes': [{'path': 'application.py', 'before_sha256': sha(source),
                                 'content': source.replace(marker, repair + marker)}]}
    else:
        proposal = propose(task, request_id)
    write(directory / 'proposal.json', proposal)
    write(directory / 'request.json', {'request_id': request_id, 'status': 'proposal_received'})
    files = candidate(task, proposal)
    plan = {'image': image, 'timeout_seconds': 20, 'checks': [
        {'id': 'existing-behavior', 'argv': ['python', 'check_contract.py']},
        {'id': 'header-retest', 'variant': 'candidate',
         'argv': ['python', 'check_contract.py', '--require-nosniff']}]}
    write(directory / 'plan.json', plan)
    verification = verify(directory / 'task.json', directory / 'proposal.json',
                          directory / 'plan.json', directory / 'verification.json')
    if not verification['receipt'].get('verified'):
        raise ValueError('Candidate verification failed; inspect the retained receipt. No automatic repair.')
    checks = verification['receipt']['checks']
    retest_output = next(c['output'] for c in checks if c['id'] == 'header-retest')
    measured = next(json.loads(line) for line in retest_output.splitlines() if line.startswith('{'))
    retest = dict(report, http_headers=measured)
    retest_assessment = assess(normalize(retest))
    assert retest_assessment['findings'] == []
    assert sha((fixture / 'application.py').read_text()) == sha(source)
    candidate_dir = directory / 'candidate'
    candidate_dir.mkdir(mode=0o700)
    for name, text in files.items():
        (candidate_dir / name).write_text(text)
    receipt = {'format': 'flame.workflow-receipt/v1', 'run_id': run_id, 'request_id': request_id,
               'provider': 'deterministic-control' if args.control else 'Mithril Code refactor service',
               'hosted_inference': not args.control, 'baseline_findings': 1, 'candidate_findings': 0,
               'verification': verification, 'retest': retest_assessment, 'original_source_unchanged': True,
               'scope': 'Controlled Flask fixture and declared response contracts only.', 'billed_cost': None}
    write(directory / 'receipt.json', receipt)
    print(json.dumps({'verified': True, 'receipt': str(directory / 'receipt.json'),
                      'baseline_findings': 1, 'candidate_findings': 0}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except (ValueError, AssertionError) as error:
        print(json.dumps({'error': str(error), 'automatic_retry': False}), file=sys.stderr)
        raise SystemExit(1)
