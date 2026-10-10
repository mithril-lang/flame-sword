"""Bounded evidence projections. Scanner heuristics are never verified findings."""
import hashlib
import json

SECTIONS = {'subdomains': 'subdomains', 'ports': 'port_scan', 'dns': 'dns_records',
            'ssl': 'ssl_scan', 'tech': 'tech_detection', 'email': 'email_enumeration',
            'real_ip': 'real_ip', 'security': 'security_analysis', 'headers': 'http_headers'}
PRIVATE = {'secrets', 'secret', 'password', 'authorization', 'cookie', 'set-cookie',
           'api_key', 'token', 'access_token', 'email_enumeration', 'ai_analysis'}


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, default=str).encode()


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def projection(value, depth=0):
    if depth > 5:
        return '[depth limit]'
    if isinstance(value, dict):
        return {str(k)[:120]: projection(v, depth + 1) for k, v in list(value.items())[:30]
                if str(k).lower() not in PRIVATE}
    if isinstance(value, list):
        return [projection(v, depth + 1) for v in value[:20]]
    if isinstance(value, str):
        return value[:300]
    return value if value is None or isinstance(value, (bool, int, float)) else str(value)[:300]


def normalize(report):
    if not isinstance(report, dict):
        raise ValueError('Report must be an object.')
    observations, gaps = [], []
    statuses = report.get('module_status', {})
    if not isinstance(statuses, dict):
        raise ValueError('module_status must be an object.')
    for module, section in SECTIONS.items():
        state = statuses.get(module, 'unknown')
        data = report.get(section)
        if state != 'completed' or not data:
            gaps.append({'module': module, 'reason': state if state != 'completed' else 'empty_observations'})
        if data and module != 'email':
            value = projection(data)
            if len(encoded(value)) > 2048:
                value = {'note': 'Evidence too large for AI projection; inspect the private raw report.'}
                gaps.append({'module': module, 'reason': 'projection_limit'})
            observations.append({'id': digest({'section': section, 'data': data}),
                                 'module': module, 'collection_status': state,
                                 'classification': 'observation', 'data': value})
    if isinstance(report.get('subdomains'), list) and len(report['subdomains']) > 20:
        gaps.append({'module': 'subdomains', 'reason': 'projection_limit'})
    source = {k: v for k, v in report.items() if k not in ('ai_analysis', 'evidence')}
    return {'format': 'flame.evidence/v1', 'assessment_id': report.get('scan_id'),
            'domain': report.get('domain'), 'observed_at': report.get('timestamp'),
            'source_sha256': digest(source), 'execution': report.get('execution', 'native-python'),
            'provenance': report.get('provenance', 'local-scanner'),
            'observations': observations, 'coverage_gaps': gaps,
            'verified_vulnerabilities': None,
            'limitations': ['Observations and heuristic risks do not establish exploitability.',
                            'Absent or unmeasured modules are unknown, not zero vulnerabilities.',
                            'AI projection is bounded and excludes known credential fields and email enumeration.']}


def assess(evidence):
    findings = []
    for item in evidence['observations']:
        if item['module'] != 'headers' or item['collection_status'] != 'completed':
            continue
        data = item['data']
        if not isinstance(data, dict) or not isinstance(data.get('headers'), dict) or not isinstance(data.get('status'), int):
            continue
        headers = {k.lower(): v for k, v in data['headers'].items()}
        if 'x-content-type-options' not in headers:
            findings.append({'rule': 'HEADER_NOSNIFF', 'policy_version': '1',
                             'classification': 'policy_violation', 'evidence_id': item['id'],
                             'message': 'The measured response lacks X-Content-Type-Options.',
                             'verified_exploit': False})
    return {'format': 'flame.assessment/v1', 'source_sha256': evidence['source_sha256'],
            'findings': findings, 'coverage_gaps': evidence['coverage_gaps'],
            'scope': 'Measured response header presence only; not whole-application security.'}
