from modules.evidence import normalize, assess
from modules.AI_analyst import AIAnalyst
from modules.storage import ScanStore
import pytest


def test_native_sections_reach_ai_and_missing_coverage_stays_unknown():
    report = {'domain': 'example.invalid', 'scan_id': 'test', 'module_status': {'ports': 'completed'},
              'port_scan': [{'target': 'example.invalid', 'ports': [{'port': 443, 'state': 'open'}]}],
              'dns_records': {'A': ['192.0.2.1']}, 'ssl_scan': {'version': 'TLSv1.3'},
              'email_enumeration': {'email': 'private@example.invalid'},
              'security_analysis': {'email_analysis': {'email': 'nested@example.invalid'}},
              'tech_detection': {'secrets': ['private-token']}}
    evidence = normalize(report)
    assert evidence['verified_vulnerabilities'] is None
    assert any(gap['module'] == 'ssl' and gap['reason'] == 'unknown' for gap in evidence['coverage_gaps'])
    prompt = AIAnalyst()._prepare_prompt(report, 'owner')
    assert '443' in prompt and '192.0.2.1' in prompt and 'TLSv1.3' in prompt
    assert 'private-token' not in prompt and 'private@example.invalid' not in prompt
    assert 'nested@example.invalid' not in prompt


def test_measured_policy_and_unmeasured_headers_are_distinct():
    report = {'http_headers': {'status': 200, 'headers': {}}, 'module_status': {'headers': 'completed'}}
    finding = assess(normalize(report))['findings'][0]
    assert finding['classification'] == 'policy_violation' and finding['verified_exploit'] is False
    report['http_headers']['headers']['X-Content-Type-Options'] = 'nosniff'
    assert assess(normalize(report))['findings'] == []
    report['http_headers'] = {'note': 'not measured'}
    assert assess(normalize(report))['findings'] == []


def test_report_recovery_fences_interrupted_jobs_and_profiles(tmp_path):
    store = ScanStore(tmp_path, 'owner-one')
    store.save('done', {'status': 'completed'}, {'domain': 'example.invalid'})
    store.save('interrupted', {'status': 'running'}, {'domain': 'example.invalid'})
    recovered = ScanStore(tmp_path, 'owner-one').restore()
    assert recovered['done'][0]['status'] == 'completed'
    assert recovered['interrupted'][0]['status'] == 'outcome_unknown'
    assert ScanStore(tmp_path, 'owner-two').restore() == {}
    assert store.read('interrupted')[0]['status'] == 'outcome_unknown'


def test_malformed_import_cannot_claim_collected_evidence():
    with pytest.raises(ValueError, match='module_status'):
        normalize({'module_status': ['completed']})
    report = {'http_headers': {'status': 200, 'headers': {}}}
    assert assess(normalize(report))['findings'] == []


def test_truncated_headers_cannot_establish_absence():
    headers = {f'X-Extra-{i}': 'value' for i in range(30)}
    headers['X-Content-Type-Options'] = 'nosniff'
    evidence = normalize({'http_headers': {'status': 200, 'headers': headers},
                          'module_status': {'headers': 'completed'}})
    assert assess(evidence)['findings'] == []
    assert {'module': 'headers', 'reason': 'projection_limit'} in evidence['coverage_gaps']
