import json
from unittest.mock import Mock, patch

import pytest

from modules.AI_analyst import AIAnalyst
from modules.mithril_api import MithrilAPI, MithrilAPIError


def response(status=200, data=None):
    return Mock(status_code=status, json=Mock(return_value=data))


def test_analysis_uses_mithril_for_both_perspectives(monkeypatch):
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-secret')
    completion = response(data={'choices': [{'message': {'content': json.dumps({'summary': 'Synthetic analysis'})}}]})
    with patch('modules.mithril_api.requests.request', return_value=completion) as request:
        result = AIAnalyst().analyze_results({'domain': 'example.invalid'})
    assert request.call_count == 2
    args, kwargs = request.call_args
    assert args == ('POST', 'https://api.mithril.fund/v1/chat/completions')
    assert kwargs['headers']['Authorization'] == 'Bearer test-secret'
    assert kwargs['allow_redirects'] is False
    assert kwargs['json']['model'] == 'qwen/qwen3.8-27b'
    assert result['owner_analysis']['ai_model'] == 'Mithril / qwen/qwen3.8-27b'
    assert result['hunter_analysis']['summary'] == 'Synthetic analysis'
    assert result['provider_errors'] == []
    assert 'test-secret' not in json.dumps(result)


@pytest.mark.parametrize('status', [401, 403, 429, 500, 302])
def test_provider_failure_is_visible_and_does_not_retry_or_expose_response(monkeypatch, status):
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-secret')
    failure = response(status, {'error': 'test-secret'})
    with patch('modules.mithril_api.requests.request', return_value=failure) as request:
        result = AIAnalyst().analyze_results({'domain': 'example.invalid'})
    assert request.call_count == 2  # one call per perspective; no retries
    assert len(result['provider_errors']) == 2
    assert result['owner_analysis']['ai_model'] == 'Rule-based Analysis'
    assert f'HTTP {status}' in result['provider_errors'][0]
    assert 'test-secret' not in json.dumps(result)


def test_missing_key_never_sends_findings(monkeypatch):
    monkeypatch.delenv('MITHRIL_API_KEY', raising=False)
    with patch('modules.mithril_api.requests.request') as request:
        result = AIAnalyst().analyze_results({'domain': 'example.invalid'})
    request.assert_not_called()
    assert result['provider_errors']


def test_invalid_completion_is_not_claimed_as_ai_success(monkeypatch):
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-secret')
    with patch('modules.mithril_api.requests.request', return_value=response(data={'choices': []})):
        with pytest.raises(MithrilAPIError, match='invalid completion'):
            MithrilAPI().complete('Synthetic test')


def test_local_pages_and_connection_state(monkeypatch):
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-secret')
    from app import app
    client = app.test_client()
    assert b'Flame Sword' in client.get('/').data
    assert client.get('/health').status_code == 200
    state = client.get('/api/mithril/status')
    assert state.json['configured'] is True
    assert b'test-secret' not in state.data
    with patch('modules.mithril_api.requests.request', return_value=response(data={'data': [{'id': 'qwen/qwen3.8-27b'}]})):
        checked = client.post('/api/mithril/check')
    assert checked.json['model_available'] is True
    assert checked.json['inference_verified'] is False


def test_scan_respects_ai_disabled(monkeypatch):
    from app import app, run_scan, scan_results, scan_status
    from datetime import datetime
    scan_id = 'disabled-test'
    scan_status[scan_id] = {'start_time': datetime.now()}
    scan_results[scan_id] = {'subdomains': [], 'ai_analysis': {}}
    options = dict.fromkeys(['subdomains', 'email', 'ports', 'dns', 'real_ip', 'ssl', 'tech', 'security', 'ai'], False)
    with patch('app.AIAnalyst') as analyst, patch('app.FastSecurityAnalyst') as security:
        run_scan(scan_id, 'example.invalid', options)
    analyst.assert_not_called()
    security.assert_not_called()
    assert scan_status[scan_id]['status'] == 'completed'
