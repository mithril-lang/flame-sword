from copy import deepcopy
import uuid
from unittest.mock import patch
import pytest

from modules.coding import candidate, task_identity, sha, propose


def task():
    return {'format': 'mithril.code-refactor-task/v1', 'goal': 'Add a header',
            'files': [{'path': 'application.py', 'encoding': 'utf-8', 'content': 'original'}],
            'editable_paths': ['application.py']}


def proposal(value):
    return {'format': 'mithril.code-refactor-proposal/v1', 'verified': False,
            'input_sha256': task_identity(value),
            'changes': [{'path': 'application.py', 'before_sha256': sha('original'), 'content': 'candidate'}]}


def test_candidate_is_inert_and_rejects_stale_source_and_scope():
    value = task()
    result = proposal(value)
    assert candidate(value, result) == {'application.py': 'candidate'}
    assert value['files'][0]['content'] == 'original'
    for bad in ['different-path.py', '.env', '../outside.py']:
        modified = deepcopy(result)
        modified['changes'][0]['path'] = bad
        with pytest.raises(ValueError):
            candidate(value, modified)
    value['files'][0]['content'] = 'concurrent edit'
    with pytest.raises(ValueError, match='stale'):
        candidate(value, result)


def test_unknown_service_outcome_does_not_retry(monkeypatch):
    import requests
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-secret')
    with patch('modules.coding.requests.post', side_effect=requests.Timeout) as call:
        with pytest.raises(ValueError, match='outcome unknown'):
            propose(task(), str(uuid.uuid4()))
    assert call.call_count == 1


@pytest.mark.parametrize('filename', ['.env', '.netrc', 'nested/secrets.json', 'private.pem'])
def test_secret_filename_is_refused_before_network(monkeypatch, filename):
    value = task()
    value['files'][0]['path'] = filename
    with patch('modules.coding.requests.post') as call:
        with pytest.raises(ValueError):
            propose(value, str(uuid.uuid4()))
    call.assert_not_called()
