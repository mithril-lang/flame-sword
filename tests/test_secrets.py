from unittest.mock import Mock, patch
import os
import subprocess

from modules.secrets import load_mithril_key


def test_reference_is_resolved_in_memory(monkeypatch):
    monkeypatch.delenv('MITHRIL_API_KEY', raising=False)
    monkeypatch.setenv('MITHRIL_API_KEY_REF', 'op://vault/item/credential')
    with patch('modules.secrets.shutil.which', return_value='/opt/homebrew/bin/op'), patch(
        'modules.secrets.subprocess.run', return_value=Mock(returncode=0, stdout='test-key\n')
    ) as run:
        assert load_mithril_key() is True
    assert os.environ['MITHRIL_API_KEY'] == 'test-key'
    assert run.call_args.args[0] == ['/opt/homebrew/bin/op', 'read', 'op://vault/item/credential']
    assert run.call_args.kwargs['capture_output'] is True


def test_direct_key_prevents_secret_manager_access(monkeypatch):
    monkeypatch.setenv('MITHRIL_API_KEY', 'test-key')
    with patch('modules.secrets.subprocess.run') as run:
        assert load_mithril_key() is True
    run.assert_not_called()


def test_failed_authorization_leaves_key_unset(monkeypatch):
    monkeypatch.delenv('MITHRIL_API_KEY', raising=False)
    monkeypatch.setenv('MITHRIL_API_KEY_REF', 'op://vault/item/credential')
    with patch('modules.secrets.shutil.which', return_value='/opt/homebrew/bin/op'), patch(
        'modules.secrets.subprocess.run', side_effect=subprocess.TimeoutExpired('op', 30)
    ):
        assert load_mithril_key() is False
    assert not os.getenv('MITHRIL_API_KEY')
