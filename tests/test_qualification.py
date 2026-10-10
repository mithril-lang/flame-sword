import importlib.util
from pathlib import Path
import sys

import pytest

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root / 'scripts'))
spec = importlib.util.spec_from_file_location('qualification', root / 'scripts/qualify-header-repair.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


def test_measurement_survives_interleaved_test_output():
    record = 'FLAME_RESPONSE_JSON={"status":200,"headers":{"x-content-type-options":"nosniff"}}'
    assert qualification.measured_response('test_header ... ' + record + '\nok\nOK')['status'] == 200
    with pytest.raises(ValueError, match='exactly one'):
        qualification.measured_response(record + '\n' + record)
