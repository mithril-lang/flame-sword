"""Keep test scan snapshots out of the running user's local state."""
import os
import tempfile

os.environ['FLAME_STATE_DIR'] = tempfile.mkdtemp(prefix='flame-tests-')
