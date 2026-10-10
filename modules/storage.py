"""Profile-bound local SQLite snapshots, with no automatic execution on recovery."""
import json
import os
import sqlite3
from pathlib import Path


class ScanStore:
    def __init__(self, root=None, profile=None):
        self.profile = profile or os.getenv('FLAME_PROFILE') or 'local'
        directory = Path(root or os.getenv('FLAME_STATE_DIR') or Path(__file__).resolve().parents[1] / '.local/state')
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = directory / 'scans.sqlite'
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS scans (profile TEXT NOT NULL, id TEXT NOT NULL, '
                       'status TEXT NOT NULL, report TEXT NOT NULL, PRIMARY KEY(profile,id))')
        self.path.chmod(0o600)

    def connect(self):
        return sqlite3.connect(self.path, timeout=10)

    def save(self, scan_id, status, report):
        values = [json.dumps(v, default=str, ensure_ascii=False) for v in (status, report)]
        if sum(len(v.encode()) for v in values) > 4 * 1024 * 1024:
            raise ValueError('Stored report exceeds 4 MiB.')
        with self.connect() as db:
            db.execute('INSERT INTO scans VALUES (?,?,?,?) ON CONFLICT(profile,id) '
                       'DO UPDATE SET status=excluded.status,report=excluded.report',
                       (self.profile, scan_id, *values))

    def read(self, scan_id):
        with self.connect() as db:
            row = db.execute('SELECT status,report FROM scans WHERE profile=? AND id=?',
                             (self.profile, scan_id)).fetchone()
        if row is None:
            raise ValueError('Assessment not found in this profile.')
        return tuple(json.loads(v) for v in row)

    def restore(self):
        with self.connect() as db:
            rows = db.execute('SELECT id,status,report FROM scans WHERE profile=?', (self.profile,)).fetchall()
        result = {}
        for scan_id, status_text, report_text in rows:
            status, report = json.loads(status_text), json.loads(report_text)
            if status.get('status') == 'running':
                status.update(status='outcome_unknown', current_task='Interrupted; reconcile before a new scan.')
                self.save(scan_id, status, report)
            result[scan_id] = (status, report)
        return result
