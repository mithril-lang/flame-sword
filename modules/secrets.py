"""Resolve optional 1Password references into process memory at startup."""
import os
import shutil
import subprocess


def load_mithril_key():
    if os.getenv("MITHRIL_API_KEY", "").strip():
        return True
    reference = os.getenv("MITHRIL_API_KEY_REF", "").strip()
    if not reference:
        return False
    command = shutil.which("op")
    if not reference.startswith("op://") or not command:
        return False
    try:
        result = subprocess.run([command, "read", reference],
                                capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return False
    if result.returncode != 0 or not result.stdout.strip():
        return False
    os.environ["MITHRIL_API_KEY"] = result.stdout.strip()
    return True
