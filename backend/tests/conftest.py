"""Test configuration: isolated temp database/storage, offline, no LLM. Runs before app imports."""
import os
import sys
import tempfile
from pathlib import Path

_tmp = tempfile.mkdtemp(prefix="codeguardian-test-")
os.environ.update({
    "DATABASE_URL": f"sqlite:///{_tmp}/test.db",
    "STORAGE_DIR": f"{_tmp}/storage",
    "OSV_ENABLED": "false",
    "LLM_PROVIDER": "none",
    "NOTIFY_WEBHOOK_URL": "",
})
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
