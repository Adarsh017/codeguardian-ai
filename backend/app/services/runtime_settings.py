"""Settings editable from the dashboard (persisted to storage/settings.json, applied over env defaults)."""
import json

from ..config import settings

EDITABLE = {
    "LLM_PROVIDER": str, "LLM_API_KEY": str, "LLM_BASE_URL": str, "LLM_MODEL": str, "LLM_MAX_FINDINGS": int,
    "GATE_FAIL_ON": str, "GATE_MIN_SECURITY_SCORE": float, "OSV_ENABLED": bool, "NOTIFY_WEBHOOK_URL": str,
    "GITHUB_TOKEN": str, "MAX_UPLOAD_MB": int,
}
SECRET_KEYS = {"LLM_API_KEY", "GITHUB_TOKEN"}
_PATH = settings.STORAGE_DIR / "settings.json"


def load() -> None:
    if _PATH.exists():
        try:
            apply(json.loads(_PATH.read_text()), persist=False)
        except (json.JSONDecodeError, OSError):
            pass


def apply(values: dict, persist: bool = True) -> None:
    stored = json.loads(_PATH.read_text()) if _PATH.exists() else {}
    for key, value in values.items():
        if key not in EDITABLE or value is None:
            continue
        if key in SECRET_KEYS and isinstance(value, str) and set(value) <= {"*"} and value:
            continue  # masked value sent back unchanged
        cast = EDITABLE[key]
        value = (str(value).lower() in ("1", "true", "yes")) if cast is bool else cast(value)
        if key in ("LLM_PROVIDER", "GATE_FAIL_ON"):
            value = value.lower()
        setattr(settings, key, value)
        stored[key] = value
    if persist:
        _PATH.write_text(json.dumps(stored, indent=2))


def public() -> dict:
    out = {}
    for key in EDITABLE:
        value = getattr(settings, key)
        if key in SECRET_KEYS:
            value = "********" if value else ""
        out[key] = value
    return out
