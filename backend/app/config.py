"""Central configuration, read from environment variables (see .env.example)."""
import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


def _load_dotenv() -> None:
    """Tiny .env loader so the project runs without python-dotenv."""
    for candidate in (BASE_DIR / ".env", BASE_DIR.parent / ".env"):
        if candidate.exists():
            for line in candidate.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_dotenv()


class Settings:
    APP_NAME = "CodeGuardian AI"
    VERSION = "1.0.0"

    # Security
    SECRET_KEY = os.getenv("SECRET_KEY", "")  # generated & persisted on first run when empty
    TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "720"))

    # Storage
    DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'codeguardian.db'}")
    STORAGE_DIR = Path(os.getenv("STORAGE_DIR", str(BASE_DIR / "storage")))
    REDIS_URL = os.getenv("REDIS_URL", "")  # optional; in-memory cache when empty
    MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))      # largest ZIP accepted
    MAX_EXTRACT_MB = int(os.getenv("MAX_EXTRACT_MB", "4000"))   # zip-bomb guard: total size once unpacked

    # LLM (AI Reviewer / Remediation agents)
    # LLM_PROVIDER: "none" | "openai" (any OpenAI-compatible API: OpenAI, Groq, Gemini, Ollama, LM Studio) | "anthropic"
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "none").lower()
    LLM_API_KEY = os.getenv("LLM_API_KEY", "")
    LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1")
    LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
    LLM_MAX_FINDINGS = int(os.getenv("LLM_MAX_FINDINGS", "25"))  # findings sent to the LLM per scan
    LLM_TIMEOUT = float(os.getenv("LLM_TIMEOUT", "60"))

    # GitHub
    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

    # Dependency agent: query OSV.dev for CVEs (set to false when offline)
    OSV_ENABLED = os.getenv("OSV_ENABLED", "true").lower() == "true"

    # Notifications: optional webhook (Slack/Discord/Teams-compatible JSON {"text": ...})
    NOTIFY_WEBHOOK_URL = os.getenv("NOTIFY_WEBHOOK_URL", "")

    # Quality gate (CI/CD): fail when any finding at/above this severity exists
    # ("critical" | "high" | "medium" | "low" | "none") or the security score is below the minimum
    GATE_FAIL_ON = os.getenv("GATE_FAIL_ON", "high").lower()
    GATE_MIN_SECURITY_SCORE = float(os.getenv("GATE_MIN_SECURITY_SCORE", "0"))

    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://localhost:3000").split(",")


settings = Settings()
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
if not settings.SECRET_KEY:
    _key_file = settings.STORAGE_DIR / ".secret_key"
    if not _key_file.exists():
        _key_file.write_text(secrets.token_urlsafe(48))
        _key_file.chmod(0o600)
    settings.SECRET_KEY = _key_file.read_text().strip()
