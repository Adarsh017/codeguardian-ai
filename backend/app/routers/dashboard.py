"""Dashboard aggregates, settings and system status."""
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..agents.base import tool_available
from ..auth import get_current_user
from ..config import settings
from ..database import get_db
from ..models import Finding, Project, Scan, User
from ..serializers import iso, scan_out
from ..services import llm, runtime_settings
from ..services.cache import cache
from ..services.orchestrator import ANALYSIS_AGENTS, HAS_LANGGRAPH

router = APIRouter(prefix="/api", tags=["dashboard"])


@router.get("/dashboard")
def dashboard(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).where(Project.owner_id == user.id)).all()
    project_ids = [p.id for p in projects]
    names = {p.id: p.name for p in projects}
    scans = db.scalars(select(Scan).where(Scan.project_id.in_(project_ids)).order_by(Scan.id.desc())).all() if project_ids else []
    completed = [s for s in scans if s.status == "completed"]
    latest_per_project = {}
    for s in completed:
        latest_per_project.setdefault(s.project_id, s)
    latest = list(latest_per_project.values())
    sev_totals = {k: 0 for k in ("Critical", "High", "Medium", "Low", "Info")}
    cat_totals: dict[str, int] = {}
    for s in latest:
        for k, v in (s.summary or {}).get("severity_counts", {}).items():
            sev_totals[k] = sev_totals.get(k, 0) + v
        for k, v in (s.summary or {}).get("category_counts", {}).items():
            cat_totals[k] = cat_totals.get(k, 0) + v
    top_rules = {}
    if latest:
        for f in db.scalars(select(Finding).where(Finding.scan_id.in_([s.id for s in latest]))).all():
            key = f.title if f.rule_id.startswith(("SEC022", "SEC023", "DEP001")) else f.rule_id
            entry = top_rules.setdefault(key, {"rule_id": f.rule_id, "title": f.title.split(" (")[0].split(":")[0]
                                               if not f.rule_id.startswith("DEP") else "Vulnerable dependency",
                                               "severity": f.severity, "count": 0})
            entry["count"] += 1
    avg = lambda vals: round(sum(vals) / len(vals), 1) if vals else None  # noqa: E731
    return {
        "projects": len(projects),
        "scans": len(scans),
        "running": sum(1 for s in scans if s.status in ("queued", "running")),
        "avg_security_score": avg([s.security_score for s in latest]),
        "avg_quality_score": avg([s.quality_score for s in latest]),
        "gate_pass_rate": avg([100.0 * s.gate_passed for s in latest]),
        "severity_totals": sev_totals,
        "category_totals": cat_totals,
        "top_issues": sorted(top_rules.values(), key=lambda r: -r["count"])[:8],
        "trend": [{"scan_id": s.id, "project": names[s.project_id], "date": iso(s.finished_at),
                   "security": s.security_score, "quality": s.quality_score} for s in reversed(completed[:20])],
        "recent_scans": [{**scan_out(s), "project_name": names[s.project_id]} for s in scans[:10]],
    }


class SettingsIn(BaseModel):
    LLM_PROVIDER: str | None = None
    LLM_API_KEY: str | None = None
    LLM_BASE_URL: str | None = None
    LLM_MODEL: str | None = None
    LLM_MAX_FINDINGS: int | None = None
    GATE_FAIL_ON: str | None = None
    GATE_MIN_SECURITY_SCORE: float | None = None
    OSV_ENABLED: bool | None = None
    NOTIFY_WEBHOOK_URL: str | None = None
    GITHUB_TOKEN: str | None = None
    MAX_UPLOAD_MB: int | None = Field(default=None, ge=1, le=5000)


def _system() -> dict:
    return {
        "version": settings.VERSION,
        "max_upload_mb": settings.MAX_UPLOAD_MB,
        "orchestration_engine": "LangGraph" if HAS_LANGGRAPH else "ThreadPool",
        "agents": [a.name for a in ANALYSIS_AGENTS] + ["AI Reviewer Agent", "AI Remediation Agent"],
        "llm": llm.describe(),
        "tools": {"bandit": tool_available("bandit"), "semgrep": tool_available("semgrep"), "git": tool_available("git")},
        "cache": cache.kind,
        "database": settings.DATABASE_URL.split(":")[0],
    }


@router.get("/settings")
def get_settings(user: User = Depends(get_current_user)):
    return {"settings": runtime_settings.public(), "system": _system()}


@router.put("/settings")
def update_settings(body: SettingsIn, user: User = Depends(get_current_user)):
    runtime_settings.apply(body.model_dump(exclude_none=True))
    return {"settings": runtime_settings.public(), "system": _system()}


@router.post("/settings/test-llm")
def test_llm(user: User = Depends(get_current_user)):
    if not llm.enabled():
        return {"ok": False, "message": "LLM is not configured (set provider and API key)"}
    try:
        data = llm.chat_json("Reply with JSON only.", 'Return {"status": "ok"} as JSON. Nonce: ' + str(id(user)))
        return {"ok": True, "message": f"Connected to {settings.LLM_MODEL}: {data}"}
    except llm.LLMError as exc:
        return {"ok": False, "message": str(exc)[:300]}


@router.get("/health")
def health():
    return {"status": "ok", **_system()}
