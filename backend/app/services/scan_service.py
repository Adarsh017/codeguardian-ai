"""Scan orchestration & scheduling: queues scans, runs the agent pipeline in a worker
pool, tracks progress and persists results."""
import logging
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from ..config import settings
from ..database import SessionLocal
from ..models import Finding, Project, Scan
from .ingestion import IngestionError, fetch_github_repo, project_dir, safe_extract_zip
from .notifications import notify_scan
from .orchestrator import Orchestrator

log = logging.getLogger("codeguardian.scans")
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="scan")
_lock = threading.Lock()


def scan_dir(scan_id: int) -> Path:
    return settings.STORAGE_DIR / "scans" / str(scan_id) / "src"


def upload_path(project_id: int) -> Path:
    return project_dir(project_id) / "upload.zip"


def enqueue(scan_id: int, github_token: str | None = None) -> None:
    _executor.submit(run_scan, scan_id, github_token)


def _update(scan_id: int, **fields) -> None:
    with _lock, SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        for k, v in fields.items():
            setattr(scan, k, v)
        db.commit()


def run_scan(scan_id: int, github_token: str | None = None) -> None:
    with SessionLocal() as db:
        scan = db.get(Scan, scan_id)
        project = db.get(Project, scan.project_id)
        project_name, source_type, repo_url, branch, project_id = (
            project.name, project.source_type, project.repo_url, project.branch, project.id)
    _update(scan_id, status="running", stage="Acquiring code", progress=3, started_at=datetime.now(timezone.utc))
    dest = scan_dir(scan_id)
    try:
        # ---- Code acquisition (snapshot per scan, so reports always match the scanned code)
        if source_type == "github":
            meta = fetch_github_repo(repo_url, dest, branch, github_token)
            _update(scan_id, commit_sha=meta.get("commit_sha", ""))
        else:
            safe_extract_zip(upload_path(project_id), dest)

        def progress(stage: str, pct: int) -> None:
            _update(scan_id, stage=stage, progress=max(5, min(99, pct)))

        result = Orchestrator(progress=progress).run(dest)

        with _lock, SessionLocal() as db:
            scan = db.get(Scan, scan_id)
            for f in result["findings"]:
                db.add(Finding(scan_id=scan_id, agent=f.agent, category=f.category, rule_id=f.rule_id,
                               title=f.title[:300], severity=f.severity, confidence=round(f.confidence, 2),
                               file=f.file, line=f.line, snippet=f.snippet, description=f.description,
                               explanation=f.explanation, remediation=f.remediation, fixed_code=f.fixed_code,
                               cwe=f.cwe, owasp=f.owasp, ai_reviewed=int(f.ai_reviewed),
                               sources=list(f.sources)))
            scores = result["scores"]
            scan.security_score = scores["security_score"]
            scan.quality_score = scores["quality_score"]
            scan.overall_score = scores["overall_score"]
            scan.gate_passed = int(result["gate"]["passed"])
            scan.summary = {k: result[k] for k in ("engine", "codebase", "scores", "gate", "summary", "severity_counts",
                                                   "category_counts", "agents", "ai_review", "ai_remediation",
                                                   "raw_finding_count", "timings")}
            scan.status, scan.stage, scan.progress = "completed", "Completed", 100
            scan.finished_at = datetime.now(timezone.utc)
            db.commit()
        notify_scan(project_name, scan_id, "completed", result["scores"], result["severity_counts"], result["gate"])
    except IngestionError as exc:
        _fail(scan_id, project_name, str(exc))
    except Exception as exc:  # pragma: no cover - unexpected
        log.exception("Scan %s failed", scan_id)
        _fail(scan_id, project_name, f"Internal error: {exc}")


def _fail(scan_id: int, project_name: str, message: str) -> None:
    _update(scan_id, status="failed", stage="Failed", error=message[:1000], finished_at=datetime.now(timezone.utc))
    notify_scan(project_name, scan_id, "failed", None, None, None, message)


def delete_scan_files(scan_id: int) -> None:
    shutil.rmtree(scan_dir(scan_id).parent, ignore_errors=True)
