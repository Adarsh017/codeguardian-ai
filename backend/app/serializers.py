from datetime import timezone

from .models import Finding, Project, Scan


def iso(dt):
    """ISO-8601 with timezone. SQLite returns naive datetimes; they are stored in UTC."""
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def scan_out(s: Scan, full: bool = False) -> dict:
    summary = s.summary or {}
    out = {
        "id": s.id, "project_id": s.project_id, "status": s.status, "stage": s.stage, "progress": s.progress,
        "error": s.error, "trigger": s.trigger, "commit_sha": s.commit_sha,
        "security_score": s.security_score, "quality_score": s.quality_score, "overall_score": s.overall_score,
        "gate_passed": bool(s.gate_passed), "severity_counts": summary.get("severity_counts", {}),
        "created_at": iso(s.created_at), "started_at": iso(s.started_at), "finished_at": iso(s.finished_at),
    }
    if full:
        out["summary"] = summary
    return out


def project_out(p: Project) -> dict:
    latest = p.scans[0] if p.scans else None
    return {"id": p.id, "name": p.name, "source_type": p.source_type, "repo_url": p.repo_url, "branch": p.branch,
            "created_at": iso(p.created_at), "scan_count": len(p.scans),
            "latest_scan": scan_out(latest) if latest else None}


def finding_out(f: Finding) -> dict:
    return {"id": f.id, "agent": f.agent, "category": f.category, "rule_id": f.rule_id, "title": f.title,
            "severity": f.severity, "confidence": f.confidence, "file": f.file, "line": f.line, "snippet": f.snippet,
            "description": f.description, "explanation": f.explanation, "remediation": f.remediation,
            "fixed_code": f.fixed_code, "cwe": f.cwe, "owasp": f.owasp, "ai_reviewed": bool(f.ai_reviewed),
            "sources": f.sources or [f.agent]}
