"""Scan status, findings, code context and report export."""
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..config import settings
from ..database import get_db
from ..models import Finding, Project, Scan, User
from ..serializers import finding_out, scan_out
from ..services import report as report_service
from ..services.scan_service import scan_dir

router = APIRouter(prefix="/api/scans", tags=["scans"])


def owned_scan(scan_id: int, user: User, db: Session) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None or db.get(Project, scan.project_id).owner_id != user.id:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/{scan_id}")
def get_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = owned_scan(scan_id, user, db)
    project = db.get(Project, scan.project_id)
    return {**scan_out(scan, full=True), "project": {"id": project.id, "name": project.name,
                                                     "source_type": project.source_type, "repo_url": project.repo_url}}


@router.get("/{scan_id}/findings")
def list_findings(scan_id: int, severity: str | None = None, category: str | None = None, q: str | None = None,
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    owned_scan(scan_id, user, db)
    stmt = select(Finding).where(Finding.scan_id == scan_id)
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity.split(",")))
    if category:
        stmt = stmt.where(Finding.category.in_(category.split(",")))
    rows = [finding_out(f) for f in db.scalars(stmt).all()]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["title"].lower() or ql in r["file"].lower() or ql in (r["cwe"] or "").lower()]
    return sorted(rows, key=report_service.sort_key)


@router.get("/{scan_id}/findings/{finding_id}/context")
def finding_context(scan_id: int, finding_id: int, radius: int = Query(8, ge=1, le=40),
                    user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    owned_scan(scan_id, user, db)
    finding = db.get(Finding, finding_id)
    if finding is None or finding.scan_id != scan_id:
        raise HTTPException(404, "Finding not found")
    root = scan_dir(scan_id).resolve()
    path = (root / finding.file).resolve()
    if not str(path).startswith(str(root)) or not path.is_file():
        return {"file": finding.file, "start": 0, "lines": []}
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    start = max(1, finding.line - radius)
    end = min(len(lines), finding.line + radius)
    return {"file": finding.file, "start": start, "highlight": finding.line, "lines": lines[start - 1:end]}


@router.get("/{scan_id}/report")
def export_report(scan_id: int, format: str = Query("pdf", pattern="^(pdf|json|csv|sarif)$"),
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = owned_scan(scan_id, user, db)
    if scan.status != "completed":
        raise HTTPException(409, "Scan has not completed yet")
    project = db.get(Project, scan.project_id)
    findings = sorted([finding_out(f) for f in scan.findings], key=report_service.sort_key)
    summary = scan.summary or {}
    report = report_service.build_report({
        "version": settings.VERSION, "project": project.name, "scan_id": scan.id,
        "source": project.repo_url or "upload", "commit_sha": scan.commit_sha,
        "scores": summary.get("scores", {}), "gate": summary.get("gate", {}), "summary": summary.get("summary", ""),
        "severity_counts": summary.get("severity_counts", {}), "category_counts": summary.get("category_counts", {}),
        "codebase": summary.get("codebase", {}), "agents": summary.get("agents", {}), "timings": summary.get("timings", {}),
    }, findings)
    exporter, media = report_service.EXPORTERS[format]
    filename = f"codeguardian-{project.name.replace('/', '-').replace(' ', '_')}-scan{scan.id}.{format if format != 'sarif' else 'sarif.json'}"
    return Response(exporter(report), media_type=media,
                    headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    from ..services.scan_service import delete_scan_files
    scan = owned_scan(scan_id, user, db)
    if scan.status in ("queued", "running"):
        raise HTTPException(409, "Scan is still running")
    delete_scan_files(scan.id)
    db.delete(scan)
    db.commit()
    return {"deleted": scan_id}

