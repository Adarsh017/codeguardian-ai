"""Project & repository management + scan triggering."""
import shutil

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..auth import get_current_user
from ..config import settings
from ..database import get_db
from ..models import Project, Scan, User
from ..serializers import project_out, scan_out
from ..services import scan_service
from ..services.ingestion import IngestionError, parse_github_url, project_dir

router = APIRouter(prefix="/api/projects", tags=["projects"])


class GithubIn(BaseModel):
    repo_url: str = Field(min_length=10, max_length=500)
    branch: str = Field(default="", max_length=120)
    name: str = Field(default="", max_length=200)
    token: str | None = Field(default=None, description="Optional token for private repos (not stored)")


class ScanIn(BaseModel):
    token: str | None = None


def owned_project(project_id: int, user: User, db: Session) -> Project:
    project = db.get(Project, project_id)
    if project is None or project.owner_id != user.id:
        raise HTTPException(404, "Project not found")
    return project


CHUNK = 1024 * 1024


async def save_upload(file: UploadFile, path) -> int:
    """Stream an uploaded file to disk in 1 MB chunks, enforcing MAX_UPLOAD_MB without loading it into memory."""
    limit = settings.MAX_UPLOAD_MB * 1024 * 1024
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".part")
    size = 0
    try:
        with open(tmp, "wb") as out:
            while chunk := await file.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise HTTPException(413, f"The ZIP is larger than the {settings.MAX_UPLOAD_MB} MB upload limit. "
                                             "Remove node_modules, venv, .git and build folders before zipping, "
                                             "or raise the limit in Settings.")
                out.write(chunk)
        if size == 0:
            raise HTTPException(400, "The uploaded file is empty")
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
    return size


def _start_scan(db: Session, project: Project, trigger: str = "manual", token: str | None = None) -> Scan:
    scan = Scan(project_id=project.id, trigger=trigger)
    db.add(scan)
    db.commit()
    scan_service.enqueue(scan.id, token)
    return scan


@router.get("")
def list_projects(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    projects = db.scalars(select(Project).where(Project.owner_id == user.id).order_by(Project.id.desc())).all()
    return [project_out(p) for p in projects]


@router.post("/upload")
async def upload_project(name: str = Form(..., max_length=200), file: UploadFile = File(...),
                         user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not (file.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "Please upload a .zip archive of your source code")
    project = Project(owner_id=user.id, name=name.strip() or file.filename, source_type="upload")
    db.add(project)
    db.commit()
    try:
        await save_upload(file, scan_service.upload_path(project.id))
    except HTTPException:
        shutil.rmtree(project_dir(project.id), ignore_errors=True)
        db.delete(project)
        db.commit()
        raise
    scan = _start_scan(db, project)
    return {"project": project_out(project), "scan": scan_out(scan)}


@router.post("/{project_id}/upload")
async def reupload(project_id: int, file: UploadFile = File(...), user: User = Depends(get_current_user),
                   db: Session = Depends(get_db)):
    """Upload a new version of the code for an existing project and scan it (used by the CLI / CI)."""
    project = owned_project(project_id, user, db)
    if project.source_type != "upload":
        raise HTTPException(400, "This project is linked to GitHub; trigger a scan instead")
    await save_upload(file, scan_service.upload_path(project.id))
    scan = _start_scan(db, project, trigger="ci")
    return scan_out(scan)


@router.post("/github")
def connect_github(body: GithubIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        owner, repo = parse_github_url(body.repo_url)
    except IngestionError as exc:
        raise HTTPException(400, str(exc))
    project = Project(owner_id=user.id, name=body.name.strip() or f"{owner}/{repo}", source_type="github",
                      repo_url=f"https://github.com/{owner}/{repo}", branch=body.branch.strip())
    db.add(project)
    db.commit()
    scan = _start_scan(db, project, token=body.token)
    return {"project": project_out(project), "scan": scan_out(scan)}


@router.get("/{project_id}")
def get_project(project_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = owned_project(project_id, user, db)
    return {**project_out(project), "scans": [scan_out(s) for s in project.scans]}


@router.post("/{project_id}/scans")
def rescan(project_id: int, body: ScanIn | None = None, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    project = owned_project(project_id, user, db)
    return scan_out(_start_scan(db, project, token=body.token if body else None))


@router.delete("/{project_id}")
def delete_project(project_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    project = owned_project(project_id, user, db)
    for s in project.scans:
        scan_service.delete_scan_files(s.id)
    shutil.rmtree(project_dir(project.id), ignore_errors=True)
    db.delete(project)
    db.commit()
    return {"deleted": project_id}
