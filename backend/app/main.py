"""CodeGuardian AI - API backend (FastAPI)."""
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .config import settings
from .database import SessionLocal, init_db
from .models import Scan
from .routers import auth, dashboard, projects, scans
from .services import runtime_settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    runtime_settings.load()
    # scans interrupted by a restart can never finish -> mark them failed
    with SessionLocal() as db:
        for scan in db.query(Scan).filter(Scan.status.in_(["queued", "running"])).all():
            scan.status, scan.stage, scan.error = "failed", "Failed", "Interrupted by server restart"
        db.commit()
    yield


app = FastAPI(title=settings.APP_NAME, lifespan=lifespan, version=settings.VERSION,
              description="Multi-Agent Intelligent Platform for Automated Secure Code Review and Vulnerability Detection")
app.add_middleware(CORSMiddleware, allow_origins=settings.CORS_ORIGINS, allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])

for r in (auth.router, projects.router, scans.router, dashboard.router):
    app.include_router(r)


# Serve the built React app (frontend/dist) when present, so one process runs everything.
FRONTEND_DIST = Path(__file__).resolve().parents[2] / "frontend" / "dist"
if FRONTEND_DIST.exists():
    app.mount("/assets", StaticFiles(directory=FRONTEND_DIST / "assets"), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str):
        if full_path.startswith("api/"):
            raise HTTPException(404, "Not found")
        candidate = (FRONTEND_DIST / full_path).resolve()
        if full_path and candidate.is_file() and str(candidate).startswith(str(FRONTEND_DIST)):
            return FileResponse(candidate)
        return FileResponse(FRONTEND_DIST / "index.html")
