from datetime import datetime, timezone

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    projects = relationship("Project", back_populates="owner", cascade="all, delete-orphan")


class Project(Base):
    __tablename__ = "projects"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    source_type: Mapped[str] = mapped_column(String(20))  # "upload" | "github"
    repo_url: Mapped[str] = mapped_column(String(500), default="")
    branch: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    owner = relationship("User", back_populates="projects")
    scans = relationship("Scan", back_populates="project", cascade="all, delete-orphan",
                         order_by="Scan.id.desc()")


class Scan(Base):
    __tablename__ = "scans"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), default="queued")  # queued|running|completed|failed
    stage: Mapped[str] = mapped_column(String(60), default="Queued")
    progress: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(Text, default="")
    trigger: Mapped[str] = mapped_column(String(20), default="manual")  # manual|ci|api
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    security_score: Mapped[float] = mapped_column(Float, default=0)
    quality_score: Mapped[float] = mapped_column(Float, default=0)
    overall_score: Mapped[float] = mapped_column(Float, default=0)
    gate_passed: Mapped[int] = mapped_column(Integer, default=1)
    summary: Mapped[dict] = mapped_column(JSON, default=dict)  # counts, languages, timings, ai summary
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    project = relationship("Project", back_populates="scans")
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id"), index=True)
    agent: Mapped[str] = mapped_column(String(40))
    category: Mapped[str] = mapped_column(String(40))
    rule_id: Mapped[str] = mapped_column(String(80))
    title: Mapped[str] = mapped_column(String(300))
    severity: Mapped[str] = mapped_column(String(10))
    confidence: Mapped[float] = mapped_column(Float, default=0.8)
    file: Mapped[str] = mapped_column(String(500), default="")
    line: Mapped[int] = mapped_column(Integer, default=0)
    snippet: Mapped[str] = mapped_column(Text, default="")
    description: Mapped[str] = mapped_column(Text, default="")
    explanation: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")
    fixed_code: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str] = mapped_column(String(40), default="")
    owasp: Mapped[str] = mapped_column(String(80), default="")
    ai_reviewed: Mapped[int] = mapped_column(Integer, default=0)
    sources: Mapped[list] = mapped_column(JSON, default=list)
    scan = relationship("Scan", back_populates="findings")
