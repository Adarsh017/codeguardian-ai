"""Input layer: ZIP upload extraction and GitHub repository import."""
import io
import re
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import httpx

from ..config import settings
from .preprocessing import MAX_FILE_BYTES, SKIP_DIRS

GITHUB_RE = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


class IngestionError(Exception):
    pass


def project_dir(project_id: int) -> Path:
    return settings.STORAGE_DIR / "projects" / str(project_id)


def source_dir(project_id: int) -> Path:
    return project_dir(project_id) / "src"


def safe_extract_zip(source: bytes | Path, dest: Path) -> int:
    """Extract a ZIP (bytes or a path on disk) while blocking zip-slip, absolute paths and zip bombs.

    Folders that are never analysed (node_modules, .git, venv, build output...) and files larger
    than the analyser reads are skipped, so big archives extract quickly and use little disk."""
    max_total = settings.MAX_EXTRACT_MB * 1024 * 1024
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    dest_resolved = dest.resolve()
    total = 0
    count = 0
    try:
        zf = zipfile.ZipFile(source if isinstance(source, Path) else io.BytesIO(source))
    except zipfile.BadZipFile as exc:
        raise IngestionError("Uploaded file is not a valid ZIP archive") from exc
    with zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest / info.filename).resolve()
            if not str(target).startswith(str(dest_resolved)):
                raise IngestionError(f"Unsafe path in archive: {info.filename}")
            parts = info.filename.replace("\\", "/").split("/")
            if any(p in SKIP_DIRS for p in parts[:-1]) or info.file_size > MAX_FILE_BYTES:
                continue
            total += info.file_size
            if total > max_total:
                raise IngestionError(f"Archive is larger than {settings.MAX_EXTRACT_MB} MB once extracted")
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as src, open(target, "wb") as out:
                shutil.copyfileobj(src, out)
            count += 1
    if count == 0:
        raise IngestionError("The archive contains no source files that can be analysed")
    _flatten_single_root(dest)
    return count


def _flatten_single_root(dest: Path) -> None:
    """If the archive contains a single top-level folder, lift its contents up."""
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir():
        inner = entries[0]
        for child in inner.iterdir():
            shutil.move(str(child), str(dest / child.name))
        inner.rmdir()


def parse_github_url(url: str) -> tuple[str, str]:
    match = GITHUB_RE.search(url.strip())
    if not match:
        raise IngestionError("Not a valid GitHub repository URL (expected https://github.com/owner/repo)")
    return match.group(1), match.group(2)


def _gh_headers(token: str | None) -> dict:
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "CodeGuardian-AI"}
    tok = token or settings.GITHUB_TOKEN
    if tok:
        headers["Authorization"] = f"Bearer {tok}"
    return headers


def fetch_github_repo(url: str, dest: Path, branch: str = "", token: str | None = None) -> dict:
    """Download the latest commit of a GitHub repo. Returns repo metadata.

    Tries the GitHub REST API (zipball) first; falls back to `git clone --depth 1`.
    """
    owner, repo = parse_github_url(url)
    meta = {"owner": owner, "repo": repo, "branch": branch, "commit_sha": ""}
    try:
        with httpx.Client(timeout=60, follow_redirects=True, headers=_gh_headers(token)) as client:
            info = client.get(f"https://api.github.com/repos/{owner}/{repo}")
            if info.status_code == 404:
                raise IngestionError("Repository not found or not accessible (private repos need a token)")
            info.raise_for_status()
            repo_info = info.json()
            ref = branch or repo_info.get("default_branch", "main")
            meta.update(branch=ref, description=repo_info.get("description") or "",
                        stars=repo_info.get("stargazers_count", 0), language=repo_info.get("language"))
            commit = client.get(f"https://api.github.com/repos/{owner}/{repo}/commits/{ref}")
            if commit.status_code == 200:
                meta["commit_sha"] = commit.json().get("sha", "")
            # stream the archive to a temp file instead of holding it in memory
            with tempfile.TemporaryDirectory() as tmp:
                zip_path = Path(tmp) / "repo.zip"
                with client.stream("GET", f"https://api.github.com/repos/{owner}/{repo}/zipball/{ref}") as archive:
                    archive.raise_for_status()
                    with open(zip_path, "wb") as fh:
                        for chunk in archive.iter_bytes(1024 * 1024):
                            fh.write(chunk)
                safe_extract_zip(zip_path, dest)
            return meta
    except IngestionError:
        raise
    except Exception:  # network/API failure -> try git
        pass

    if dest.exists():
        shutil.rmtree(dest)
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["--branch", branch]
    clone_url = f"https://github.com/{owner}/{repo}.git"
    tok = token or settings.GITHUB_TOKEN
    if tok:
        clone_url = f"https://x-access-token:{tok}@github.com/{owner}/{repo}.git"
    result = subprocess.run(cmd + [clone_url, str(dest)], capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise IngestionError(f"Could not fetch repository: {result.stderr.strip()[:300]}")
    sha = subprocess.run(["git", "-C", str(dest), "rev-parse", "HEAD"], capture_output=True, text=True)
    meta["commit_sha"] = sha.stdout.strip()
    shutil.rmtree(dest / ".git", ignore_errors=True)
    return meta
