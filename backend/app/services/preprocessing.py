"""Preprocessing layer: file extraction, language detection, parsing,
dependency identification, normalization and repository info."""
import ast
import fnmatch
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:  # Python 3.10
    tomllib = None

LANGUAGES = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".php": "php", ".rb": "ruby",
    ".go": "go", ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".cs": "csharp",
    ".kt": "kotlin", ".swift": "swift", ".rs": "rust", ".sql": "sql", ".sh": "shell",
    ".html": "html", ".yml": "yaml", ".yaml": "yaml", ".env": "config", ".ini": "config",
    ".cfg": "config", ".json": "json", ".xml": "xml", ".properties": "config", ".tf": "terraform",
}
SPECIAL_FILES = {"Dockerfile": "docker", ".env": "config", "requirements.txt": "manifest",
                 "package.json": "manifest", "pyproject.toml": "manifest", "Pipfile": "manifest"}
SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build", ".next",
             ".idea", ".vscode", "target", "vendor", ".tox", ".mypy_cache", ".pytest_cache", "coverage",
             "site-packages", "bower_components", ".gradle"}
MAX_FILE_BYTES = 1_000_000


@dataclass
class SourceFile:
    path: str            # path relative to the project root (forward slashes)
    language: str
    code: str
    tree: ast.AST | None = None  # Python AST when parseable

    @property
    def lines(self) -> list[str]:
        return self.code.splitlines()


@dataclass
class Dependency:
    name: str
    version: str
    ecosystem: str       # "PyPI" | "npm"
    manifest: str        # file it was declared in
    line: int = 0


@dataclass
class CodeBase:
    root: Path
    files: list[SourceFile] = field(default_factory=list)
    dependencies: list[Dependency] = field(default_factory=list)
    imports: set[str] = field(default_factory=set)
    skipped: int = 0
    parse_errors: list[str] = field(default_factory=list)

    def info(self) -> dict:
        langs: dict[str, dict] = {}
        for f in self.files:
            entry = langs.setdefault(f.language, {"files": 0, "lines": 0})
            entry["files"] += 1
            entry["lines"] += len(f.lines)
        return {
            "files": len(self.files),
            "lines": sum(len(f.lines) for f in self.files),
            "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1]["lines"])),
            "dependencies": len(self.dependencies),
            "skipped_files": self.skipped,
            "parse_errors": self.parse_errors[:20],
        }


def _is_binary(sample: bytes) -> bool:
    return b"\x00" in sample[:4096]


def normalize(code: str) -> str:
    """Normalize line endings and tabs, strip BOM and trailing whitespace at EOF."""
    code = code.lstrip("﻿").replace("\r\n", "\n").replace("\r", "\n")
    return code.rstrip() + "\n" if code.strip() else ""


def detect_language(path: Path) -> str | None:
    if path.name in SPECIAL_FILES:
        return SPECIAL_FILES[path.name]
    if path.name.startswith(".env"):
        return "config"
    return LANGUAGES.get(path.suffix.lower())


# ---------------------------------------------------------------- dependencies
_REQ_RE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([\w.\-*]+)?")


def _parse_requirements(text: str, manifest: str) -> list[Dependency]:
    deps = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            continue
        m = _REQ_RE.match(line)
        if m:
            version = m.group(3) if m.group(2) == "==" else (m.group(3) or "")
            deps.append(Dependency(m.group(1).lower(), version or "", "PyPI", manifest, i))
    return deps


def _parse_package_json(text: str, manifest: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = []
    lines = text.splitlines()
    for section in ("dependencies", "devDependencies"):
        for name, spec in (data.get(section) or {}).items():
            version = re.sub(r"^[\^~>=<\s]+", "", str(spec)).split(" ")[0]
            line_no = next((i for i, l in enumerate(lines, 1) if f'"{name}"' in l), 0)
            deps.append(Dependency(name, version, "npm", manifest, line_no))
    return deps


def _parse_pyproject(text: str, manifest: str) -> list[Dependency]:
    if tomllib is None:
        return []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    specs = list((data.get("project") or {}).get("dependencies") or [])
    poetry = ((data.get("tool") or {}).get("poetry") or {}).get("dependencies") or {}
    specs += [f"{k}=={str(v).lstrip('^~')}" if isinstance(v, str) else k for k, v in poetry.items() if k != "python"]
    return _parse_requirements("\n".join(specs), manifest)


# ---------------------------------------------------------------- main entry
def load_ignore_patterns(root: Path) -> list[str]:
    """Read gitignore-style patterns from .codeguardianignore (one glob per line)."""
    ignore = root / ".codeguardianignore"
    if not ignore.exists():
        return []
    return [l.strip().rstrip("/") for l in ignore.read_text(encoding="utf-8", errors="ignore").splitlines()
            if l.strip() and not l.strip().startswith("#")]


def _excluded(rel: str, patterns: list[str]) -> bool:
    """A pattern matches the path itself, or any directory prefix of it (e.g. 'samples' or 'samples/*')."""
    parts = rel.split("/")
    prefixes = ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]
    for pat in patterns:
        pat = pat.lstrip("/")
        if pat.endswith("/*"):
            pat = pat[:-2]
        if any(fnmatch.fnmatch(p, pat) for p in prefixes):
            return True
    return False


def preprocess(root: Path, exclude: list[str] | None = None) -> CodeBase:
    cb = CodeBase(root=root)
    patterns = (exclude or []) + load_ignore_patterns(root)
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(p in SKIP_DIRS for p in rel_parts[:-1]):
            continue
        rel = "/".join(rel_parts)
        if patterns and _excluded(rel, patterns):
            cb.skipped += 1
            continue
        language = detect_language(path)
        if language is None or path.stat().st_size > MAX_FILE_BYTES:
            cb.skipped += 1
            continue
        raw = path.read_bytes()
        if _is_binary(raw):
            cb.skipped += 1
            continue
        code = normalize(raw.decode("utf-8", errors="replace"))

        # Dependency identification
        if path.name == "requirements.txt" or (path.name.startswith("requirements") and path.suffix == ".txt"):
            cb.dependencies += _parse_requirements(code, rel)
            language = "manifest"
        elif path.name == "package.json":
            cb.dependencies += _parse_package_json(code, rel)
        elif path.name == "pyproject.toml":
            cb.dependencies += _parse_pyproject(code, rel)

        sf = SourceFile(rel, language, code)
        if language == "python":
            try:
                sf.tree = ast.parse(code, filename=rel)
                for node in ast.walk(sf.tree):
                    if isinstance(node, ast.Import):
                        cb.imports.update(a.name.split(".")[0] for a in node.names)
                    elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                        cb.imports.add(node.module.split(".")[0])
            except SyntaxError as exc:
                cb.parse_errors.append(f"{rel}:{exc.lineno}: {exc.msg}")
        elif language in ("javascript", "typescript"):
            for m in re.finditer(r"""(?:require\(|from\s+)['"]([^'".][^'"]*)['"]""", code):
                cb.imports.add(m.group(1).split("/")[0])
        cb.files.append(sf)
    return cb
