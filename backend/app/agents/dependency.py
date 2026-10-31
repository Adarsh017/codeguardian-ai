"""Dependency Agent: dependency parsing, CVE lookup (OSV.dev), pinning, license and
undeclared-dependency checks."""
import ast
import re
import sys
from concurrent.futures import ThreadPoolExecutor

import httpx

from ..config import settings
from ..services.preprocessing import CodeBase, Dependency
from .base import Agent, RawFinding

# Offline fallback advisories (used when OSV.dev is unreachable / disabled).
# (ecosystem, package) -> list of (fixed_in_version, advisory id, summary, severity)
OFFLINE_ADVISORIES = {
    ("PyPI", "requests"): [("2.31.0", "CVE-2023-32681", "Proxy-Authorization header leaked to destination on redirect", "Medium")],
    ("PyPI", "pyyaml"): [("5.4", "CVE-2020-14343", "Arbitrary code execution via full_load / FullLoader", "Critical")],
    ("PyPI", "urllib3"): [("1.26.5", "CVE-2021-33503", "ReDoS in URL authority parsing", "High")],
    ("PyPI", "jinja2"): [("2.11.3", "CVE-2020-28493", "ReDoS in urlize filter", "Medium")],
    ("PyPI", "flask"): [("2.2.5", "CVE-2023-30861", "Session cookie may be cached and shared by proxies", "High")],
    ("PyPI", "werkzeug"): [("2.2.3", "CVE-2023-25577", "High resource usage when parsing multipart form data", "High")],
    ("PyPI", "pillow"): [("9.0.1", "CVE-2022-22817", "ImageMath.eval allows arbitrary expression evaluation", "Critical")],
    ("npm", "lodash"): [("4.17.21", "CVE-2021-23337", "Command injection via template()", "High")],
    ("npm", "minimist"): [("1.2.6", "CVE-2021-44906", "Prototype pollution", "Critical")],
    ("npm", "axios"): [("0.21.1", "CVE-2020-28168", "Server-side request forgery via redirect", "Medium")],
    ("npm", "jsonwebtoken"): [("9.0.0", "CVE-2022-23540", "Insecure default algorithm allows signature bypass", "High")],
    ("npm", "express"): [("4.17.3", "CVE-2022-24999", "Prototype pollution via qs dependency", "High")],
    ("npm", "node-fetch"): [("2.6.7", "CVE-2022-0235", "Exposure of sensitive information to an unauthorized actor", "High")],
}
COPYLEFT = re.compile(r"\b(A?GPL|LGPL|GNU (Affero )?General Public|SSPL|EUPL|OSL)\b", re.I)
IMPORT_TO_PACKAGE = {"yaml": "pyyaml", "PIL": "pillow", "cv2": "opencv-python", "sklearn": "scikit-learn",
                     "bs4": "beautifulsoup4", "jwt": "pyjwt", "dotenv": "python-dotenv", "dateutil": "python-dateutil",
                     "Crypto": "pycryptodome", "MySQLdb": "mysqlclient", "psycopg2": "psycopg2-binary",
                     "google": "google-api-python-client", "magic": "python-magic", "multipart": "python-multipart",
                     "jose": "python-jose", "attr": "attrs", "pkg_resources": "setuptools", "serial": "pyserial",
                     "skimage": "scikit-image", "docx": "python-docx", "pptx": "python-pptx", "fitz": "pymupdf"}
OSV_SEVERITY = {"CRITICAL": "Critical", "HIGH": "High", "MODERATE": "Medium", "MEDIUM": "Medium", "LOW": "Low"}


def parse_version(v: str) -> tuple:
    parts = []
    for p in re.split(r"[.\-+]", v):
        m = re.match(r"(\d+)", p)
        parts.append(int(m.group(1)) if m else 0)
    return tuple(parts + [0] * (4 - len(parts)))


def _normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


class DependencyAgent(Agent):
    name = "Dependency Agent"
    category = "Dependency"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        out: list[RawFinding] = []
        by_path = {f.path: f for f in codebase.files}
        deps = codebase.dependencies
        for dep in deps:
            if not dep.version or not re.match(r"^\d", dep.version) or dep.version in ("*", "latest"):
                sf = by_path.get(dep.manifest)
                if sf:
                    out.append(self.finding("DEP002", sf, dep.line, title=f"Unpinned dependency '{dep.name}'"))
        pinned = [d for d in deps if d.version and re.match(r"^\d", d.version)]
        vulns = self._osv(pinned) if settings.OSV_ENABLED else None
        if vulns is None:
            vulns = self._offline(pinned)
        for dep, advisory in vulns:
            sf = by_path.get(dep.manifest)
            if sf is None:
                continue
            fixed = f" Upgrade to {advisory['fixed']} or later." if advisory.get("fixed") else ""
            out.append(self.finding(
                "DEP001", sf, dep.line,
                title=f"{dep.name}@{dep.version}: {advisory['id']} — {advisory['summary']}"[:300],
                severity=advisory["severity"], confidence=0.95,
                description=f"{advisory['summary']} ({advisory['id']}). Affects {dep.name} {dep.version} "
                            f"declared in {dep.manifest}.",
                remediation=f"Upgrade {dep.name} in {dep.manifest}.{fixed} See https://osv.dev/vulnerability/{advisory['id']}",
                fixed_code=f"{dep.name}=={advisory['fixed']}" if advisory.get("fixed") and dep.ecosystem == "PyPI" else ""))
        if settings.OSV_ENABLED:
            out += self._licenses(deps, by_path)
        out += self._undeclared(codebase)
        return out

    # ---------------------------------------------------------------- CVEs
    def _osv(self, deps: list[Dependency]):
        if not deps:
            return []
        try:
            with httpx.Client(timeout=20) as client:
                queries = [{"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in deps]
                results = []
                for i in range(0, len(queries), 500):
                    r = client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries[i:i + 500]})
                    r.raise_for_status()
                    results += r.json().get("results", [])
                pairs = [(dep, v["id"]) for dep, res in zip(deps, results) for v in (res.get("vulns") or [])]
                details = {}

                def fetch(vid):
                    resp = client.get(f"https://api.osv.dev/v1/vulns/{vid}")
                    return vid, resp.json() if resp.status_code == 200 else {}
                with ThreadPoolExecutor(8) as pool:
                    for vid, data in pool.map(fetch, list({vid for _, vid in pairs})[:80]):
                        details[vid] = data
        except Exception:
            return None
        out = []
        for dep, vid in pairs:
            data = details.get(vid, {})
            aliases = [a for a in data.get("aliases", []) if a.startswith("CVE-")]
            sev = OSV_SEVERITY.get(str((data.get("database_specific") or {}).get("severity", "")).upper(), "High")
            fixed = ""
            for aff in data.get("affected", []):
                if _normalize(aff.get("package", {}).get("name", "")) == _normalize(dep.name):
                    for rng in aff.get("ranges", []):
                        for ev in rng.get("events", []):
                            if "fixed" in ev and parse_version(ev["fixed"]) > parse_version(dep.version):
                                if not fixed or parse_version(ev["fixed"]) < parse_version(fixed):
                                    fixed = ev["fixed"]
            out.append((dep, {"id": aliases[0] if aliases else vid, "summary": data.get("summary") or "Known vulnerability",
                              "severity": sev, "fixed": fixed}))
        return out

    def _offline(self, deps: list[Dependency]):
        out = []
        for dep in deps:
            for fixed, adv_id, summary, sev in OFFLINE_ADVISORIES.get((dep.ecosystem, _normalize(dep.name)), []):
                if parse_version(dep.version) < parse_version(fixed):
                    out.append((dep, {"id": adv_id, "summary": summary, "severity": sev, "fixed": fixed}))
        return out

    # ---------------------------------------------------------------- licenses
    def _licenses(self, deps: list[Dependency], by_path) -> list[RawFinding]:
        def lookup(dep: Dependency):
            try:
                if dep.ecosystem == "PyPI":
                    r = httpx.get(f"https://pypi.org/pypi/{dep.name}/json", timeout=8)
                    info = r.json().get("info", {}) if r.status_code == 200 else {}
                    lic = (info.get("license") or "")[:100] + " " + " ".join(c for c in info.get("classifiers", []) if "License" in c)
                else:
                    r = httpx.get(f"https://registry.npmjs.org/{dep.name}/latest", timeout=8)
                    lic = str(r.json().get("license", "")) if r.status_code == 200 else ""
                return dep, lic
            except Exception:
                return dep, ""
        out = []
        with ThreadPoolExecutor(8) as pool:
            for dep, lic in pool.map(lookup, deps[:60]):
                m = COPYLEFT.search(lic or "")
                if m and by_path.get(dep.manifest):
                    out.append(self.finding("DEP003", by_path[dep.manifest], dep.line,
                                            title=f"'{dep.name}' uses a copyleft license ({m.group(0)})"))
        return out

    # ---------------------------------------------------------------- undeclared
    def _undeclared(self, codebase: CodeBase) -> list[RawFinding]:
        py_files = [f for f in codebase.files if f.language == "python"]
        if not py_files or not any(f.language == "manifest" or f.path.endswith(("pyproject.toml", "setup.py"))
                                   for f in codebase.files):
            return []  # no manifest at all -> nothing to compare against
        declared = {_normalize(d.name) for d in codebase.dependencies if d.ecosystem == "PyPI"}
        local = set()
        for f in codebase.files:
            parts = f.path.split("/")
            local.update(p.removesuffix(".py") for p in parts)
        stdlib = set(sys.stdlib_module_names)
        out, reported = [], set()
        for f in py_files:
            if f.tree is None:
                continue
            for node in ast.walk(f.tree):
                mods = []
                if isinstance(node, ast.Import):
                    mods = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                    mods = [node.module.split(".")[0]]
                for mod in mods:
                    if mod in stdlib or mod in local or mod.startswith("_"):
                        continue
                    pkg = _normalize(IMPORT_TO_PACKAGE.get(mod, mod))
                    if pkg not in declared and _normalize(mod) not in declared and pkg not in reported:
                        reported.add(pkg)
                        out.append(self.finding("DEP004", f, node.lineno, title=f"Package '{mod}' is imported but not declared",
                                                confidence=0.6))
        return out
