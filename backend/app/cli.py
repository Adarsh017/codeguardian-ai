"""CodeGuardian AI command-line scanner (used locally and in CI/CD pipelines).

Examples
  python -m app.cli scan ../samples/vulnerable-app
  python -m app.cli scan . --fail-on critical --format json,sarif,pdf --output reports
  python -m app.cli scan . --server http://localhost:8000 --token <JWT> --project 3   # also push to dashboard

Exit codes: 0 = quality gate passed, 1 = quality gate failed, 2 = usage / runtime error.
"""
import argparse
import io
import os
import sys
import time
import zipfile
from pathlib import Path

COLORS = {"Critical": "\033[1;31m", "High": "\033[31m", "Medium": "\033[33m", "Low": "\033[36m", "Info": "\033[90m"}
RESET = "\033[0m"


def _c(text: str, sev: str, use_color: bool) -> str:
    return f"{COLORS.get(sev, '')}{text}{RESET}" if use_color else text


def scan_local(args) -> int:
    from .config import settings
    from .services import report as report_service
    from .services.orchestrator import Orchestrator

    root = Path(args.path).resolve()
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 2
    if args.offline:
        settings.OSV_ENABLED = False
    if args.no_ai:
        settings.LLM_PROVIDER = "none"
    use_color = sys.stdout.isatty() and not args.no_color

    def progress(stage, pct):
        if not args.quiet:
            print(f"  [{pct:3d}%] {stage}", file=sys.stderr)

    print(f"CodeGuardian AI - scanning {root}", file=sys.stderr)
    result = Orchestrator(progress=progress, fail_on=args.fail_on, min_security_score=args.min_score,
                          exclude=["codeguardian-reports", *[e for e in args.exclude.split(",") if e]]).run(root)
    findings = [f.to_dict() for f in result["findings"]]
    min_level = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[args.min_severity]
    from .agents.rules import SEVERITY_ORDER
    shown = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= min_level]

    # ---- console output
    info, scores, gate = result["codebase"], result["scores"], result["gate"]
    print()
    print(f"Files: {info['files']}  Lines: {info['lines']}  Dependencies: {info['dependencies']}  "
          f"Engine: {result['engine']}  AI: {'on (' + settings.LLM_MODEL + ')' if result['ai_review']['llm']['enabled'] else 'off'}")
    print(f"Security score: {scores['security_score']:.0f}/100 ({scores['security_grade']})   "
          f"Quality score: {scores['quality_score']:.0f}/100 ({scores['quality_grade']})")
    print("Findings: " + "  ".join(_c(f"{k}: {v}", k, use_color) for k, v in result["severity_counts"].items()))
    print()
    for f in shown[: args.max_print]:
        print(_c(f"[{f['severity']:<8}]", f["severity"], use_color) + f" {f['file']}:{f['line']}  {f['title']}")
        if args.verbose:
            if f["snippet"]:
                print(f"            > {f['snippet']}")
            print(f"            fix: {f['remediation'].splitlines()[0] if f['remediation'] else ''}")
            if f["fixed_code"]:
                print("            suggested: " + f["fixed_code"].replace("\n", "\n                       "))
    if len(shown) > args.max_print:
        print(f"... and {len(shown) - args.max_print} more (see the exported report)")
    print()
    print("Quality gate: " + ("PASSED" if gate["passed"] else "FAILED - " + "; ".join(gate["reasons"])))

    # ---- report export
    if args.format:
        out_dir = Path(args.output)
        out_dir.mkdir(parents=True, exist_ok=True)
        report = report_service.build_report({
            "project": args.project_name or root.name, "scan_id": "cli", "scores": scores, "gate": gate,
            "summary": result["summary"], "severity_counts": result["severity_counts"],
            "category_counts": result["category_counts"], "codebase": info, "agents": result["agents"],
            "timings": result["timings"], "commit_sha": os.getenv("GITHUB_SHA", ""),
        }, findings)
        for fmt in args.format.split(","):
            fmt = fmt.strip().lower()
            if fmt not in report_service.EXPORTERS:
                print(f"warning: unknown format {fmt}", file=sys.stderr)
                continue
            exporter, _ = report_service.EXPORTERS[fmt]
            path = out_dir / f"codeguardian-report.{fmt if fmt != 'sarif' else 'sarif'}"
            path.write_bytes(exporter(report))
            print(f"Report written: {path}")

    # ---- GitHub Actions job summary
    summary_file = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write("## CodeGuardian AI scan\n\n")
            fh.write(f"**Quality gate:** {'✅ PASSED' if gate['passed'] else '❌ FAILED'}  \n")
            fh.write(f"**Security score:** {scores['security_score']:.0f}/100 · **Quality score:** {scores['quality_score']:.0f}/100\n\n")
            fh.write("| Severity | Count |\n|---|---|\n")
            for k, v in result["severity_counts"].items():
                fh.write(f"| {k} | {v} |\n")
            fh.write("\n| Severity | Location | Issue |\n|---|---|---|\n")
            for f in findings[:30]:
                fh.write(f"| {f['severity']} | `{f['file']}:{f['line']}` | {f['title'].replace('|', '/')} |\n")
            fh.write(f"\n{result['summary']}\n")

    if args.server:
        push_to_server(args, root)
    return 0 if gate["passed"] else 1


def push_to_server(args, root: Path) -> None:
    """Upload the code to a CodeGuardian server project so results appear on the dashboard."""
    import httpx
    from .services.preprocessing import SKIP_DIRS

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in root.rglob("*"):
            if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts):
                zf.write(p, p.relative_to(root).as_posix())
    headers = {"Authorization": f"Bearer {args.token}"}
    base = args.server.rstrip("/")
    with httpx.Client(timeout=120, headers=headers) as client:
        if args.project:
            r = client.post(f"{base}/api/projects/{args.project}/upload", files={"file": ("code.zip", buf.getvalue())})
            r.raise_for_status()
            scan = r.json()
        else:
            r = client.post(f"{base}/api/projects/upload", data={"name": args.project_name or root.name},
                            files={"file": ("code.zip", buf.getvalue())})
            r.raise_for_status()
            scan = r.json()["scan"]
        print(f"Uploaded to dashboard: scan #{scan['id']}", file=sys.stderr)
        for _ in range(300):
            s = client.get(f"{base}/api/scans/{scan['id']}").json()
            if s["status"] in ("completed", "failed"):
                print(f"Dashboard scan #{s['id']} {s['status']}", file=sys.stderr)
                break
            time.sleep(2)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="codeguardian", description="CodeGuardian AI multi-agent code scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="Scan a directory")
    s.add_argument("path", nargs="?", default=".")
    s.add_argument("--fail-on", default=os.getenv("GATE_FAIL_ON", "high"),
                   choices=["critical", "high", "medium", "low", "none"], help="Severity that fails the quality gate")
    s.add_argument("--min-score", type=float, default=float(os.getenv("GATE_MIN_SECURITY_SCORE", "0")),
                   help="Minimum security score required to pass")
    s.add_argument("--min-severity", default="low", choices=["info", "low", "medium", "high", "critical"],
                   help="Lowest severity to print to the console")
    s.add_argument("--format", default="", help="Comma separated: json,csv,pdf,sarif")
    s.add_argument("--output", default="codeguardian-reports")
    s.add_argument("--exclude", default="", help="Comma separated glob patterns to skip (also read from .codeguardianignore)")
    s.add_argument("--project-name", default="")
    s.add_argument("--offline", action="store_true", help="Do not query OSV.dev / package registries")
    s.add_argument("--no-ai", action="store_true", help="Disable the LLM even if configured")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--quiet", "-q", action="store_true")
    s.add_argument("--verbose", "-v", action="store_true", help="Show code and suggested fixes")
    s.add_argument("--max-print", type=int, default=50)
    s.add_argument("--server", default="", help="CodeGuardian server URL to push results to the dashboard")
    s.add_argument("--token", default=os.getenv("CODEGUARDIAN_TOKEN", ""))
    s.add_argument("--project", type=int, default=0, help="Existing dashboard project id")
    args = parser.parse_args(argv)
    try:
        return scan_local(args)
    except KeyboardInterrupt:
        return 2


if __name__ == "__main__":
    sys.exit(main())
