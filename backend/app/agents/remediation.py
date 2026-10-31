"""AI Remediation Agent: generates secure code alternatives, optimized solutions and
step-by-step fixes. Uses the LLM when configured, plus deterministic rule-based auto-fixes."""
import json
import logging
import re

from ..config import settings
from ..services import llm
from ..services.preprocessing import CodeBase
from .base import RawFinding, context

log = logging.getLogger("codeguardian.remediation")

SYSTEM = """You are the AI Remediation Agent of CodeGuardian AI. For each confirmed finding you get the code context
(line numbers on the left). Produce a minimal, secure, drop-in replacement for the flagged line(s) that follows
secure-coding standards (OWASP, CERT) and keeps the original behaviour. Keep the same language and style; do not
include line numbers in the fix. Also give short step-by-step remediation guidance.
Respond ONLY with JSON:
{"fixes": [{"id": <int>, "fixed_code": "<replacement code>", "steps": ["step 1", "step 2", "..."]}]}"""
BATCH = 6


def _sql_fstring_fix(line: str) -> str | None:
    m = re.search(r"""\bf(["'])(.*?)\1""", line)
    if not m:
        return None
    body, params = m.group(2), []

    def repl(mm):
        params.append(mm.group(2).strip())
        return "%s"
    new_body = re.sub(r"""(['"]?)\{([^{}]+)\}\1""", repl, body)
    if not params:
        return None
    query = f'"{new_body}"'
    tuple_src = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    replaced = line[:m.start()] + query + line[m.end():]
    if re.search(r"\.(execute|executemany)\(", line):
        return re.sub(r"\)\s*$", f", {tuple_src})", replaced.rstrip(), count=1)
    return replaced + f"\n# then: cursor.execute({line.split('=')[0].strip()}, {tuple_src})"


def _sql_concat_fix(line: str) -> str | None:
    if "%" in line and re.search(r"""["'].*%s.*["']\s*%\s*""", line):
        m = re.search(r"""(["'].*?["'])\s*%\s*(\(.*\)|\w+)""", line)
        if m:
            params = m.group(2) if m.group(2).startswith("(") else f"({m.group(2)},)"
            if ".execute(" in line:
                return line.replace(m.group(0), f"{m.group(1)}, {params}")
    return None


def _secret_fix(line: str) -> str | None:
    m = re.match(r"""^(\s*)([\w.\[\]'"]+)\s*=\s*["'][^"']*["']""", line)
    if m:
        target = m.group(2)
        env = re.sub(r"[^A-Za-z0-9]", "_", target.split(".")[-1].strip("[]'\"")).upper()
        return f'{m.group(1)}{target} = os.environ["{env}"]  # set in .env / secret manager'
    m = re.match(r"""^(\s*)(["'])(\w+)\2\s*:\s*["'][^"']*["']""", line)
    if m:
        return f'{m.group(1)}"{m.group(3)}": os.environ["{m.group(3).upper()}"],'
    return None


def rule_based_fix(f: RawFinding) -> str:
    line = f.snippet
    if not line:
        return ""
    r = f.rule_id
    try:
        if r == "SEC002":
            return _sql_fstring_fix(line) or _sql_concat_fix(line) or ""
        if r == "SEC001":
            if "eval(" in line and f.file.endswith(".py"):
                return line.replace("eval(", "ast.literal_eval(", 1) + "  # import ast"
            if "eval(" in line:
                return line.replace("eval(", "JSON.parse(", 1)
        if r == "SEC003":
            if "os.system(" in line:
                return re.sub(r"os\.system\((.*)\)", r"subprocess.run(shlex.split(\1), check=True)", line)
            m = re.search(r"(subprocess\.\w+\()(.+?),\s*shell\s*=\s*True\)", line)
            if m:
                return line.replace(m.group(0), f"{m.group(1)}shlex.split({m.group(2)}), shell=False)") + \
                    "  # validate the input against an allow-list as well"
        if r in ("SEC004", "SEC017") and f.file.endswith(".py"):
            return _secret_fix(line) or ""
        if r == "SEC005":
            if "yaml.load(" in line:
                return re.sub(r"yaml\.load\(([^,)]*)(,[^)]*)?\)", r"yaml.safe_load(\1)", line)
            if "pickle.load" in line:
                return line.replace("pickle.loads", "json.loads").replace("pickle.load", "json.load")
        if r == "SEC006":
            return re.sub(r"hashlib\.(md5|sha1)\(", "hashlib.sha256(", line).replace("createHash('md5')", "createHash('sha256')") \
                .replace('createHash("md5")', 'createHash("sha256")').replace("createHash('sha1')", "createHash('sha256')")
        if r == "SEC007":
            return re.sub(r",?\s*verify\s*=\s*False", "", line).replace("rejectUnauthorized: false", "rejectUnauthorized: true")
        if r == "SEC008":
            if re.search(r"\bDEBUG\s*=\s*True", line):
                return re.sub(r"DEBUG\s*=\s*True", 'DEBUG = os.getenv("DEBUG", "false").lower() == "true"', line)
            return line.replace("debug=True", 'debug=os.getenv("APP_DEBUG") == "1"')
        if r == "SEC009":
            if "render_template_string(" in line:
                return ""  # needs a template rewrite -> left to the AI Remediation agent / manual fix
            return line.replace(".innerHTML", ".textContent").replace(".outerHTML", ".textContent") \
                .replace("Markup(", "escape(")
        if r == "SEC010":
            if "Math.random()" in line:
                line2 = re.sub(r"Math\.random\(\)\.toString\(36\)(\.(substring|substr|slice)\([^)]*\))?", "crypto.randomUUID()", line)
                return line2.replace("Math.random()", "(crypto.getRandomValues(new Uint32Array(1))[0] / 2 ** 32)")
            return re.sub(r"\brandom\.", "secrets.SystemRandom().", line)
        if r == "SEC011":
            line2 = re.sub(r",?\s*verify\s*=\s*False", "", line)
            line2 = re.sub(r"[\"']verify_signature[\"']\s*:\s*False", '"verify_signature": True', line2)
            return line2 if line2 != line else ""
        if r == "SEC012":
            return line.replace('"0.0.0.0"', '"127.0.0.1"').replace("'0.0.0.0'", "'127.0.0.1'")
        if r == "SEC013":
            return re.sub(r"""(['"])\*\1""", '"https://your-frontend.example.com"', line, count=1)
        if r == "SEC014":
            return line.replace("mktemp(", "mkstemp(")
        if r == "SEC018":
            return line.replace("http://", "https://")
        if r == "SEC019":
            return "RUN adduser --disabled-password --gecos '' appuser\nUSER appuser"
        if r == "LOG002":
            return line.replace("!= None", "is not None").replace("== None", "is None")
        if r == "LOG003":
            line2 = re.sub(r"\bis not\s+(?=['\"\d-])", "!= ", line)
            return re.sub(r"\bis\s+(?=['\"\d-])", "== ", line2)
        if r == "QLT005" and re.match(r"\s*except\s*:", line):
            return line.replace("except:", "except Exception as exc:  # narrow to the exceptions you expect; log exc")
        if r == "QLT006":
            return re.sub(r"=\s*(\[\]|\{\}|set\(\)|list\(\)|dict\(\))", "=None", line) + \
                "\n    # inside the function: if arg is None: arg = []"
        if r == "QLT013":
            return re.sub(r"\bvar\s+", "let ", line, count=1)
        if r == "QLT014":
            return re.sub(r"(?<![=!<>])==(?!=)", "===", re.sub(r"!=(?!=)", "!==", line))
        if r == "PRF010":
            return re.sub(r"sorted\((.*?)\)\[0\]", r"min(\1)", re.sub(r"sorted\((.*?)\)\[-1\]", r"max(\1)", line))
        if r == "PRF006" and "time.sleep" in line:
            return line.replace("time.sleep(", "await asyncio.sleep(")
    except re.error:
        return ""
    return ""


class AIRemediationAgent:
    name = "AI Remediation Agent"

    def run(self, findings: list[RawFinding], codebase: CodeBase) -> dict:
        stats = {"rule_based_fixes": 0, "ai_fixes": 0, "errors": []}
        for f in findings:
            if not f.fixed_code:
                fix = rule_based_fix(f)
                if fix and fix.strip() != f.snippet.strip():
                    f.fixed_code = fix
                    stats["rule_based_fixes"] += 1

        if not llm.enabled():
            return stats
        files = {sf.path: sf.code for sf in codebase.files}
        targets = [f for f in findings if f.severity in ("Critical", "High", "Medium") and f.snippet
                   and f.category != "Dependency"][: settings.LLM_MAX_FINDINGS]
        for start in range(0, len(targets), BATCH):
            batch = targets[start:start + BATCH]
            payload = [{"id": i, "issue": f.title, "severity": f.severity, "cwe": f.cwe, "file": f.file, "line": f.line,
                        "flagged_line": f.snippet, "explanation": f.explanation,
                        "code_context": context(files.get(f.file, ""), f.line, 6)} for i, f in enumerate(batch)]
            try:
                data = llm.chat_json(SYSTEM, json.dumps(payload, indent=1))
            except llm.LLMError as exc:
                stats["errors"].append(str(exc)[:200])
                log.warning("AI remediation batch failed: %s", exc)
                continue
            for fix in data.get("fixes", []):
                try:
                    f = batch[int(fix["id"])]
                except (KeyError, ValueError, IndexError, TypeError):
                    continue
                if fix.get("fixed_code"):
                    f.fixed_code = str(fix["fixed_code"]).strip("\n")
                    stats["ai_fixes"] += 1
                steps = fix.get("steps") or []
                if steps:
                    f.remediation = "\n".join(f"{n}. {s}" for n, s in enumerate(steps, 1))
                if "AI Remediation" not in f.sources:
                    f.sources.append("AI Remediation")
        return stats
