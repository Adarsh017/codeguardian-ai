"""Security Agent: SAST rules (Python AST + multi-language patterns), secret detection
(Gitleaks-style), container checks, and optional Bandit / Semgrep integration."""
import ast
import json
import os
import re
import subprocess

from ..services.preprocessing import CodeBase, SourceFile
from .base import (FUNC_TYPES, Agent, RawFinding, call_name, is_dynamic_string, kwarg, line_at,
                   tool_available, tool_path)

SECRET_NAME = re.compile(r"(passw(or)?d|passwd|pwd|secret|api_?key|apikey|access_?key|auth_?token|"
                         r"private_?key|client_?secret|token|credentials?)$", re.I)
PLACEHOLDER = re.compile(r"^(|x+|\*+|\.+|<.*>|\$\{.*\}|\{\{.*\}\}|none|null|true|false|test|[A-Z_]+)$|"
                         r"change[-_ ]?me|replace[-_ ]?(me|with)|your[-_ ]|example|dummy|placeholder|sample|"
                         r"redacted|todo|<[^>]*>", re.I)
SQL_TEXT = re.compile(r"\b(SELECT\b.+\bFROM|INSERT\s+INTO|UPDATE\b.+\bSET|DELETE\s+FROM|DROP\s+TABLE|"
                      r"WHERE\b.+=)", re.I | re.S)
RANDOM_FUNCS = {"random.random", "random.randint", "random.choice", "random.choices", "random.randrange",
                "random.getrandbits", "random.sample", "random.uniform"}
SENSITIVE_NAME = re.compile(r"(token|password|passwd|secret|otp|nonce|salt|session|reset|api_?key|code)", re.I)
TAINT_SOURCES = re.compile(r"\b(request\.(args|form|values|files|json|data|cookies|headers|GET|POST|"
                           r"get_json|query_params|path_params)|input\(|sys\.argv)")

# Gitleaks-style credential signatures
SECRET_PATTERNS = [
    ("AWS Access Key ID", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("Stripe secret key", re.compile(r"\b(sk|rk)_live_[0-9A-Za-z]{20,}\b")),
    ("OpenAI API key", re.compile(r"\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b")),
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{32,}\b")),
    ("Private key", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    ("Database URL with password", re.compile(r"\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis)://[^\s:/@'\"]+:[^\s@'\"]{3,}@")),
]

GENERIC_SECRET_ASSIGN = re.compile(
    r"""(?i)\b([\w-]*(password|passwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|client[_-]?secret|private[_-]?key))\b["']?\s*[:=]\s*["']([^"'\s]{4,})["']""")
CONFIG_SECRET = re.compile(
    r"""(?i)^\s*(export\s+)?([\w.-]*(password|passwd|secret|token|api[_-]?key|private[_-]?key)[\w.-]*)\s*[:=]\s*["']?([^"'\s#]+)""")

JS_RULES = [
    ("SEC001", re.compile(r"\beval\s*\(|\bnew\s+Function\s*\("), {}),
    ("SEC009", re.compile(r"\.(innerHTML|outerHTML)\s*\+?=|document\.write(ln)?\s*\(|dangerouslySetInnerHTML|insertAdjacentHTML\s*\("), {}),
    ("SEC003", re.compile(r"\b(exec|execSync|spawn)\s*\(\s*(`[^`]*\$\{|['\"][^'\"]*['\"]\s*\+)"), {}),
    ("SEC003", re.compile(r"shell\s*:\s*true"), {"confidence": 0.6}),
    ("SEC002", re.compile(r"(?i)([\"'`]\s*(SELECT\b[^\"'`]*\bFROM|INSERT\s+INTO|UPDATE\b[^\"'`]*\bSET|DELETE\s+FROM)[^\"'`]*[\"'`]\s*\+)"), {}),
    ("SEC002", re.compile(r"(?i)`[^`]*(SELECT\b[^`]*\bFROM|INSERT\s+INTO|UPDATE\b[^`]*\bSET|DELETE\s+FROM)[^`]*\$\{"), {}),
    ("SEC010", re.compile(r"(?i)(token|secret|password|otp|nonce|salt|session)\w*\s*[:=][^;\n]*Math\.random"), {}),
    ("SEC011", re.compile(r"""algorithms\s*:\s*\[[^\]]*['"]none['"]"""), {}),
    ("SEC011", re.compile(r"\bjwt\.decode\s*\("), {"severity": "Medium", "confidence": 0.5,
                                                  "description": "jsonwebtoken's jwt.decode() does NOT verify the signature. If this result is trusted for authentication, tokens can be forged."}),
    ("SEC013", re.compile(r"""origin\s*:\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*,\s*['"]\*"""), {}),
    ("SEC007", re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"), {}),
    ("SEC006", re.compile(r"""createHash\(\s*['"](md5|sha1)['"]"""), {}),
    ("SEC015", re.compile(r"(readFile|readFileSync|createReadStream|sendFile)\s*\([^)]*req\.(params|query|body)"), {}),
    ("SEC016", re.compile(r"(axios\.(get|post)|fetch|got|request)\s*\(\s*req\.(params|query|body)"), {}),
]
JAVA_RULES = [
    ("SEC003", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\([^)]*\+"), {}),
    ("SEC002", re.compile(r"(?i)(executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*\"[^\"]*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+"), {}),
    ("SEC006", re.compile(r"""MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"\s*\)"""), {}),
    ("SEC005", re.compile(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\("), {"confidence": 0.6}),
    ("SEC010", re.compile(r"(?i)(token|password|secret|otp)\w*\s*=.*new\s+Random\s*\("), {}),
]
PHP_RULES = [
    ("SEC002", re.compile(r"(mysqli?_query|->query)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)"), {}),
    ("SEC002", re.compile(r"(?i)[\"'](SELECT|INSERT|UPDATE|DELETE)\b[^\"']*[\"']\s*\.\s*\$"), {}),
    ("SEC001", re.compile(r"\beval\s*\(|\bassert\s*\(\s*\$_"), {}),
    ("SEC003", re.compile(r"\b(system|shell_exec|passthru|exec|popen|proc_open)\s*\([^;]*\$_(GET|POST|REQUEST)"), {}),
    ("SEC009", re.compile(r"\becho\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)"), {}),
    ("SEC005", re.compile(r"\bunserialize\s*\(\s*\$_"), {}),
    ("SEC015", re.compile(r"\b(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)"), {}),
    ("SEC006", re.compile(r"\b(md5|sha1)\s*\(\s*\$\w*pass"), {}),
]
CLEAR_HTTP = re.compile(r"""["']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|"""
                        r"""xmlns|example\.(com|org)|json-schema\.org)[\w.-]+""")
BANDIT_MAP = {"B102": "SEC001", "B307": "SEC001", "B608": "SEC002", "B602": "SEC003", "B605": "SEC003",
              "B604": "SEC003", "B301": "SEC005", "B302": "SEC005", "B506": "SEC005", "B303": "SEC006",
              "B324": "SEC006", "B501": "SEC007", "B201": "SEC008", "B701": "SEC009", "B703": "SEC009",
              "B104": "SEC012", "B306": "SEC014", "B110": "QLT005", "B112": "QLT005"}
CODE_LANGS = {"python", "javascript", "typescript", "java", "php", "ruby", "go", "csharp", "kotlin", "c", "cpp"}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def _is_test_path(path: str) -> bool:
    return bool(re.search(r"(^|/)(tests?|spec|__tests__|fixtures?|examples?|samples?)/|_test\.|\.test\.|test_", path))


class SecurityAgent(Agent):
    name = "Security Agent"
    category = "Security"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        findings: list[RawFinding] = []
        for f in codebase.files:
            findings += self._secrets(f)
            if f.language == "python" and f.tree is not None:
                findings += self._python(f)
            elif f.language in ("javascript", "typescript", "html"):
                findings += self.regex_rules(f, JS_RULES)
            elif f.language in ("java", "kotlin"):
                findings += self.regex_rules(f, JAVA_RULES)
            elif f.language == "php":
                findings += self.regex_rules(f, PHP_RULES)
            elif f.language == "docker":
                findings += self._dockerfile(f)
            if f.language in CODE_LANGS:
                for idx, text in enumerate(f.lines, 1):
                    if CLEAR_HTTP.search(text) and not text.strip().startswith(("#", "//", "*")):
                        findings.append(self.finding("SEC018", f, idx, confidence=0.6))
        findings += self._bandit(codebase)
        findings += self._semgrep(codebase)
        return findings

    # ---------------------------------------------------------------- secrets
    def _secrets(self, f: SourceFile) -> list[RawFinding]:
        out = []
        test_file = _is_test_path(f.path)
        for idx, text in enumerate(f.lines, 1):
            for label, pattern in SECRET_PATTERNS:
                m = pattern.search(text)
                if m:
                    out.append(self.finding("SEC017", f, idx, title=f"Hardcoded {label}",
                                            snippet=text.strip().replace(m.group(0), _mask(m.group(0)))[:300],
                                            confidence=0.6 if test_file else 0.95))
                    break
            else:
                if f.language == "python":
                    continue  # python handled precisely by AST
                pattern = CONFIG_SECRET if f.language in ("config", "yaml") else GENERIC_SECRET_ASSIGN
                m = pattern.search(text)
                if m:
                    value = m.groups()[-1]
                    if not PLACEHOLDER.search(value) and not value.startswith(("$", "process.env", "os.environ", "%")):
                        out.append(self.finding("SEC004", f, idx, snippet=text.strip().replace(value, _mask(value))[:300],
                                                confidence=0.5 if test_file else 0.8))
        return out

    # ---------------------------------------------------------------- python
    def _python(self, f: SourceFile) -> list[RawFinding]:
        out: list[RawFinding] = []
        tree = f.tree
        tainted = self._tainted_names(tree)
        flagged_sql_lines: set[int] = set()

        def is_tainted(node: ast.AST) -> bool:
            for sub in ast.walk(node):
                if isinstance(sub, ast.Name) and sub.id in tainted:
                    return True
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "request":
                    return True
            return False

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = call_name(node)
                short = name.split(".")[-1]
                args = node.args
                # SEC001 eval/exec
                if name in ("eval", "exec") and args and not isinstance(args[0], ast.Constant):
                    out.append(self.finding("SEC001", f, node.lineno, confidence=0.95 if is_tainted(args[0]) else 0.8,
                                            severity="Critical" if is_tainted(args[0]) else ""))
                # SEC002 SQL injection
                elif short in ("execute", "executemany", "executescript", "raw", "read_sql", "read_sql_query", "text") \
                        and args and (is_dynamic_string(args[0]) or (isinstance(args[0], ast.Name) and args[0].id in tainted)):
                    flagged_sql_lines.add(node.lineno)
                    out.append(self.finding("SEC002", f, node.lineno, confidence=0.95 if is_tainted(args[0]) else 0.85))
                # SEC003 command injection
                elif name in ("os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput"):
                    dyn = args and not isinstance(args[0], ast.Constant)
                    out.append(self.finding("SEC003", f, node.lineno, severity="" if dyn else "Low",
                                            confidence=0.9 if dyn and is_tainted(args[0]) else (0.75 if dyn else 0.5)))
                elif name.startswith("subprocess.") and isinstance(kwarg(node, "shell"), ast.Constant) \
                        and kwarg(node, "shell").value is True:
                    dyn = args and not isinstance(args[0], ast.Constant)
                    out.append(self.finding("SEC003", f, node.lineno, severity="" if dyn else "Low",
                                            confidence=0.9 if dyn else 0.5))
                # SEC005 deserialization
                elif name in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "marshal.loads",
                              "marshal.load", "yaml.unsafe_load", "jsonpickle.decode", "shelve.open", "dill.loads"):
                    out.append(self.finding("SEC005", f, node.lineno, confidence=0.85))
                elif name == "yaml.load":
                    loader = kwarg(node, "Loader") or (args[1] if len(args) > 1 else None)
                    loader_name = ast.unparse(loader) if loader is not None else ""
                    if "Safe" not in loader_name:
                        out.append(self.finding("SEC005", f, node.lineno, confidence=0.9))
                # SEC006 weak hash
                elif name in ("hashlib.md5", "hashlib.sha1", "md5", "sha1") or (
                        name == "hashlib.new" and args and isinstance(args[0], ast.Constant)
                        and str(args[0].value).lower() in ("md5", "sha1")):
                    ufs = kwarg(node, "usedforsecurity")
                    if not (isinstance(ufs, ast.Constant) and ufs.value is False):
                        out.append(self.finding("SEC006", f, node.lineno, confidence=0.75))
                # SEC014 mktemp
                elif name in ("tempfile.mktemp", "mktemp"):
                    out.append(self.finding("SEC014", f, node.lineno))
                # SEC009 XSS / SSTI
                elif short in ("Markup", "render_template_string", "mark_safe", "HTMLResponse") and args \
                        and not isinstance(args[0], ast.Constant):
                    out.append(self.finding("SEC009", f, node.lineno,
                                            confidence=0.9 if is_tainted(args[0]) else 0.65,
                                            severity="Critical" if short == "render_template_string" and is_tainted(args[0]) else ""))
                # SEC011 JWT
                elif name in ("jwt.decode",):
                    verify = kwarg(node, "verify")
                    options = kwarg(node, "options")
                    algs = kwarg(node, "algorithms")
                    src = ast.unparse(node)
                    if (isinstance(verify, ast.Constant) and verify.value is False) or \
                            (options is not None and "verify_signature" in ast.unparse(options) and "False" in ast.unparse(options)) or \
                            (algs is not None and "none" in ast.unparse(algs).lower()):
                        out.append(self.finding("SEC011", f, node.lineno, confidence=0.95, snippet=src[:300]))
                # SEC015 path traversal
                elif name in ("open", "send_file", "os.remove", "os.unlink", "shutil.rmtree", "os.path.join",
                              "pathlib.Path", "Path", "FileResponse") and args and any(is_tainted(a) for a in args):
                    out.append(self.finding("SEC015", f, node.lineno, confidence=0.75))
                # SEC016 SSRF
                elif name in ("requests.get", "requests.post", "requests.request", "httpx.get", "httpx.post",
                              "urllib.request.urlopen", "urlopen", "urllib.request.Request") and args and is_tainted(args[0]):
                    out.append(self.finding("SEC016", f, node.lineno, confidence=0.8))

                # keyword-based checks (any call)
                verify = kwarg(node, "verify")
                if isinstance(verify, ast.Constant) and verify.value is False and name != "jwt.decode":
                    out.append(self.finding("SEC007", f, node.lineno, confidence=0.95))
                debug = kwarg(node, "debug")
                if short == "run" and isinstance(debug, ast.Constant) and debug.value is True:
                    out.append(self.finding("SEC008", f, node.lineno, confidence=0.9))
                host = kwarg(node, "host")
                if short == "run" and isinstance(host, ast.Constant) and host.value == "0.0.0.0":
                    out.append(self.finding("SEC012", f, node.lineno, confidence=0.6))
                for kw in node.keywords:
                    if kw.arg in ("origins", "allow_origins", "resources") and "'*'" in ast.unparse(kw.value):
                        out.append(self.finding("SEC013", f, node.lineno, confidence=0.85))
                    if kw.arg and SECRET_NAME.search(kw.arg) and isinstance(kw.value, ast.Constant) \
                            and isinstance(kw.value.value, str) and not PLACEHOLDER.search(kw.value.value):
                        out.append(self._secret_finding(f, node.lineno, kw.value.value))

            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                for target in targets:
                    tname = target.id if isinstance(target, ast.Name) else (
                        target.attr if isinstance(target, ast.Attribute) else (
                            target.slice.value if isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant)
                            and isinstance(target.slice.value, str) else ""))
                    if not tname or value is None:
                        continue
                    # hardcoded secret
                    if SECRET_NAME.search(tname) and isinstance(value, ast.Constant) and isinstance(value.value, str) \
                            and not PLACEHOLDER.search(value.value) and len(value.value) >= 4:
                        out.append(self._secret_finding(f, node.lineno, value.value))
                    # debug flags
                    if tname in ("DEBUG", "debug") and isinstance(value, ast.Constant) and value.value is True:
                        out.append(self.finding("SEC008", f, node.lineno, confidence=0.6))
                    if tname in ("CORS_ORIGIN_ALLOW_ALL", "CORS_ALLOW_ALL_ORIGINS") and isinstance(value, ast.Constant) and value.value is True:
                        out.append(self.finding("SEC013", f, node.lineno, confidence=0.9))
                    # insecure randomness for sensitive values
                    if SENSITIVE_NAME.search(tname) and any(
                            isinstance(c, ast.Call) and call_name(c) in RANDOM_FUNCS for c in ast.walk(value)):
                        out.append(self.finding("SEC010", f, node.lineno, confidence=0.85))
                # SQL string built dynamically and stored in a variable
                if value is not None and is_dynamic_string(value) and node.lineno not in flagged_sql_lines:
                    literal = " ".join(c.value for c in ast.walk(value) if isinstance(c, ast.Constant) and isinstance(c.value, str))
                    if SQL_TEXT.search(literal):
                        flagged_sql_lines.add(node.lineno)
                        out.append(self.finding("SEC002", f, node.lineno, confidence=0.8))

            elif isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str) and SECRET_NAME.search(k.value) \
                            and isinstance(v, ast.Constant) and isinstance(v.value, str) \
                            and not PLACEHOLDER.search(v.value) and len(v.value) >= 4:
                        out.append(self._secret_finding(f, v.lineno, v.value))

            elif isinstance(node, FUNC_TYPES) and SENSITIVE_NAME.search(node.name):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call) and call_name(sub) in RANDOM_FUNCS:
                        out.append(self.finding("SEC010", f, sub.lineno, confidence=0.75))
                        break

            elif isinstance(node, ast.Assert):
                text = ast.unparse(node.test)
                if re.search(r"(is_admin|is_authenticated|authorized|permission|is_staff|role|logged_in|is_superuser)", text):
                    out.append(self.finding("SEC021", f, node.lineno, confidence=0.7))
        return out

    def _secret_finding(self, f: SourceFile, line: int, value: str) -> RawFinding:
        snippet = line_at(f, line).replace(value, _mask(value))
        return self.finding("SEC004", f, line, snippet=snippet, confidence=0.5 if _is_test_path(f.path) else 0.85)

    @staticmethod
    def _tainted_names(tree: ast.AST) -> set[str]:
        """Very small taint analysis: names assigned (directly or transitively) from request data."""
        tainted: set[str] = set()
        assigns = [n for n in ast.walk(tree) if isinstance(n, ast.Assign)]
        for _ in range(3):  # propagate a few hops
            for n in assigns:
                src = ast.unparse(n.value)
                if TAINT_SOURCES.search(src) or any(
                        isinstance(s, ast.Name) and s.id in tainted for s in ast.walk(n.value)):
                    for t in n.targets:
                        for s in ast.walk(t):
                            if isinstance(s, ast.Name):
                                tainted.add(s.id)
        return tainted

    # ---------------------------------------------------------------- docker
    def _dockerfile(self, f: SourceFile) -> list[RawFinding]:
        out = []
        has_user = any(l.strip().upper().startswith("USER ") and "root" not in l.lower() for l in f.lines)
        for idx, text in enumerate(f.lines, 1):
            m = re.match(r"\s*FROM\s+(\S+)", text, re.I)
            if m:
                image = m.group(1)
                if image.lower() != "scratch" and "@sha256" not in image and (":" not in image or image.endswith(":latest")):
                    out.append(self.finding("SEC020", f, idx))
        if not has_user and f.lines:
            out.append(self.finding("SEC019", f, 1, confidence=0.8))
        return out

    # ---------------------------------------------------------------- external tools
    def _bandit(self, codebase: CodeBase) -> list[RawFinding]:
        if not tool_available("bandit") or not any(f.language == "python" for f in codebase.files):
            return []
        skip = "B101,B404,B403,B405,B410,B311,B105,B106,B107,B603,B607"  # covered natively or noisy
        try:
            proc = subprocess.run([tool_path("bandit"), "-r", str(codebase.root), "-f", "json", "-q", "-s", skip,
                                   "-x", ",".join(f"*/{d}/*" for d in ("node_modules", "venv", ".venv"))],
                                  capture_output=True, text=True, timeout=180)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return []
        sev = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}
        conf = {"HIGH": 0.9, "MEDIUM": 0.7, "LOW": 0.5}
        out = []
        by_path = {f.path: f for f in codebase.files}
        for r in data.get("results", []):
            rel = os.path.relpath(r["filename"], codebase.root).replace(os.sep, "/")
            sf = by_path.get(rel)
            if sf is None:
                continue
            cwe = r.get("issue_cwe", {}).get("id")
            mapped = BANDIT_MAP.get(r["test_id"])
            if mapped:  # same weakness as a native rule -> merged by the AI Reviewer's dedupe step
                out.append(RawFinding(agent=self.name, category="Quality" if mapped.startswith("QLT") else self.category,
                                      rule_id=mapped, file=rel, line=r.get("line_number", 0),
                                      snippet=line_at(sf, r.get("line_number", 0)), confidence=conf.get(r["issue_confidence"], 0.6),
                                      sources=["Bandit"]))
                continue
            out.append(RawFinding(agent=self.name, category=self.category, rule_id="SEC022", file=rel,
                                  line=r.get("line_number", 0), snippet=line_at(sf, r.get("line_number", 0)),
                                  title=f"{r['test_id']}: {r['issue_text']}", severity=sev.get(r["issue_severity"], "Medium"),
                                  confidence=conf.get(r["issue_confidence"], 0.6),
                                  description=r["issue_text"], remediation=f"See {r.get('more_info', 'Bandit docs')}",
                                  cwe=f"CWE-{cwe}" if cwe else "", sources=["Bandit"]))
        return out

    def _semgrep(self, codebase: CodeBase) -> list[RawFinding]:
        config = os.getenv("SEMGREP_CONFIG", "")
        if not config or not tool_available("semgrep"):
            return []
        try:
            proc = subprocess.run([tool_path("semgrep"), "--config", config, "--json", "--quiet", str(codebase.root)],
                                  capture_output=True, text=True, timeout=600)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, json.JSONDecodeError):
            return []
        sev = {"ERROR": "High", "WARNING": "Medium", "INFO": "Low"}
        out = []
        for r in data.get("results", []):
            rel = os.path.relpath(r["path"], codebase.root).replace(os.sep, "/")
            extra = r.get("extra", {})
            cwe = (extra.get("metadata", {}).get("cwe") or [""])
            out.append(RawFinding(agent=self.name, category=self.category, rule_id="SEC023", file=rel,
                                  line=r.get("start", {}).get("line", 0), snippet=(extra.get("lines") or "").strip()[:300],
                                  title=r.get("check_id", "semgrep").split(".")[-1], severity=sev.get(extra.get("severity"), "Medium"),
                                  description=extra.get("message", ""), confidence=0.8,
                                  cwe=(cwe[0] if isinstance(cwe, list) else cwe).split(":")[0], sources=["Semgrep"]))
        return out
