"""Common types for analysis agents."""
import ast
import re
import shutil
import sys
from pathlib import Path
from dataclasses import asdict, dataclass, field

from ..services.preprocessing import CodeBase, SourceFile
from .rules import rule


@dataclass
class RawFinding:
    agent: str
    category: str
    rule_id: str
    file: str
    line: int
    snippet: str = ""
    title: str = ""
    severity: str = ""
    confidence: float = 0.8
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    explanation: str = ""
    fixed_code: str = ""
    ai_reviewed: bool = False
    sources: list[str] = field(default_factory=list)  # agents/tools that reported it

    def __post_init__(self):
        meta = rule(self.rule_id)
        self.title = self.title or meta["title"]
        self.severity = self.severity or meta["severity"]
        self.description = self.description or meta["description"]
        self.remediation = self.remediation or meta["remediation"]
        self.cwe = self.cwe or meta["cwe"]
        self.owasp = self.owasp or meta["owasp"]
        if not self.sources:
            self.sources = [self.agent]

    def to_dict(self) -> dict:
        return asdict(self)


class Agent:
    name = "agent"
    category = "General"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        raise NotImplementedError

    # helpers --------------------------------------------------------------
    def finding(self, rule_id: str, f: SourceFile, line: int, **kw) -> RawFinding:
        snippet = kw.pop("snippet", None)
        if snippet is None:
            snippet = line_at(f, line)
        return RawFinding(agent=self.name, category=self.category, rule_id=rule_id, file=f.path,
                          line=line, snippet=snippet, **kw)

    def regex_rules(self, f: SourceFile, rules: list[tuple[str, re.Pattern, dict]]) -> list[RawFinding]:
        """Apply (rule_id, compiled_regex, overrides) line by line, skipping comments."""
        out = []
        for idx, text in enumerate(f.lines, start=1):
            stripped = text.strip()
            if stripped.startswith(("//", "#", "*", "/*", "<!--")):
                continue
            for rule_id, pattern, overrides in rules:
                if pattern.search(text):
                    out.append(self.finding(rule_id, f, idx, **overrides))
        return out


def line_at(f: SourceFile, line: int) -> str:
    lines = f.lines
    if 1 <= line <= len(lines):
        return lines[line - 1].strip()[:300]
    return ""


def context(f_code: str, line: int, radius: int = 4) -> str:
    lines = f_code.splitlines()
    start, end = max(0, line - 1 - radius), min(len(lines), line + radius)
    return "\n".join(f"{i + 1:>4} | {lines[i]}" for i in range(start, end))


def call_name(node: ast.Call) -> str:
    """Return dotted name of a call target, e.g. 'os.system', 'cursor.execute', 'eval'."""
    parts = []
    target = node.func
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    elif isinstance(target, ast.Call):
        parts.append(call_name(target) + "()")
    return ".".join(reversed(parts))


def kwarg(node: ast.Call, name: str):
    for kw in node.keywords:
        if kw.arg == name:
            return kw.value
    return None


def is_dynamic_string(node: ast.AST) -> bool:
    """True if node builds a string from runtime values (f-string, %, +, .format)."""
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return not (isinstance(node.left, ast.Constant) and isinstance(node.right, ast.Constant))
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return False


def tool_path(name: str) -> str | None:
    """Find a CLI tool, checking the active virtualenv's bin/Scripts folder first.

    When the app is started from an IDE (e.g. the VS Code debugger) the venv is often not on PATH,
    so tools installed by `pip install -r requirements.txt` would otherwise be missed."""
    bin_dir = Path(sys.executable).parent
    for candidate in (bin_dir / name, bin_dir / f"{name}.exe"):
        if candidate.is_file():
            return str(candidate)
    return shutil.which(name)


def tool_available(name: str) -> bool:
    return tool_path(name) is not None


def parents(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    mapping = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            mapping[child] = node
    return mapping


LOOP_TYPES = (ast.For, ast.While, ast.AsyncFor, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
FUNC_TYPES = (ast.FunctionDef, ast.AsyncFunctionDef)


def inside_loop(node: ast.AST, parent_map: dict) -> bool:
    """True if node executes repeatedly inside a loop body (the loop's own iterable runs only once)."""
    child, cur = node, parent_map.get(node)
    while cur is not None and not isinstance(cur, FUNC_TYPES):
        if isinstance(cur, (ast.For, ast.AsyncFor)) and child is not cur.iter and child is not cur.target:
            return True
        if isinstance(cur, ast.While):
            return True
        child, cur = cur, parent_map.get(cur)
    return False
