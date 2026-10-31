"""Code Quality Agent: complexity, size, maintainability, duplication and code smells."""
import ast
import hashlib
import re
from collections import defaultdict

from ..services.preprocessing import CodeBase, SourceFile
from .base import FUNC_TYPES, Agent, RawFinding

try:
    from pyflakes import checker as pyflakes_checker
    from pyflakes import messages as pyflakes_messages
except ImportError:  # pragma: no cover
    pyflakes_checker = None

MAX_FUNC_LINES = 60
MAX_COMPLEXITY = 10
MAX_PARAMS = 6
MAX_NESTING = 4
MAX_FILE_LINES = 500
MAX_LINE_LEN = 120
DUP_WINDOW = 6

JS_RULES = [
    ("QLT012", re.compile(r"\bconsole\.(log|debug)\s*\("), {}),
    ("QLT013", re.compile(r"^\s*var\s+\w"), {}),
    ("QLT014", re.compile(r"[^=!<>]==[^=]|!=[^=]"), {"confidence": 0.7}),
]
TODO_RE = re.compile(r"(#|//|/\*|\*)\s*(TODO|FIXME|HACK|XXX)\b", re.I)
COMMENT_OR_TRIVIAL = re.compile(r"^(#|//|/\*|\*|\}|\{|\)|\]|import\b|from\b|else:?|try:|finally:|pass|return;?|break;?|"
                                r"\"\"\"|'''|@|end|</?\w+>)")


def cyclomatic_complexity(func: ast.AST) -> int:
    complexity = 1
    stack = list(ast.iter_child_nodes(func))
    while stack:
        node = stack.pop()
        if isinstance(node, FUNC_TYPES + (ast.Lambda, ast.ClassDef)):
            continue  # nested scopes are measured separately
        if isinstance(node, (ast.If, ast.For, ast.While, ast.AsyncFor, ast.IfExp, ast.ExceptHandler,
                             ast.Assert, ast.comprehension)):
            complexity += 1
            if isinstance(node, ast.comprehension):
                complexity += len(node.ifs)
        elif isinstance(node, ast.BoolOp):
            complexity += len(node.values) - 1
        elif isinstance(node, ast.match_case):
            complexity += 1
        stack.extend(ast.iter_child_nodes(node))
    return complexity


BLOCKS = (ast.If, ast.For, ast.While, ast.With, ast.Try, ast.AsyncFor, ast.AsyncWith)


def max_nesting(node: ast.AST, depth: int = 0) -> tuple[int, int]:
    """Return (max_depth, line_of_deepest_block)."""
    best = (depth, getattr(node, "lineno", 0))
    for child in ast.iter_child_nodes(node):
        if isinstance(child, FUNC_TYPES + (ast.ClassDef,)):
            continue
        d = depth + 1 if isinstance(child, BLOCKS) else depth
        result = max_nesting(child, d)
        if result[0] > best[0]:
            best = result
    return best


class QualityAgent(Agent):
    name = "Code Quality Agent"
    category = "Quality"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        out: list[RawFinding] = []
        for f in codebase.files:
            if f.language in ("config", "json", "yaml", "manifest", "xml", "html", "docker"):
                continue
            out += self._generic(f)
            if f.language == "python" and f.tree is not None:
                out += self._python(f)
            elif f.language in ("javascript", "typescript"):
                out += self.regex_rules(f, JS_RULES)
        out += self._duplicates(codebase)
        return out

    def _generic(self, f: SourceFile) -> list[RawFinding]:
        out = []
        lines = f.lines
        if len(lines) > MAX_FILE_LINES:
            out.append(self.finding("QLT007", f, 1, snippet=f"{len(lines)} lines",
                                    title=f"Large source file ({len(lines)} lines)"))
        long_lines = [i for i, l in enumerate(lines, 1) if len(l) > MAX_LINE_LEN]
        if len(long_lines) >= 5:
            out.append(self.finding("QLT009", f, long_lines[0],
                                    title=f"{len(long_lines)} lines exceed {MAX_LINE_LEN} characters"))
        for idx, text in enumerate(lines, 1):
            if TODO_RE.search(text):
                out.append(self.finding("QLT010", f, idx))
        return out

    def _python(self, f: SourceFile) -> list[RawFinding]:
        out = []
        for node in ast.walk(f.tree):
            if isinstance(node, FUNC_TYPES):
                length = (node.end_lineno or node.lineno) - node.lineno + 1
                if length > MAX_FUNC_LINES:
                    out.append(self.finding("QLT001", f, node.lineno,
                                            title=f"Function '{node.name}' is too long ({length} lines)"))
                cc = cyclomatic_complexity(node)
                if cc > MAX_COMPLEXITY:
                    out.append(self.finding("QLT002", f, node.lineno,
                                            title=f"High cyclomatic complexity in '{node.name}' ({cc})",
                                            severity="High" if cc > 25 else ""))
                params = [a for a in node.args.args + node.args.kwonlyargs if a.arg not in ("self", "cls")]
                if len(params) > MAX_PARAMS:
                    out.append(self.finding("QLT003", f, node.lineno,
                                            title=f"'{node.name}' has {len(params)} parameters"))
                depth, line = max_nesting(node)
                if depth > MAX_NESTING:
                    out.append(self.finding("QLT004", f, line,
                                            title=f"Code nested {depth} levels deep in '{node.name}'"))
                for default in node.args.defaults + node.args.kw_defaults:
                    if isinstance(default, (ast.List, ast.Dict, ast.Set)) or (
                            isinstance(default, ast.Call) and getattr(default.func, "id", "") in ("list", "dict", "set")):
                        out.append(self.finding("QLT006", f, default.lineno))
            elif isinstance(node, ast.ExceptHandler):
                broad = node.type is None or (isinstance(node.type, ast.Name) and node.type.id in ("Exception", "BaseException"))
                swallow = all(isinstance(s, (ast.Pass, ast.Continue)) or
                              (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)) for s in node.body)
                if node.type is None or (broad and swallow):
                    out.append(self.finding("QLT005", f, node.lineno,
                                            title="Bare except clause" if node.type is None else "Exception silently swallowed"))
        # unused imports via pyflakes
        if pyflakes_checker is not None and not f.path.endswith("__init__.py"):
            try:
                chk = pyflakes_checker.Checker(f.tree, filename=f.path)
                for msg in chk.messages:
                    if isinstance(msg, pyflakes_messages.UnusedImport):
                        out.append(self.finding("QLT011", f, msg.lineno, title=f"Unused import {msg.message_args[0]}"))
            except Exception:
                pass
        return out

    def _duplicates(self, codebase: CodeBase) -> list[RawFinding]:
        index: dict[str, list[tuple[SourceFile, int]]] = defaultdict(list)
        for f in codebase.files:
            if f.language not in ("python", "javascript", "typescript", "java", "php", "go", "csharp", "ruby", "c", "cpp"):
                continue
            meaningful = [(i, re.sub(r"\s+", " ", l.strip())) for i, l in enumerate(f.lines, 1)]
            meaningful = [(i, l) for i, l in meaningful if len(l) > 8 and not COMMENT_OR_TRIVIAL.match(l)]
            for k in range(len(meaningful) - DUP_WINDOW + 1):
                window = meaningful[k:k + DUP_WINDOW]
                digest = hashlib.md5("\n".join(l for _, l in window).encode(), usedforsecurity=False).hexdigest()
                index[digest].append((f, window[0][0]))
        out, reported = [], set()
        for locations in index.values():
            unique = {(f.path, line): (f, line) for f, line in locations}
            if len(unique) < 2:
                continue
            ordered = sorted(unique.values(), key=lambda x: (x[0].path, x[1]))
            first_f, first_line = ordered[0]
            for f, line in ordered[1:]:
                # suppress overlapping windows of the same duplicated region
                key = (f.path, line // (DUP_WINDOW * 2), first_f.path, first_line // (DUP_WINDOW * 2))
                if key in reported or any((f.path, l) in reported for l in range(line - DUP_WINDOW, line)):
                    continue
                reported.add(key)
                reported.add((f.path, line))
                out.append(self.finding("QLT008", f, line,
                                        description=f"This block duplicates code at {first_f.path}:{first_line}. "
                                                    "Fixes must be applied to every copy.",
                                        title=f"Duplicated code (also at {first_f.path}:{first_line})"))
        return out
