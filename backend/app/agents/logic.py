"""Logic Agent: logical errors, incorrect conditions, dead code and likely bugs."""
import ast
import builtins
import re

from ..services.preprocessing import CodeBase, SourceFile
from .base import FUNC_TYPES, Agent, RawFinding

try:
    from pyflakes import checker as pyflakes_checker
    from pyflakes import messages as pyflakes_messages
except ImportError:  # pragma: no cover
    pyflakes_checker = None

TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)
SHADOWABLE = {"list", "dict", "str", "int", "float", "set", "tuple", "id", "type", "input", "len", "max", "min",
              "sum", "file", "filter", "map", "object", "open", "range", "hash", "format", "bytes", "all", "any",
              "iter", "next", "zip", "sorted", "compile", "vars", "dir"}
EXC_HIERARCHY = {"Exception": {"ValueError", "TypeError", "KeyError", "IndexError", "OSError", "IOError",
                               "RuntimeError", "AttributeError", "LookupError", "ZeroDivisionError",
                               "FileNotFoundError", "PermissionError", "ConnectionError", "TimeoutError",
                               "NotImplementedError", "ImportError", "ModuleNotFoundError", "UnicodeDecodeError"},
                 "LookupError": {"KeyError", "IndexError"},
                 "OSError": {"FileNotFoundError", "PermissionError", "ConnectionError", "TimeoutError", "IsADirectoryError"}}
EXC_HIERARCHY["BaseException"] = EXC_HIERARCHY["Exception"] | {"Exception", "KeyboardInterrupt", "SystemExit"}

JS_RULES = [
    ("LOG016", re.compile(r"\b(if|while)\s*\(\s*[\w.\[\]]+\s=\s[^=]"), {}),
    ("LOG004", re.compile(r"\b(if|while)\s*\(\s*(false|0)\s*\)"), {}),
]


class LogicAgent(Agent):
    name = "Logic Agent"
    category = "Logic"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        out: list[RawFinding] = []
        for f in codebase.files:
            if f.language == "python" and f.tree is not None:
                out += self._python(f)
                out += self._pyflakes(f)
            elif f.language in ("javascript", "typescript"):
                out += self.regex_rules(f, JS_RULES)
                out += self._js_unreachable(f)
        return out

    # ------------------------------------------------------------------ python
    def _python(self, f: SourceFile) -> list[RawFinding]:
        out = []
        for node in ast.walk(f.tree):
            # unreachable code in any statement list
            for field in ("body", "orelse", "finalbody"):
                stmts = getattr(node, field, None)
                if isinstance(stmts, list) and stmts and isinstance(stmts[0], ast.stmt):
                    for i, stmt in enumerate(stmts[:-1]):
                        if isinstance(stmt, TERMINATORS):
                            out.append(self.finding("LOG001", f, stmts[i + 1].lineno))
                            break
            if isinstance(node, ast.Compare):
                for op, comp in zip(node.ops, node.comparators):
                    if isinstance(op, (ast.Eq, ast.NotEq)) and isinstance(comp, ast.Constant) and comp.value is None:
                        out.append(self.finding("LOG002", f, node.lineno))
                    if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(comp, ast.Constant) \
                            and comp.value is not None and not isinstance(comp.value, bool) and comp.value is not ...:
                        out.append(self.finding("LOG003", f, node.lineno))
                if len(node.ops) == 1 and isinstance(node.ops[0], (ast.Eq, ast.NotEq, ast.Lt, ast.Gt, ast.LtE, ast.GtE, ast.Is)) \
                        and ast.dump(node.left) == ast.dump(node.comparators[0]) and not isinstance(node.left, ast.Call):
                    out.append(self.finding("LOG005", f, node.lineno))
            elif isinstance(node, (ast.If, ast.While)):
                test = node.test
                if isinstance(test, ast.Constant) and not (isinstance(node, ast.While) and test.value is True):
                    out.append(self.finding("LOG004", f, node.lineno, title=f"Condition is always {bool(test.value)}"))
                if isinstance(node, ast.While) and isinstance(test, ast.Constant) and test.value is True:
                    if not any(isinstance(s, (ast.Break, ast.Return, ast.Raise)) or
                               (isinstance(s, ast.Call) and getattr(s.func, "attr", getattr(s.func, "id", "")) in ("exit", "_exit"))
                               for s in ast.walk(node)):
                        out.append(self.finding("LOG017", f, node.lineno, confidence=0.6))
                if isinstance(node, ast.If):
                    out += self._if_chain(f, node)
            elif isinstance(node, ast.Dict):
                seen = {}
                for k in node.keys:
                    if isinstance(k, ast.Constant):
                        if k.value in seen:
                            out.append(self.finding("LOG006", f, k.lineno, title=f"Duplicate dictionary key {k.value!r}"))
                        seen[k.value] = True
            elif isinstance(node, FUNC_TYPES):
                out += self._returns(f, node)
                for arg in node.args.args + node.args.kwonlyargs:
                    if arg.arg in SHADOWABLE:
                        out.append(self.finding("LOG013", f, node.lineno, title=f"Parameter '{arg.arg}' shadows a built-in"))
            elif isinstance(node, ast.Try):
                for stmt in node.finalbody:
                    for sub in ast.walk(stmt):
                        if isinstance(sub, (ast.Return, ast.Break, ast.Continue)):
                            out.append(self.finding("LOG010", f, sub.lineno))
                caught: set[str] = set()
                for handler in node.handlers:
                    names = []
                    if isinstance(handler.type, ast.Name):
                        names = [handler.type.id]
                    elif isinstance(handler.type, ast.Tuple):
                        names = [e.id for e in handler.type.elts if isinstance(e, ast.Name)]
                    for n in names:
                        if any(n in EXC_HIERARCHY.get(c, set()) for c in caught):
                            out.append(self.finding("LOG011", f, handler.lineno,
                                                    title=f"'except {n}' is unreachable (caught by an earlier clause)"))
                    caught.update(names)
            elif isinstance(node, ast.Call) and getattr(node.func, "id", "") == "range" and node.args:
                arg = node.args[-1] if len(node.args) <= 2 else node.args[1]
                if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add) and isinstance(arg.left, ast.Call) \
                        and getattr(arg.left.func, "id", "") == "len" and isinstance(arg.right, ast.Constant) and arg.right.value == 1:
                    out.append(self.finding("LOG012", f, node.lineno, confidence=0.6))
            elif isinstance(node, ast.Assign):
                for t in node.targets:
                    if isinstance(t, ast.Name) and t.id in SHADOWABLE:
                        out.append(self.finding("LOG013", f, node.lineno, title=f"Variable '{t.id}' shadows a built-in"))
        return out

    def _if_chain(self, f: SourceFile, node: ast.If) -> list[RawFinding]:
        out = []
        # identical branches
        if node.orelse and not (len(node.orelse) == 1 and isinstance(node.orelse[0], ast.If)):
            if [ast.dump(s) for s in node.body] == [ast.dump(s) for s in node.orelse]:
                out.append(self.finding("LOG008", f, node.lineno))
        # duplicate conditions in if/elif chain (only examine from the head of a chain)
        conditions = []
        cur = node
        while isinstance(cur, ast.If):
            dumped = ast.dump(cur.test)
            if dumped in conditions:
                out.append(self.finding("LOG007", f, cur.lineno))
            conditions.append(dumped)
            cur = cur.orelse[0] if len(cur.orelse) == 1 and isinstance(cur.orelse[0], ast.If) else None
        return out

    def _returns(self, f: SourceFile, func: ast.AST) -> list[RawFinding]:
        returns = []
        stack = list(func.body)
        while stack:
            n = stack.pop()
            if isinstance(n, FUNC_TYPES + (ast.ClassDef, ast.Lambda)):
                continue
            if isinstance(n, ast.Return):
                returns.append(n)
            stack.extend(ast.iter_child_nodes(n))
        with_value = [r for r in returns if r.value is not None and not (isinstance(r.value, ast.Constant) and r.value.value is None)]
        bare = [r for r in returns if r.value is None]
        if with_value and bare:
            return [self.finding("LOG009", f, bare[0].lineno, title=f"'{func.name}' mixes 'return value' and bare 'return'")]
        return []

    def _pyflakes(self, f: SourceFile) -> list[RawFinding]:
        if pyflakes_checker is None:
            return []
        out = []
        try:
            chk = pyflakes_checker.Checker(f.tree, filename=f.path)
        except Exception:
            return []
        builtin_names = set(dir(builtins))
        for msg in chk.messages:
            if isinstance(msg, pyflakes_messages.UndefinedName) and msg.message_args[0] not in builtin_names:
                out.append(self.finding("LOG014", f, msg.lineno, title=f"Undefined name '{msg.message_args[0]}'"))
            elif isinstance(msg, pyflakes_messages.UnusedVariable):
                out.append(self.finding("LOG015", f, msg.lineno, title=f"Local variable '{msg.message_args[0]}' is never used"))
        return out

    # ------------------------------------------------------------------ javascript
    def _js_unreachable(self, f: SourceFile) -> list[RawFinding]:
        out = []
        lines = f.lines
        for i, text in enumerate(lines[:-1]):
            s = text.strip()
            if re.match(r"^(return\b[^{(]*;|throw\b.*;|break;|continue;)$", s):
                nxt = lines[i + 1].strip()
                if nxt and not nxt.startswith(("}", "case ", "default", "//", "/*", "*")) and \
                        (len(text) - len(text.lstrip())) == (len(lines[i + 1]) - len(lines[i + 1].lstrip())):
                    out.append(self.finding("LOG001", f, i + 2, confidence=0.7))
        return out
