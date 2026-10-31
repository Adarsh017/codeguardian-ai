"""Performance Agent: inefficient loops, N+1 I/O, expensive operations and blocking calls."""
import ast
import re

from ..services.preprocessing import CodeBase, SourceFile
from .base import FUNC_TYPES, Agent, RawFinding, call_name, inside_loop, parents

IO_CALLS = re.compile(r"(^|\.)(execute|executemany|query|fetchone|fetchall|commit|filter|get|post|put|delete|"
                      r"request|urlopen|open|connect|read_csv|read_sql|load|save|find_one|find|insert_one|"
                      r"update_one|send|recv|sleep)$")
IO_PREFIXES = ("requests.", "httpx.", "urllib.", "session.", "cursor.", "conn.", "connection.", "db.", "client.",
               "s3.", "boto3.", "redis.", "collection.", "Model.objects", "objects.", "pd.")
LOOPS = (ast.For, ast.While, ast.AsyncFor)

JS_LOOP_START = re.compile(r"^\s*(for|while)\s*\(|\.forEach\s*\(|\.map\s*\(")
JS_RULES_IN_LOOP = [
    ("PRF008", re.compile(r"\bawait\s+")),
    ("PRF003", re.compile(r"document\.(querySelector|getElementById|getElementsBy\w+)\s*\(|\b(fetch|axios\.\w+)\s*\(")),
    ("PRF009", re.compile(r"JSON\.parse\s*\(\s*JSON\.stringify|structuredClone\s*\(")),
]


class PerformanceAgent(Agent):
    name = "Performance Agent"
    category = "Performance"

    def analyze(self, codebase: CodeBase) -> list[RawFinding]:
        out: list[RawFinding] = []
        for f in codebase.files:
            if f.language == "python" and f.tree is not None:
                out += self._python(f)
            elif f.language in ("javascript", "typescript"):
                out += self._javascript(f)
        return out

    def _python(self, f: SourceFile) -> list[RawFinding]:
        out = []
        pmap = parents(f.tree)
        list_vars = {t.id for n in ast.walk(f.tree) if isinstance(n, ast.Assign) and isinstance(n.value, ast.List)
                     for t in n.targets if isinstance(t, ast.Name)}
        str_vars = {t.id for n in ast.walk(f.tree) if isinstance(n, ast.Assign) and isinstance(n.value, (ast.Constant, ast.JoinedStr))
                    and isinstance(getattr(n.value, "value", ""), str) for t in n.targets if isinstance(t, ast.Name)}
        reported_nested: set[int] = set()
        async_funcs = {id(n) for n in ast.walk(f.tree) if isinstance(n, ast.AsyncFunctionDef)}

        for node in ast.walk(f.tree):
            if isinstance(node, LOOPS):
                depth, cur = 1, pmap.get(node)
                outer = node
                while cur is not None and not isinstance(cur, FUNC_TYPES):
                    if isinstance(cur, LOOPS):
                        depth += 1
                        outer = cur
                    cur = pmap.get(cur)
                if depth >= 3 and outer.lineno not in reported_nested:
                    reported_nested.add(outer.lineno)
                    out.append(self.finding("PRF001", f, outer.lineno, title=f"{depth} nested loops (O(n^{depth}))"))
                if isinstance(node, ast.For) and isinstance(node.iter, ast.Call) and getattr(node.iter.func, "id", "") == "range" \
                        and len(node.iter.args) == 1 and isinstance(node.iter.args[0], ast.Call) \
                        and getattr(node.iter.args[0].func, "id", "") == "len":
                    out.append(self.finding("PRF007", f, node.lineno))
            elif isinstance(node, ast.AugAssign) and isinstance(node.op, ast.Add) and isinstance(node.target, ast.Name) \
                    and inside_loop(node, pmap) and (node.target.id in str_vars or isinstance(node.value, ast.JoinedStr)
                                                      or (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str))):
                out.append(self.finding("PRF002", f, node.lineno))
            elif isinstance(node, ast.Call):
                name = call_name(node)
                in_loop = inside_loop(node, pmap)
                if in_loop and (name.startswith(IO_PREFIXES) or name == "open" or
                                (IO_CALLS.search(name) and "." in name and name.split(".")[0] in
                                 ("cursor", "cur", "conn", "db", "session", "requests", "httpx", "client", "collection"))):
                    if not name.endswith(("sleep",)):
                        out.append(self.finding("PRF003", f, node.lineno, title=f"'{name}()' called inside a loop"))
                if in_loop and name in ("re.compile", "re.match", "re.search", "re.findall", "re.sub", "re.fullmatch") \
                        and node.args and isinstance(node.args[0], ast.Constant) and name == "re.compile":
                    out.append(self.finding("PRF005", f, node.lineno))
                if in_loop and name in ("copy.deepcopy", "deepcopy"):
                    out.append(self.finding("PRF009", f, node.lineno))
                if name == "time.sleep":
                    cur = pmap.get(node)
                    while cur is not None and not isinstance(cur, FUNC_TYPES):
                        cur = pmap.get(cur)
                    if cur is not None and id(cur) in async_funcs:
                        out.append(self.finding("PRF006", f, node.lineno, severity="High",
                                                title="time.sleep() blocks the event loop in async function"))
                    elif in_loop:
                        out.append(self.finding("PRF006", f, node.lineno, confidence=0.5))
                if name in ("readlines",) or (name.endswith(".readlines") or name.endswith(".read")) and not node.args \
                        and "open(" in ast.unparse(node):
                    out.append(self.finding("PRF011", f, node.lineno, confidence=0.5))
            elif isinstance(node, ast.Subscript) and isinstance(node.value, ast.Call) \
                    and getattr(node.value.func, "id", "") == "sorted" and isinstance(node.slice, ast.Constant) \
                    and node.slice.value in (0, -1):
                out.append(self.finding("PRF010", f, node.lineno))
            elif isinstance(node, ast.Compare) and any(isinstance(op, (ast.In, ast.NotIn)) for op in node.ops) \
                    and inside_loop(node, pmap):
                comp = node.comparators[0]
                if isinstance(comp, ast.List) and len(comp.elts) > 3 or (isinstance(comp, ast.Name) and comp.id in list_vars):
                    out.append(self.finding("PRF004", f, node.lineno))
        return out

    def _javascript(self, f: SourceFile) -> list[RawFinding]:
        out = []
        depth_stack: list[int] = []  # brace depth at which each loop started
        depth = 0
        loop_depths: list[int] = []
        for idx, text in enumerate(f.lines, 1):
            stripped = text.strip()
            if stripped.startswith(("//", "*", "/*")):
                continue
            if JS_LOOP_START.search(text):
                loop_depths.append(depth)
                if len(loop_depths) >= 3:
                    out.append(self.finding("PRF001", f, idx, title=f"{len(loop_depths)} nested loops"))
            elif loop_depths:
                for rule_id, pattern in JS_RULES_IN_LOOP:
                    if pattern.search(text) and not (rule_id == "PRF008" and "Promise.all" in text):
                        out.append(self.finding(rule_id, f, idx))
            depth += text.count("{") - text.count("}")
            while loop_depths and depth <= loop_depths[-1] and "}" in text:
                loop_depths.pop()
            del depth_stack[:]
        return out
