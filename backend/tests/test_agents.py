"""Unit tests for the analysis agents and the orchestration pipeline (run: pytest -q)."""
from pathlib import Path

from app.agents.dependency import DependencyAgent  # noqa: E402
from app.agents.logic import LogicAgent  # noqa: E402
from app.agents.performance import PerformanceAgent  # noqa: E402
from app.agents.quality import QualityAgent  # noqa: E402
from app.agents.remediation import rule_based_fix  # noqa: E402
from app.agents.reviewer import merge_duplicates  # noqa: E402
from app.agents.security import SecurityAgent  # noqa: E402
from app.services.orchestrator import Orchestrator  # noqa: E402
from app.services.preprocessing import preprocess  # noqa: E402

SAMPLE = Path(__file__).resolve().parents[2] / "samples" / "vulnerable-app"


def make(tmp_path: Path, files: dict[str, str]):
    for name, code in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(code)
    return preprocess(tmp_path)


def rules(findings):
    return {f.rule_id for f in findings}


def test_security_detects_core_vulnerabilities(tmp_path):
    cb = make(tmp_path, {"a.py": (
        "import os, pickle, hashlib, yaml\n"
        "from flask import request\n"
        "PASSWORD = 'hunter2hunter2'\n"
        "def f(cur):\n"
        "    uid = request.args.get('id')\n"
        "    cur.execute(f\"SELECT * FROM t WHERE id={uid}\")\n"
        "    os.system('ls ' + uid)\n"
        "    eval(uid)\n"
        "    pickle.loads(uid)\n"
        "    yaml.load(uid)\n"
        "    hashlib.md5(b'x')\n"
    )})
    found = rules(SecurityAgent().analyze(cb))
    assert {"SEC001", "SEC002", "SEC003", "SEC004", "SEC005", "SEC006"} <= found


def test_security_ignores_safe_code(tmp_path):
    cb = make(tmp_path, {"a.py": (
        "import os, yaml, hashlib\n"
        "PASSWORD = os.environ['PASSWORD']\n"
        "API_KEY = 'your-api-key-here'\n"
        "def f(cur, uid):\n"
        "    cur.execute('SELECT * FROM t WHERE id = %s', (uid,))\n"
        "    yaml.safe_load('a: 1')\n"
        "    hashlib.md5(b'x', usedforsecurity=False)\n"
    )})
    assert SecurityAgent().analyze(cb) == []


def test_secret_patterns_are_masked(tmp_path):
    cb = make(tmp_path, {"config.js": "const key = 'AKIAIOSFODNN7EXAMPLE';\n"})
    findings = SecurityAgent().analyze(cb)
    assert any(f.rule_id == "SEC017" for f in findings)
    assert all("AKIAIOSFODNN7EXAMPLE" not in f.snippet for f in findings)


def test_quality_and_logic(tmp_path):
    cb = make(tmp_path, {"b.py": (
        "def f(x, items=[]):\n"
        "    if x == None:\n"
        "        return 1\n"
        "        print('dead')\n"
        "    try:\n"
        "        pass\n"
        "    except:\n"
        "        pass\n"
        "    d = {'a': 1, 'a': 2}\n"
        "    return d\n"
    )})
    assert {"QLT005", "QLT006"} <= rules(QualityAgent().analyze(cb))
    assert {"LOG001", "LOG002", "LOG006"} <= rules(LogicAgent().analyze(cb))


def test_performance(tmp_path):
    cb = make(tmp_path, {"c.py": (
        "import time\n"
        "def f(a, b, c, cursor):\n"
        "    s = ''\n"
        "    for x in a:\n"
        "        for y in b:\n"
        "            for z in c:\n"
        "                s += 'x'\n"
        "        cursor.execute('SELECT 1')\n"
        "    return s\n"
        "async def g():\n"
        "    time.sleep(1)\n"
    )})
    assert {"PRF001", "PRF002", "PRF003", "PRF006"} <= rules(PerformanceAgent().analyze(cb))


def test_dependency_offline_advisories(tmp_path):
    cb = make(tmp_path, {"requirements.txt": "requests==2.25.1\nflask\n"})
    findings = DependencyAgent().analyze(cb)
    assert any(f.rule_id == "DEP001" and "CVE-2023-32681" in f.title for f in findings)
    assert any(f.rule_id == "DEP002" for f in findings)


def test_rule_based_fixes():
    from app.agents.base import RawFinding
    f = RawFinding(agent="t", category="Security", rule_id="SEC002", file="a.py", line=1,
                   snippet='cursor.execute(f"SELECT * FROM users WHERE id = \'{uid}\'")')
    assert rule_based_fix(f) == 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
    f = RawFinding(agent="t", category="Security", rule_id="SEC005", file="a.py", line=1, snippet="cfg = yaml.load(data)")
    assert rule_based_fix(f) == "cfg = yaml.safe_load(data)"


def test_merge_duplicates_across_tools():
    from app.agents.base import RawFinding
    a = RawFinding(agent="Security Agent", category="Security", rule_id="SEC002", file="a.py", line=3)
    b = RawFinding(agent="Security Agent", category="Security", rule_id="SEC002", file="a.py", line=3, sources=["Bandit"])
    merged = merge_duplicates([a, b])
    assert len(merged) == 1 and set(merged[0].sources) == {"Security Agent", "Bandit"}


def test_full_pipeline_on_sample_app():
    stages = []
    result = Orchestrator(progress=lambda s, p: stages.append(p)).run(SAMPLE)
    assert result["severity_counts"]["Critical"] >= 5
    assert result["gate"]["passed"] is False
    assert result["scores"]["security_score"] < 40
    assert stages[-1] == 100
    assert all(a["error"] == "" for a in result["agents"].values())
    cats = result["category_counts"]
    assert {"Security", "Quality", "Logic", "Performance", "Dependency"} <= set(cats)


def test_ignore_file(tmp_path):
    (tmp_path / ".codeguardianignore").write_text("vendor_code\n")
    cb = make(tmp_path, {"vendor_code/x.py": "eval(input())\n", "main.py": "print(1)\n"})
    assert [f.path for f in cb.files if f.language == "python"] == ["main.py"]
