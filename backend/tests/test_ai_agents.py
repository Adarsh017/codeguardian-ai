"""AI Reviewer / Remediation agents with a mocked LLM (no network)."""
import json

from app.agents.base import RawFinding
from app.agents.remediation import AIRemediationAgent
from app.agents.reviewer import AIReviewerAgent
from app.services import llm
from app.services.preprocessing import CodeBase, SourceFile


def test_ai_review_filters_false_positives_and_adds_fixes(monkeypatch, tmp_path):
    code = "import os\nDEBUG_TOKEN = 'abcd1234'\nos.system(cmd)\n"
    cb = CodeBase(root=tmp_path, files=[SourceFile("a.py", "python", code)])
    findings = [
        RawFinding(agent="Security Agent", category="Security", rule_id="SEC004", file="a.py", line=2, snippet="DEBUG_TOKEN = 'abcd1234'"),
        RawFinding(agent="Security Agent", category="Security", rule_id="SEC003", file="a.py", line=3, snippet="os.system(cmd)"),
    ]
    calls = []

    def fake_chat(system, user, max_tokens=4000):
        calls.append(system)
        items = json.loads(user)
        if "Reviewer" in system:
            return {"reviews": [
                {"id": items[0]["id"], "verdict": "false_positive", "confidence": 0.9, "severity": "Low", "explanation": "test fixture"},
                {"id": items[1]["id"], "verdict": "true_positive", "confidence": 0.95, "severity": "Critical",
                 "explanation": "cmd flows into a shell."}]}
        return {"fixes": [{"id": i["id"], "fixed_code": "subprocess.run(['ls', arg], check=True)",
                           "steps": ["Avoid the shell", "Validate input"]} for i in items]}

    monkeypatch.setattr(llm, "enabled", lambda: True)
    monkeypatch.setattr(llm, "chat_json", fake_chat)
    kept, stats = AIReviewerAgent().run(findings, cb)
    assert stats["false_positives_removed"] == 1
    assert len(kept) == 1 and kept[0].severity == "Critical" and kept[0].ai_reviewed
    rem = AIRemediationAgent().run(kept, cb)
    assert rem["ai_fixes"] == 1
    assert kept[0].fixed_code.startswith("subprocess.run")
    assert kept[0].remediation.startswith("1. Avoid the shell")


def test_extract_json_from_fenced_reply():
    assert llm._extract_json('Sure!\n```json\n{"a": 1}\n```') == {"a": 1}


def test_openai_compatible_http_call(monkeypatch):
    import httpx

    from app.config import settings
    seen = {}

    def handler(request):
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": '{"reviews": []}'}}]})

    real_client = httpx.Client
    monkeypatch.setattr(llm.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(settings, "LLM_PROVIDER", "openai")
    monkeypatch.setattr(settings, "LLM_API_KEY", "test-key")
    monkeypatch.setattr(settings, "LLM_BASE_URL", "https://api.groq.com/openai/v1")
    assert llm.chat_json("sys", "user-unique-1") == {"reviews": []}
    assert seen["url"] == "https://api.groq.com/openai/v1/chat/completions"
    assert seen["auth"] == "Bearer test-key"


def test_anthropic_http_call(monkeypatch):
    import httpx

    from app.config import settings

    def handler(request):
        assert request.headers["x-api-key"] == "k"
        return httpx.Response(200, json={"content": [{"type": "text", "text": '{"fixes": []}'}]})

    real_client = httpx.Client
    monkeypatch.setattr(llm.httpx, "Client", lambda **kw: real_client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr(settings, "LLM_PROVIDER", "anthropic")
    monkeypatch.setattr(settings, "LLM_API_KEY", "k")
    assert llm.chat_json("sys", "user-unique-2") == {"fixes": []}
