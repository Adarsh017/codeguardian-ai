"""AI Reviewer Agent: consolidates findings, removes duplicates and false positives,
understands code context, assigns severity & confidence, and explains each issue."""
import json
import logging

from ..config import settings
from ..services import llm
from ..services.preprocessing import CodeBase
from .base import RawFinding, context
from .rules import SEVERITY_ORDER

log = logging.getLogger("codeguardian.reviewer")

SYSTEM = """You are the AI Reviewer Agent of CodeGuardian AI, a senior application-security and code-review expert.
You receive findings produced by static-analysis agents together with the surrounding source code.
For EACH finding decide, using the code context:
  - verdict: "true_positive" or "false_positive" (e.g. value is a constant, input is already sanitized, test fixture, dead path)
  - severity: one of Critical, High, Medium, Low, Info (re-assess using real exploitability and impact)
  - confidence: number 0..1 for your verdict
  - explanation: 2-4 sentences in plain language explaining WHY this is a problem in THIS code and what could happen (impact)
Be precise and do not invent code that is not shown. Respond ONLY with JSON:
{"reviews": [{"id": <int>, "verdict": "...", "severity": "...", "confidence": 0.0, "explanation": "..."}]}"""

SUMMARY_SYSTEM = """You are the AI Reviewer Agent of CodeGuardian AI. Write an executive summary of a code scan for a
development team: overall risk posture, the most important issues to fix first, and recurring patterns.
4-6 sentences, plain language, no markdown headings. Respond ONLY with JSON: {"summary": "..."}"""

BATCH = 8


def _r(x: float) -> int:
    """Round half up (matches how the dashboard displays scores)."""
    return int(x + 0.5)


def merge_duplicates(findings: list[RawFinding]) -> list[RawFinding]:
    """Consolidate findings reported by several agents/tools for the same location and weakness."""
    merged: dict[tuple, RawFinding] = {}
    for f in findings:
        keys = [(f.file, f.line, f.rule_id)]
        if f.cwe:
            keys.append((f.file, f.line, f.cwe))
        existing = merged.get(keys[0])
        if existing is None and len(keys) > 1:
            candidate = merged.get(keys[1])
            # same weakness on the same line reported by a *different* tool/agent -> one finding
            if candidate is not None and not set(candidate.sources) & set(f.sources):
                existing = candidate
        if existing is None:
            for k in keys:
                merged.setdefault(k, f)
            merged[keys[0]] = f
            continue
        # merge into the existing one
        for src in f.sources:
            if src not in existing.sources:
                existing.sources.append(src)
        if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(existing.severity, 0):
            existing.severity = f.severity
        existing.confidence = min(0.99, max(existing.confidence, f.confidence) + 0.05)
        for k in keys:
            merged.setdefault(k, existing)
    unique = list({id(f): f for f in merged.values()}.values())
    return sort_findings(unique)


def sort_findings(findings: list[RawFinding]) -> list[RawFinding]:
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -f.confidence, f.file, f.line))


class AIReviewerAgent:
    name = "AI Reviewer Agent"

    def run(self, findings: list[RawFinding], codebase: CodeBase) -> tuple[list[RawFinding], dict]:
        stats = {"reviewed": 0, "false_positives_removed": 0, "severity_changes": 0, "llm": llm.describe(), "errors": []}
        findings = merge_duplicates(findings)
        files = {f.path: f.code for f in codebase.files}

        # default (rule-based) explanations so every finding is explained even without an LLM
        for f in findings:
            if not f.explanation:
                f.explanation = f.description

        if not llm.enabled():
            return findings, stats

        candidates = [f for f in findings if f.severity != "Info"][: settings.LLM_MAX_FINDINGS]
        removed: set[int] = set()
        for start in range(0, len(candidates), BATCH):
            batch = candidates[start:start + BATCH]
            payload = []
            for i, f in enumerate(batch):
                payload.append({"id": i, "rule": f.rule_id, "title": f.title, "severity": f.severity, "cwe": f.cwe,
                                "file": f.file, "line": f.line, "detected_by": f.sources,
                                "code_context": context(files.get(f.file, ""), f.line, 6)})
            try:
                data = llm.chat_json(SYSTEM, json.dumps(payload, indent=1))
            except llm.LLMError as exc:
                stats["errors"].append(str(exc)[:200])
                log.warning("AI review batch failed: %s", exc)
                continue
            for review in data.get("reviews", []):
                try:
                    f = batch[int(review["id"])]
                except (KeyError, ValueError, IndexError, TypeError):
                    continue
                stats["reviewed"] += 1
                f.ai_reviewed = True
                conf = float(review.get("confidence", 0.7) or 0.7)
                if review.get("verdict") == "false_positive" and conf >= 0.7:
                    removed.add(id(f))
                    continue
                sev = str(review.get("severity", "")).capitalize()
                if sev in SEVERITY_ORDER and sev != f.severity:
                    f.severity = sev
                    stats["severity_changes"] += 1
                f.confidence = round(max(0.05, min(0.99, (f.confidence + conf) / 2)), 2)
                if review.get("explanation"):
                    f.explanation = str(review["explanation"])
                if "AI Reviewer" not in f.sources:
                    f.sources.append("AI Reviewer")
        stats["false_positives_removed"] = len(removed)
        return sort_findings([f for f in findings if id(f) not in removed]), stats

    def executive_summary(self, findings: list[RawFinding], info: dict, scores: dict) -> str:
        counts = {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}
        top = [f"{f.severity}: {f.title} ({f.file}:{f.line})" for f in findings[:10]]
        if llm.enabled():
            try:
                data = llm.chat_json(SUMMARY_SYSTEM, json.dumps(
                    {"scores": scores, "severity_counts": counts, "codebase": {k: info[k] for k in ("files", "lines", "languages")},
                     "top_findings": top}))
                if data.get("summary"):
                    return str(data["summary"])
            except llm.LLMError:
                pass
        # deterministic summary
        crit_high = counts["Critical"] + counts["High"]
        posture = ("critical risk" if counts["Critical"] else "high risk" if counts["High"] else
                   "moderate risk" if counts["Medium"] else "low risk")
        cats: dict[str, int] = {}
        for f in findings:
            cats[f.category] = cats.get(f.category, 0) + 1
        main = ", ".join(f"{n} {c.lower()}" for c, n in sorted(cats.items(), key=lambda kv: -kv[1])[:3])
        text = (f"The scan analysed {info['files']} files ({info['lines']} lines) and found {len(findings)} issues "
                f"({main}). Overall posture: {posture}, with a security score of {_r(scores['security_score'])}/100 "
                f"and a code quality score of {_r(scores['quality_score'])}/100. ")
        if crit_high:
            text += f"{crit_high} critical/high issues should be fixed before release, starting with: {findings[0].title} in {findings[0].file}."
        else:
            text += "No critical or high severity issues were found."
        return text
