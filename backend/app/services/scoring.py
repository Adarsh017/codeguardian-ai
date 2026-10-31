"""Security score, code quality score, grades and the CI/CD quality gate."""
import math

from ..agents.base import RawFinding
from ..agents.rules import SEVERITY_ORDER, SEVERITY_WEIGHT

SECURITY_CATEGORIES = {"Security", "Dependency"}


def _penalty(findings: list[RawFinding]) -> float:
    return sum(SEVERITY_WEIGHT.get(f.severity, 0) * f.confidence for f in findings)


def grade(score: float) -> str:
    return "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"


def compute_scores(findings: list[RawFinding], total_lines: int) -> dict:
    kloc = max(1.0, total_lines / 1000)
    sec = [f for f in findings if f.category in SECURITY_CATEGORIES]
    qual = [f for f in findings if f.category not in SECURITY_CATEGORIES]
    # Security: absolute — every exploitable issue matters regardless of code size.
    security = 100 * math.exp(-_penalty(sec) / 80)
    # Quality: normalized by code size (issues per sqrt(KLOC)).
    quality = 100 * math.exp(-(_penalty(qual) / math.sqrt(kloc)) / 120)
    overall = 0.6 * security + 0.4 * quality
    return {
        "security_score": round(security, 1),
        "quality_score": round(quality, 1),
        "overall_score": round(overall, 1),
        "security_grade": grade(security),
        "quality_grade": grade(quality),
        "overall_grade": grade(overall),
    }


def severity_counts(findings: list[RawFinding]) -> dict:
    return {s: sum(1 for f in findings if f.severity == s) for s in SEVERITY_ORDER}


def category_counts(findings: list[RawFinding]) -> dict:
    out: dict[str, int] = {}
    for f in findings:
        out[f.category] = out.get(f.category, 0) + 1
    return out


def quality_gate(findings: list[RawFinding], scores: dict, fail_on: str = "high", min_security_score: float = 0) -> dict:
    reasons = []
    threshold = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(fail_on.lower())
    if threshold is not None:
        blocking = [f for f in findings if SEVERITY_ORDER.get(f.severity, 0) >= threshold]
        if blocking:
            reasons.append(f"{len(blocking)} finding(s) at or above '{fail_on}' severity")
    if scores["security_score"] < min_security_score:
        reasons.append(f"security score {scores['security_score']} < required {min_security_score}")
    return {"passed": not reasons, "reasons": reasons, "fail_on": fail_on, "min_security_score": min_security_score}
