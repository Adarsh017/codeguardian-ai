"""Agent Orchestration Engine.

Pipeline (matches the methodology):
  preprocess -> [security | quality | logic | performance | dependency]  (parallel)
             -> aggregate (dedupe, map file/line, severity, confidence)
             -> ai_review -> ai_remediation -> report (scores + quality gate)

Implemented as a LangGraph StateGraph when langgraph is installed; otherwise an
equivalent thread-pool implementation is used, so the engine always works.
"""
import logging
import operator
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Annotated, Any, Callable, TypedDict

from ..agents.base import RawFinding
from ..agents.dependency import DependencyAgent
from ..agents.logic import LogicAgent
from ..agents.performance import PerformanceAgent
from ..agents.quality import QualityAgent
from ..agents.remediation import AIRemediationAgent
from ..agents.reviewer import AIReviewerAgent
from ..agents.security import SecurityAgent
from ..config import settings
from . import scoring
from .preprocessing import CodeBase, preprocess

log = logging.getLogger("codeguardian.orchestrator")

try:
    from langgraph.graph import END, START, StateGraph
    HAS_LANGGRAPH = True
except ImportError:  # pragma: no cover
    HAS_LANGGRAPH = False

ANALYSIS_AGENTS = [SecurityAgent(), QualityAgent(), LogicAgent(), PerformanceAgent(), DependencyAgent()]
ProgressFn = Callable[[str, int], None]


def _merge_dicts(a: dict, b: dict) -> dict:
    return {**a, **b}


class ScanState(TypedDict, total=False):
    root: str
    codebase: Any
    raw_findings: Annotated[list, operator.add]
    agent_stats: Annotated[dict, _merge_dicts]
    findings: list
    review_stats: dict
    remediation_stats: dict
    scores: dict
    gate: dict
    summary: str
    timings: Annotated[dict, _merge_dicts]


def _run_agent(agent, codebase: CodeBase) -> tuple[list[RawFinding], dict, float]:
    t0 = time.perf_counter()
    try:
        found = agent.analyze(codebase)
        error = ""
    except Exception as exc:  # one failing agent must not kill the scan
        log.exception("%s failed", agent.name)
        found, error = [], str(exc)[:300]
    dt = round(time.perf_counter() - t0, 3)
    return found, {agent.name: {"findings": len(found), "seconds": dt, "error": error}}, dt


class Orchestrator:
    def __init__(self, progress: ProgressFn | None = None, fail_on: str | None = None,
                 min_security_score: float | None = None, exclude: list[str] | None = None):
        self.exclude = exclude or []
        self.progress = progress or (lambda stage, pct: None)
        self.fail_on = fail_on or settings.GATE_FAIL_ON
        self.min_security_score = settings.GATE_MIN_SECURITY_SCORE if min_security_score is None else min_security_score
        self.reviewer = AIReviewerAgent()
        self.remediator = AIRemediationAgent()
        self._done_agents = 0

    # ------------------------------------------------------------------ nodes
    def node_preprocess(self, state: ScanState) -> dict:
        self.progress("Preprocessing code", 10)
        t0 = time.perf_counter()
        cb = preprocess(Path(state["root"]), self.exclude)
        return {"codebase": cb, "timings": {"preprocess": round(time.perf_counter() - t0, 3)}}

    def make_agent_node(self, agent):
        def node(state: ScanState) -> dict:
            found, stats, dt = _run_agent(agent, state["codebase"])
            self._done_agents += 1
            self.progress(f"{agent.name} finished", 20 + int(40 * self._done_agents / len(ANALYSIS_AGENTS)))
            return {"raw_findings": found, "agent_stats": stats, "timings": {agent.name: dt}}
        return node

    def node_aggregate(self, state: ScanState) -> dict:
        self.progress("Aggregating findings", 62)
        return {}

    def node_review(self, state: ScanState) -> dict:
        self.progress("AI contextual review", 70)
        t0 = time.perf_counter()
        findings, stats = self.reviewer.run(state.get("raw_findings", []), state["codebase"])
        return {"findings": findings, "review_stats": stats, "timings": {"ai_review": round(time.perf_counter() - t0, 3)}}

    def node_remediate(self, state: ScanState) -> dict:
        self.progress("AI remediation", 82)
        t0 = time.perf_counter()
        stats = self.remediator.run(state["findings"], state["codebase"])
        return {"remediation_stats": stats, "timings": {"ai_remediation": round(time.perf_counter() - t0, 3)}}

    def node_report(self, state: ScanState) -> dict:
        self.progress("Generating report", 92)
        findings = state["findings"]
        info = state["codebase"].info()
        scores = scoring.compute_scores(findings, info["lines"])
        gate = scoring.quality_gate(findings, scores, self.fail_on, self.min_security_score)
        summary = self.reviewer.executive_summary(findings, info, scores)
        return {"scores": scores, "gate": gate, "summary": summary}

    # ------------------------------------------------------------------ graph
    def build_graph(self):
        g = StateGraph(ScanState)
        g.add_node("preprocess", self.node_preprocess)
        names = []
        for agent in ANALYSIS_AGENTS:
            key = agent.name.lower().replace(" ", "_")
            names.append(key)
            g.add_node(key, self.make_agent_node(agent))
            g.add_edge("preprocess", key)
        g.add_node("aggregate", self.node_aggregate)
        g.add_node("ai_review", self.node_review)
        g.add_node("ai_remediation", self.node_remediate)
        g.add_node("report", self.node_report)
        g.add_edge(START, "preprocess")
        g.add_edge(names, "aggregate")  # fan-in: wait for all agents
        g.add_edge("aggregate", "ai_review")
        g.add_edge("ai_review", "ai_remediation")
        g.add_edge("ai_remediation", "report")
        g.add_edge("report", END)
        return g.compile()

    def run(self, root: Path) -> dict:
        t0 = time.perf_counter()
        state: ScanState = {"root": str(root), "raw_findings": [], "agent_stats": {}, "timings": {}}
        if HAS_LANGGRAPH:
            final = self.build_graph().invoke(state)
            engine = "langgraph"
        else:
            final = self._run_fallback(state)
            engine = "threadpool"
        cb: CodeBase = final["codebase"]
        findings: list[RawFinding] = final["findings"]
        self.progress("Completed", 100)
        return {
            "engine": engine,
            "codebase": cb.info(),
            "dependencies": [d.__dict__ for d in cb.dependencies],
            "findings": findings,
            "scores": final["scores"],
            "gate": final["gate"],
            "summary": final["summary"],
            "severity_counts": scoring.severity_counts(findings),
            "category_counts": scoring.category_counts(findings),
            "agents": final["agent_stats"],
            "ai_review": final["review_stats"],
            "ai_remediation": final["remediation_stats"],
            "raw_finding_count": len(final.get("raw_findings", [])),
            "timings": {**final["timings"], "total": round(time.perf_counter() - t0, 3)},
        }

    def _run_fallback(self, state: ScanState) -> ScanState:
        def merge(update: dict):
            for k, v in update.items():
                if k in ("raw_findings",):
                    state[k] = state.get(k, []) + v
                elif k in ("agent_stats", "timings"):
                    state[k] = {**state.get(k, {}), **v}
                else:
                    state[k] = v
        merge(self.node_preprocess(state))
        with ThreadPoolExecutor(len(ANALYSIS_AGENTS)) as pool:
            for update in pool.map(lambda a: self.make_agent_node(a)(state), ANALYSIS_AGENTS):
                merge(update)
        for node in (self.node_aggregate, self.node_review, self.node_remediate, self.node_report):
            merge(node(state))
        return state
