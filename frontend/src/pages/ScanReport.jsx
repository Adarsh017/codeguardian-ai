import { useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api, CATEGORIES, SEVERITIES, timeAgo } from "../api.js";
import { ErrorNote, GateBadge, Score, SeverityStrip, SeverityTag } from "../components/ui.jsx";

// The methodology, as the backend reports it through scan.progress
const PIPELINE = [
  { at: 3, name: "Code acquisition", detail: "Extract the archive or fetch the latest commit" },
  { at: 10, name: "Preprocessing", detail: "Detect languages, parse code, identify dependencies" },
  { at: 20, name: "Parallel multi-agent analysis", detail: "Security, quality, logic, performance and dependency agents" },
  { at: 62, name: "Finding aggregation", detail: "Merge duplicates, map file and line, assign confidence" },
  { at: 70, name: "AI contextual review", detail: "Validate findings against the surrounding code" },
  { at: 82, name: "AI remediation", detail: "Generate secure replacements and fix steps" },
  { at: 92, name: "Report generation", detail: "Scores, quality gate and exports" },
];

function Pipeline({ scan }) {
  const agentsDone = Math.max(0, Math.min(5, Math.round((scan.progress - 20) / 8)));
  return (
    <section className="panel pipeline-panel" aria-live="polite">
      <div className="pipeline-head">
        <h2>Scanning</h2>
        <span className="muted">{scan.stage} · {scan.progress}%</span>
      </div>
      <div className="progress"><span style={{ width: `${scan.progress}%` }} /></div>
      <ol className="pipeline">
        {PIPELINE.map((step, i) => {
          const next = PIPELINE[i + 1]?.at ?? 100;
          const state = scan.progress >= next ? "done" : scan.progress >= step.at ? "active" : "todo";
          return (
            <li key={step.name} className={`step step-${state}`}>
              <span className="step-mark" aria-hidden="true">{state === "done" ? "✓" : i + 1}</span>
              <div>
                <strong>{step.name}</strong>
                <span>{i === 2 && state !== "todo" ? `${agentsDone} of 5 agents finished` : step.detail}</span>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function CodeContext({ scanId, finding }) {
  const [ctx, setCtx] = useState(null);
  useEffect(() => {
    setCtx(null);
    api.context(scanId, finding.id).then(setCtx).catch(() => setCtx({ lines: [] }));
  }, [scanId, finding.id]);
  if (!ctx) return <div className="code skeleton" />;
  if (!ctx.lines.length) return finding.snippet ? <pre className="code"><code>{finding.snippet}</code></pre> : null;
  return (
    <pre className="code" tabIndex={0}>
      {ctx.lines.map((l, i) => {
        const n = ctx.start + i;
        return <span key={n} className={`code-line ${n === ctx.highlight ? "is-hit" : ""}`}><i>{n}</i>{l || " "}</span>;
      })}
    </pre>
  );
}

function FixDiff({ before, after }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try { await navigator.clipboard.writeText(after); setCopied(true); setTimeout(() => setCopied(false), 1500); } catch { /* ignore */ }
  };
  return (
    <div className="diff">
      <div className="diff-bar">
        <span>Suggested secure code</span>
        <button className="link-btn" onClick={copy}>{copied ? "Copied" : "Copy fix"}</button>
      </div>
      <pre>
        {before && before.split("\n").map((l, i) => <span key={`d${i}`} className="del">{l}</span>)}
        {after.split("\n").map((l, i) => <span key={`a${i}`} className="add">{l}</span>)}
      </pre>
    </div>
  );
}

function FindingDetail({ scanId, f, onClose }) {
  const cweId = f.cwe?.match(/CWE-(\d+)/)?.[1];
  const steps = f.remediation.split("\n").filter(Boolean);
  return (
    <article className="detail" aria-label="Finding detail">
      <button className="link-btn detail-close" onClick={onClose}>Back to list</button>
      <div className="detail-head">
        <SeverityTag severity={f.severity} />
        <h2>{f.title}</h2>
        <p className="detail-loc"><code>{f.file}:{f.line}</code></p>
        <dl className="facts">
          <div><dt>Category</dt><dd>{f.category}</dd></div>
          <div><dt>Confidence</dt><dd>{Math.round(f.confidence * 100)}%</dd></div>
          {f.cwe && <div><dt>Weakness</dt><dd>{cweId ? <a href={`https://cwe.mitre.org/data/definitions/${cweId}.html`} target="_blank" rel="noreferrer">{f.cwe}</a> : f.cwe}</dd></div>}
          {f.owasp && <div><dt>OWASP Top 10</dt><dd>{f.owasp}</dd></div>}
          <div><dt>Detected by</dt><dd>{f.sources.join(", ")}</dd></div>
        </dl>
      </div>
      <h3>Why it matters</h3>
      <p>{f.explanation || f.description}</p>
      <h3>Where</h3>
      <CodeContext scanId={scanId} finding={f} />
      {/* SEC019 (container runs as root) is an addition, not a replacement of the flagged line */}
      {f.fixed_code && <FixDiff before={f.rule_id === "SEC019" ? "" : f.snippet} after={f.fixed_code} />}
      <h3>How to fix it</h3>
      {steps.length > 1 ? <ol className="steps">{steps.map((s, i) => <li key={i}>{s.replace(/^\d+\.\s*/, "")}</li>)}</ol> : <p>{f.remediation}</p>}
    </article>
  );
}

export default function ScanReport() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [findings, setFindings] = useState(null);
  const [error, setError] = useState("");
  const [sev, setSev] = useState(new Set(["Critical", "High", "Medium", "Low"]));
  const [cat, setCat] = useState("");
  const [q, setQ] = useState("");
  const [selected, setSelected] = useState(null);
  const [exporting, setExporting] = useState("");

  useEffect(() => {
    let timer, alive = true;
    setScan(null); setFindings(null); setSelected(null);
    const poll = async () => {
      try {
        const s = await api.scan(id);
        if (!alive) return;
        setScan(s);
        if (s.status === "completed") {
          const list = await api.findings(id);
          if (alive) { setFindings(list); setSelected(window.innerWidth > 1080 ? list[0]?.id ?? null : null); }
        } else if (s.status !== "failed") timer = setTimeout(poll, 1200);
      } catch (e) { if (alive) setError(e.message); }
    };
    poll();
    return () => { alive = false; clearTimeout(timer); };
  }, [id]);

  const visible = useMemo(() => (findings || []).filter((f) =>
    sev.has(f.severity) && (!cat || f.category === cat) &&
    (!q || `${f.title} ${f.file} ${f.cwe}`.toLowerCase().includes(q.toLowerCase()))), [findings, sev, cat, q]);
  const current = visible.find((f) => f.id === selected) || null;

  const toggleSev = (s) => { const n = new Set(sev); n.has(s) ? n.delete(s) : n.add(s); setSev(n); };
  async function exportAs(fmt) {
    setExporting(fmt);
    try { await api.download(id, fmt); } catch (e) { setError(e.message); } finally { setExporting(""); }
  }

  if (error && !scan) return <ErrorNote error={error} />;
  if (!scan) return <p className="muted">Loading…</p>;
  const summary = scan.summary || {};
  const counts = summary.severity_counts || {};

  return (
    <div className="page">
      <header className="page-head">
        <div>
          <p className="crumbs"><Link to={`/projects/${scan.project.id}`}>{scan.project.name}</Link> / Scan #{scan.id}</p>
          <h1>Security review</h1>
          <p className="muted">
            {timeAgo(scan.created_at)}{scan.commit_sha && <> · commit <code>{scan.commit_sha.slice(0, 7)}</code></>}
            {summary.codebase && ` · ${summary.codebase.files} files, ${summary.codebase.lines.toLocaleString()} lines`}
          </p>
        </div>
        {scan.status === "completed" && (
          <div className="actions export">
            <span className="muted">Export</span>
            {["pdf", "json", "csv", "sarif"].map((f) => (
              <button key={f} className="btn" onClick={() => exportAs(f)} disabled={!!exporting}>{exporting === f ? "…" : f.toUpperCase()}</button>
            ))}
          </div>
        )}
      </header>

      {scan.status === "failed" && (
        <div className="panel failed">
          <h2>The scan could not finish</h2>
          <p>{scan.error}</p>
          <Link className="btn" to={`/projects/${scan.project.id}`}>Back to project</Link>
        </div>
      )}
      {(scan.status === "queued" || scan.status === "running") && <Pipeline scan={scan} />}

      {scan.status === "completed" && (
        <>
          <section className="verdict">
            <div className="verdict-gate">
              <GateBadge passed={scan.gate_passed} />
              <p>{summary.gate?.passed ? `No findings at or above “${summary.gate?.fail_on}” severity.` : summary.gate?.reasons?.join("; ")}</p>
            </div>
            <div className="verdict-scores">
              <Score label="Security" value={scan.security_score} />
              <Score label="Code quality" value={scan.quality_score} />
              <Score label="Overall" value={scan.overall_score} small />
            </div>
            <div className="verdict-strip"><SeverityStrip counts={counts} height={26} /></div>
          </section>

          <section className="panel summary">
            <h2>Reviewer summary</h2>
            <p>{summary.summary}</p>
            <details>
              <summary>How this scan ran</summary>
              <table className="table compact">
                <thead><tr><th>Agent</th><th>Findings</th><th>Time</th></tr></thead>
                <tbody>
                  {Object.entries(summary.agents || {}).map(([name, a]) => (
                    <tr key={name}><td>{name}{a.error && <span className="error-inline"> failed: {a.error}</span>}</td><td className="num">{a.findings}</td><td className="num">{a.seconds}s</td></tr>
                  ))}
                </tbody>
              </table>
              <p className="muted small">
                Engine: {summary.engine === "langgraph" ? "LangGraph" : "thread pool"} · {summary.raw_finding_count} raw findings merged into {findings?.length ?? "…"} ·
                AI review: {summary.ai_review?.llm?.enabled ? `${summary.ai_review.reviewed} findings checked by ${summary.ai_review.llm.model}, ${summary.ai_review.false_positives_removed} false positives removed` : "off (rule-based explanations)"} ·
                fixes: {summary.ai_remediation?.ai_fixes || 0} AI, {summary.ai_remediation?.rule_based_fixes || 0} rule-based · total {summary.timings?.total}s
              </p>
            </details>
          </section>

          <section className="findings">
            <div className="filters">
              <div className="chips" role="group" aria-label="Filter by severity">
                {SEVERITIES.map((s) => (
                  <button key={s} className={`chip chip-${s.toLowerCase()}`} aria-pressed={sev.has(s)} onClick={() => toggleSev(s)}>
                    {s} <b>{counts[s] || 0}</b>
                  </button>
                ))}
              </div>
              <select value={cat} onChange={(e) => setCat(e.target.value)} aria-label="Filter by category">
                <option value="">All categories</option>
                {CATEGORIES.map((c) => <option key={c} value={c}>{c} ({summary.category_counts?.[c] || 0})</option>)}
              </select>
              <input type="search" placeholder="Search title, file or CWE" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search findings" />
            </div>

            {!findings ? <p className="muted">Loading findings…</p> : visible.length === 0 ? (
              <p className="muted empty-inline">{findings.length ? "No findings match these filters." : "No issues found. This code passed every agent."}</p>
            ) : (
              <div className={`split ${current ? "has-detail" : ""}`}>
                <ul className="finding-list" aria-label={`${visible.length} findings`}>
                  {visible.map((f) => (
                    <li key={f.id}>
                      <button className={`finding ${f.id === selected ? "is-selected" : ""}`} onClick={() => setSelected(f.id)} aria-current={f.id === selected}>
                        <span className={`bar bar-${f.severity.toLowerCase()}`} aria-hidden="true" />
                        <span className="finding-main">
                          <span className="finding-title">{f.title}</span>
                          <span className="finding-meta"><code>{f.file}:{f.line}</code> · {f.category}{f.fixed_code && " · fix ready"}</span>
                        </span>
                        <SeverityTag severity={f.severity} />
                      </button>
                    </li>
                  ))}
                </ul>
                {current && <FindingDetail scanId={id} f={current} onClose={() => setSelected(null)} />}
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}
