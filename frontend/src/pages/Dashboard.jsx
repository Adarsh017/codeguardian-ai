import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, timeAgo } from "../api.js";
import { Empty, ErrorNote, GateBadge, SeverityStrip, SeverityTag } from "../components/ui.jsx";

function TrendChart({ points }) {
  if (points.length < 2) return <p className="muted">The trend appears after two completed scans.</p>;
  const W = 560, H = 170, P = 28;
  const x = (i) => P + (i * (W - 2 * P)) / (points.length - 1);
  const y = (v) => H - P - (v / 100) * (H - 2 * P);
  const line = (key) => points.map((p, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(p[key]).toFixed(1)}`).join(" ");
  return (
    <figure className="trend">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label="Security and quality scores across recent scans">
        {[0, 50, 100].map((g) => (
          <g key={g}>
            <line x1={P} x2={W - P} y1={y(g)} y2={y(g)} className="grid" />
            <text x={P - 6} y={y(g) + 4} className="axis" textAnchor="end">{g}</text>
          </g>
        ))}
        <path d={line("quality")} className="ln ln-quality" />
        <path d={line("security")} className="ln ln-security" />
        {points.map((p, i) => (
          <g key={p.scan_id}>
            <circle cx={x(i)} cy={y(p.security)} r="3.5" className="pt-security"><title>Scan #{p.scan_id} ({p.project}): security {Math.round(p.security)}</title></circle>
            <circle cx={x(i)} cy={y(p.quality)} r="3.5" className="pt-quality"><title>Scan #{p.scan_id} ({p.project}): quality {Math.round(p.quality)}</title></circle>
          </g>
        ))}
      </svg>
      <figcaption><i className="key key-security" />Security score <i className="key key-quality" />Quality score</figcaption>
    </figure>
  );
}

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let timer;
    const load = () => api.dashboard().then((d) => {
      setData(d);
      if (d.running) timer = setTimeout(load, 3000);
    }).catch((e) => setError(e.message));
    load();
    return () => clearTimeout(timer);
  }, []);

  if (error) return <ErrorNote error={error} />;
  if (!data) return <p className="muted">Loading…</p>;
  if (!data.projects) {
    return (
      <Empty title="No code scanned yet">
        <p>Upload a ZIP of your source code or connect a GitHub repository to run your first multi-agent review.</p>
        <Link className="btn btn-primary" to="/scan/new">Start a scan</Link>
      </Empty>
    );
  }
  const open = data.severity_totals;
  return (
    <div className="page">
      <header className="page-head">
        <h1>Overview</h1>
        <Link className="btn btn-primary" to="/scan/new">New scan</Link>
      </header>

      <section className="overview">
        <div className="overview-strip">
          <h2>Open findings in your latest scans</h2>
          <SeverityStrip counts={open} height={22} />
        </div>
        <dl className="kpis">
          <div><dt>Average security score</dt><dd>{data.avg_security_score != null ? Math.round(data.avg_security_score) : "–"}</dd></div>
          <div><dt>Average quality score</dt><dd>{data.avg_quality_score != null ? Math.round(data.avg_quality_score) : "–"}</dd></div>
          <div><dt>Projects passing the gate</dt><dd>{data.gate_pass_rate != null ? `${Math.round(data.gate_pass_rate)}%` : "–"}</dd></div>
          <div><dt>Projects · scans</dt><dd>{data.projects} · {data.scans}</dd></div>
        </dl>
      </section>

      <div className="two-col">
        <section className="panel">
          <h2>Score trend</h2>
          <TrendChart points={data.trend} />
        </section>
        <section className="panel">
          <h2>Most frequent issues</h2>
          {data.top_issues.length ? (
            <ol className="top-issues">
              {data.top_issues.map((t) => (
                <li key={t.rule_id + t.title}><SeverityTag severity={t.severity} /><span>{t.title}</span><b>{t.count}</b></li>
              ))}
            </ol>
          ) : <p className="muted">No issues found.</p>}
        </section>
      </div>

      <section className="panel">
        <h2>Recent scans</h2>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Project</th><th>Scan</th><th>Status</th><th>Security</th><th>Quality</th><th>Findings</th><th>When</th></tr></thead>
            <tbody>
              {data.recent_scans.map((s) => (
                <tr key={s.id}>
                  <td><Link to={`/projects/${s.project_id}`}>{s.project_name}</Link></td>
                  <td><Link to={`/scans/${s.id}`}>#{s.id}</Link></td>
                  <td><GateBadge passed={s.gate_passed} status={s.status} /></td>
                  <td className="num">{s.status === "completed" ? Math.round(s.security_score) : "–"}</td>
                  <td className="num">{s.status === "completed" ? Math.round(s.quality_score) : "–"}</td>
                  <td className="strip-cell">{s.status === "completed" ? <SeverityStrip counts={s.severity_counts} height={8} showLegend={false} /> : s.stage}</td>
                  <td className="muted">{timeAgo(s.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
