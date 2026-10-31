import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, timeAgo } from "../api.js";
import { Empty, ErrorNote, GateBadge, SeverityStrip } from "../components/ui.jsx";

export default function Projects() {
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => { api.projects().then(setProjects).catch((e) => setError(e.message)); }, []);

  if (error) return <ErrorNote error={error} />;
  if (!projects) return <p className="muted">Loading…</p>;
  return (
    <div className="page">
      <header className="page-head">
        <h1>Projects</h1>
        <Link className="btn btn-primary" to="/scan/new">New scan</Link>
      </header>
      {!projects.length ? (
        <Empty title="No projects yet"><p>Each upload or connected repository becomes a project you can rescan.</p></Empty>
      ) : (
        <ul className="project-list">
          {projects.map((p) => {
            const s = p.latest_scan;
            return (
              <li key={p.id}>
                <Link to={`/projects/${p.id}`} className="project-row">
                  <div className="project-name">
                    <strong>{p.name}</strong>
                    <span className="muted">{p.source_type === "github" ? p.repo_url.replace("https://", "") : "Uploaded archive"} · {p.scan_count} scan{p.scan_count === 1 ? "" : "s"}</span>
                  </div>
                  {s && s.status === "completed" ? (
                    <>
                      <span className="mini-score">Security <b>{Math.round(s.security_score)}</b></span>
                      <span className="mini-score">Quality <b>{Math.round(s.quality_score)}</b></span>
                      <div className="project-strip"><SeverityStrip counts={s.severity_counts} height={8} showLegend={false} /></div>
                    </>
                  ) : <span className="muted">{s?.stage}</span>}
                  {s && <GateBadge passed={s.gate_passed} status={s.status} />}
                  <span className="muted when">{timeAgo(s?.created_at || p.created_at)}</span>
                </Link>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}
