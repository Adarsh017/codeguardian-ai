import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, timeAgo } from "../api.js";
import { ErrorNote, GateBadge, SeverityStrip } from "../components/ui.jsx";

export default function ProjectDetail() {
  const { id } = useParams();
  const [project, setProject] = useState(null);
  const [error, setError] = useState("");
  const [confirming, setConfirming] = useState(false);
  const navigate = useNavigate();

  useEffect(() => { api.project(id).then(setProject).catch((e) => setError(e.message)); }, [id]);

  async function rescan() {
    try { const s = await api.rescan(id); navigate(`/scans/${s.id}`); } catch (e) { setError(e.message); }
  }
  async function remove() {
    try { await api.deleteProject(id); navigate("/projects"); } catch (e) { setError(e.message); }
  }

  if (error && !project) return <ErrorNote error={error} />;
  if (!project) return <p className="muted">Loading…</p>;
  return (
    <div className="page">
      <header className="page-head">
        <div>
          <h1>{project.name}</h1>
          <p className="muted">
            {project.source_type === "github"
              ? <a href={project.repo_url} target="_blank" rel="noreferrer">{project.repo_url.replace("https://", "")}</a>
              : "Uploaded archive"}{project.branch && ` · branch ${project.branch}`}
          </p>
        </div>
        <div className="actions">
          <button className="btn btn-primary" onClick={rescan}>
            {project.source_type === "github" ? "Scan latest commit" : "Scan again"}
          </button>
          {confirming ? (
            <span className="confirm">Delete project and all scans?
              <button className="btn btn-danger" onClick={remove}>Delete</button>
              <button className="btn" onClick={() => setConfirming(false)}>Keep</button>
            </span>
          ) : <button className="btn" onClick={() => setConfirming(true)}>Delete project</button>}
        </div>
      </header>
      <ErrorNote error={error} />
      <section className="panel">
        <h2>Scan history</h2>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Scan</th><th>Status</th><th>Security</th><th>Quality</th><th>Findings</th><th>Commit</th><th>When</th></tr></thead>
            <tbody>
              {project.scans.map((s) => (
                <tr key={s.id}>
                  <td><Link to={`/scans/${s.id}`}>#{s.id}</Link> <span className="muted">{s.trigger}</span></td>
                  <td><GateBadge passed={s.gate_passed} status={s.status} /></td>
                  <td className="num">{s.status === "completed" ? Math.round(s.security_score) : "–"}</td>
                  <td className="num">{s.status === "completed" ? Math.round(s.quality_score) : "–"}</td>
                  <td className="strip-cell">{s.status === "completed" ? <SeverityStrip counts={s.severity_counts} height={8} showLegend={false} /> : s.error || s.stage}</td>
                  <td><code>{s.commit_sha ? s.commit_sha.slice(0, 7) : "–"}</code></td>
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
