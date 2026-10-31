import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api.js";
import { ErrorNote } from "../components/ui.jsx";

function formatSize(bytes) {
  return bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(bytes / 1024))} KB`;
}

export default function NewScan() {
  const [source, setSource] = useState("upload");
  const [name, setName] = useState("");
  const [file, setFile] = useState(null);
  const [drag, setDrag] = useState(false);
  const [repo, setRepo] = useState({ repo_url: "", branch: "", token: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [limitMb, setLimitMb] = useState(null);
  const [progress, setProgress] = useState(null);
  const input = useRef();
  useEffect(() => { api.settings().then((d) => setLimitMb(d.system.max_upload_mb)).catch(() => {}); }, []);
  const navigate = useNavigate();

  function pick(f) {
    if (!f) return;
    if (!f.name.toLowerCase().endsWith(".zip")) { setError("Choose a .zip archive of your source code."); return; }
    if (limitMb && f.size > limitMb * 1024 * 1024) {
      setError(`This ZIP is ${formatSize(f.size)}, over the ${limitMb} MB upload limit. Remove node_modules, venv, .git and build folders before zipping, or raise the limit in Settings.`);
      return;
    }
    setError(""); setFile(f);
    if (!name) setName(f.name.replace(/\.zip$/i, ""));
  }

  async function submit(e) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      const res = source === "upload"
        ? await api.uploadProject(name || file.name, file, setProgress)
        : await api.connectGithub({ ...repo, name, token: repo.token || null });
      navigate(`/scans/${res.scan.id}`);
    } catch (err) {
      setError(err.message);
      setBusy(false);
      setProgress(null);
    }
  }

  const ready = source === "upload" ? !!file : repo.repo_url.trim().length > 10;
  return (
    <div className="page page-narrow">
      <header className="page-head"><h1>New scan</h1></header>
      <form className="panel form" onSubmit={submit}>
        <div className="segmented" role="tablist" aria-label="Code source">
          <button type="button" role="tab" aria-selected={source === "upload"} onClick={() => setSource("upload")}>Upload a ZIP</button>
          <button type="button" role="tab" aria-selected={source === "github"} onClick={() => setSource("github")}>GitHub repository</button>
        </div>

        {source === "upload" ? (
          <div
            className={`dropzone ${drag ? "is-drag" : ""} ${file ? "has-file" : ""}`}
            onDragOver={(e) => { e.preventDefault(); setDrag(true); }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files[0]); }}
            onClick={() => input.current.click()}
            onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current.click()}
            role="button" tabIndex={0}
          >
            <input ref={input} type="file" accept=".zip" hidden onChange={(e) => pick(e.target.files[0])} />
            {file ? (
              <><strong>{file.name}</strong><span>{formatSize(file.size)} · click to choose another file</span></>
            ) : (
              <><strong>Drop a .zip of your project here</strong><span>or click to browse{limitMb ? `, up to ${limitMb} MB` : ""}. Python, JavaScript/TypeScript, Java, PHP, configs and manifests are analysed. Folders like node_modules and .git are skipped automatically.</span></>
            )}
          </div>
        ) : (
          <>
            <label>Repository URL
              <input placeholder="https://github.com/owner/repo" value={repo.repo_url}
                onChange={(e) => setRepo({ ...repo, repo_url: e.target.value })} required />
            </label>
            <div className="row">
              <label>Branch <small>optional, defaults to the main branch</small>
                <input placeholder="main" value={repo.branch} onChange={(e) => setRepo({ ...repo, branch: e.target.value })} />
              </label>
              <label>Access token <small>only for private repos, not stored</small>
                <input type="password" value={repo.token} onChange={(e) => setRepo({ ...repo, token: e.target.value })} autoComplete="off" />
              </label>
            </div>
          </>
        )}

        <label>Project name
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder={source === "github" ? "Defaults to owner/repo" : "My project"} />
        </label>
        <ErrorNote error={error} />
        {busy && progress != null && progress < 1 && (
          <div className="progress" role="progressbar" aria-valuenow={Math.round(progress * 100)} aria-valuemin={0} aria-valuemax={100}>
            <span style={{ width: `${progress * 100}%` }} />
          </div>
        )}
        <div className="form-actions">
          <button className="btn btn-primary" disabled={!ready || busy}>{!busy ? "Start scan" : progress != null && progress < 1 ? `Uploading ${Math.round(progress * 100)}%` : "Starting scan…"}</button>
        </div>
      </form>
    </div>
  );
}
