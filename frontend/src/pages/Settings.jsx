import { useEffect, useState } from "react";
import { api } from "../api.js";
import { ErrorNote } from "../components/ui.jsx";

const PRESET_NAMES = { openai: "OpenAI", groq: "Groq", gemini: "Gemini", ollama: "Ollama (local)", anthropic: "Anthropic" };
const PRESETS = {
  openai: { LLM_PROVIDER: "openai", LLM_BASE_URL: "https://api.openai.com/v1", LLM_MODEL: "gpt-4o-mini" },
  groq: { LLM_PROVIDER: "openai", LLM_BASE_URL: "https://api.groq.com/openai/v1", LLM_MODEL: "llama-3.3-70b-versatile" },
  gemini: { LLM_PROVIDER: "openai", LLM_BASE_URL: "https://generativelanguage.googleapis.com/v1beta/openai", LLM_MODEL: "gemini-2.0-flash" },
  ollama: { LLM_PROVIDER: "openai", LLM_BASE_URL: "http://localhost:11434/v1", LLM_MODEL: "qwen2.5-coder:7b" },
  anthropic: { LLM_PROVIDER: "anthropic", LLM_BASE_URL: "https://api.anthropic.com/v1", LLM_MODEL: "" },
};

export default function Settings() {
  const [form, setForm] = useState(null);
  const [system, setSystem] = useState(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => { api.settings().then((d) => { setForm(d.settings); setSystem(d.system); }).catch((e) => setError(e.message)); }, []);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.type === "checkbox" ? e.target.checked : e.target.value });

  async function save(e) {
    e?.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const d = await api.saveSettings({ ...form, LLM_MAX_FINDINGS: Number(form.LLM_MAX_FINDINGS), MAX_UPLOAD_MB: Number(form.MAX_UPLOAD_MB), GATE_MIN_SECURITY_SCORE: Number(form.GATE_MIN_SECURITY_SCORE) });
      setForm(d.settings); setSystem(d.system); setNotice("Settings saved. They apply to the next scan.");
    } catch (err) { setError(err.message); } finally { setBusy(false); }
  }
  async function test() {
    setNotice(""); setError("");
    await save();
    const r = await api.testLlm();
    r.ok ? setNotice(r.message) : setError(r.message);
  }

  if (!form) return error ? <ErrorNote error={error} /> : <p className="muted">Loading…</p>;
  return (
    <div className="page page-narrow">
      <header className="page-head"><h1>Settings</h1></header>
      <form className="form" onSubmit={save}>
        <section className="panel">
          <h2>AI reviewer and remediation</h2>
          <p className="muted">Without a model, findings still get rule-based explanations and fixes. Connect one to have the reviewer confirm findings in context, drop false positives and write fixes.</p>
          <div className="preset-row">
            <span className="muted">Presets</span>
            {Object.keys(PRESETS).map((k) => (
              <button type="button" key={k} className="btn btn-small" onClick={() => setForm({ ...form, ...PRESETS[k] })}>{PRESET_NAMES[k]}</button>
            ))}
            <button type="button" className="btn btn-small" onClick={() => setForm({ ...form, LLM_PROVIDER: "none" })}>Turn off</button>
          </div>
          <div className="row">
            <label>Provider
              <select value={form.LLM_PROVIDER} onChange={set("LLM_PROVIDER")}>
                <option value="none">None (rule-based only)</option>
                <option value="openai">OpenAI-compatible API</option>
                <option value="anthropic">Anthropic</option>
              </select>
            </label>
            <label>Model<input value={form.LLM_MODEL} onChange={set("LLM_MODEL")} /></label>
          </div>
          <label>API base URL<input value={form.LLM_BASE_URL} onChange={set("LLM_BASE_URL")} /></label>
          <div className="row">
            <label>API key<input type="password" value={form.LLM_API_KEY} onChange={set("LLM_API_KEY")} autoComplete="off" placeholder="Not set" /></label>
            <label>Findings sent to the model per scan<input type="number" min="1" max="200" value={form.LLM_MAX_FINDINGS} onChange={set("LLM_MAX_FINDINGS")} /></label>
          </div>
          <button type="button" className="btn" onClick={test} disabled={busy}>Save and test connection</button>
        </section>

        <section className="panel">
          <h2>Quality gate</h2>
          <p className="muted">Used for the pass/fail verdict on every scan and as the default for the CI command.</p>
          <div className="row">
            <label>Fail when a finding is at or above
              <select value={form.GATE_FAIL_ON} onChange={set("GATE_FAIL_ON")}>
                <option value="critical">Critical</option><option value="high">High</option>
                <option value="medium">Medium</option><option value="low">Low</option><option value="none">Never (score only)</option>
              </select>
            </label>
            <label>Minimum security score<input type="number" min="0" max="100" value={form.GATE_MIN_SECURITY_SCORE} onChange={set("GATE_MIN_SECURITY_SCORE")} /></label>
          </div>
        </section>

        <section className="panel">
          <h2>Integrations</h2>
          <label className="check"><input type="checkbox" checked={!!form.OSV_ENABLED} onChange={set("OSV_ENABLED")} />
            Look up dependency vulnerabilities on OSV.dev and licenses on PyPI/npm (turn off when offline)</label>
          <label>Maximum ZIP upload size (MB) <small>folders like node_modules, venv and .git inside the ZIP are skipped when unpacking</small>
            <input type="number" min="1" max="5000" value={form.MAX_UPLOAD_MB} onChange={set("MAX_UPLOAD_MB")} /></label>
          <label>GitHub token <small>for private repositories and higher rate limits</small>
            <input type="password" value={form.GITHUB_TOKEN} onChange={set("GITHUB_TOKEN")} autoComplete="off" placeholder="Not set" /></label>
          <label>Notification webhook <small>Slack, Discord or Teams incoming webhook URL</small>
            <input value={form.NOTIFY_WEBHOOK_URL} onChange={set("NOTIFY_WEBHOOK_URL")} placeholder="https://hooks.slack.com/services/…" /></label>
        </section>

        <ErrorNote error={error} />
        {notice && <p className="notice" role="status">{notice}</p>}
        <div className="form-actions"><button className="btn btn-primary" disabled={busy}>Save settings</button></div>
      </form>

      {system && (
        <section className="panel">
          <h2>System</h2>
          <dl className="facts facts-grid">
            <div><dt>Orchestration</dt><dd>{system.orchestration_engine}</dd></div>
            <div><dt>AI model</dt><dd>{system.llm.enabled ? system.llm.model : "Not connected"}</dd></div>
            <div><dt>Database</dt><dd>{system.database}</dd></div>
            <div><dt>Cache</dt><dd>{system.cache}</dd></div>
            <div><dt>Bandit</dt><dd>{system.tools.bandit ? "Installed" : "Not installed"}</dd></div>
            <div><dt>Semgrep</dt><dd>{system.tools.semgrep ? "Installed" : "Not installed"}</dd></div>
          </dl>
          <p className="muted small">Agents: {system.agents.join(", ")}. Version {system.version}.</p>
        </section>
      )}
    </div>
  );
}
