import { SEVERITIES } from "../api.js";

export function Shield({ size = 24 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <path d="M16 2 4 7v8c0 7.5 5.1 13.4 12 15 6.9-1.6 12-7.5 12-15V7z" fill="currentColor" />
      <path d="m11 16 3.5 3.5L21 13" stroke="var(--paper)" strokeWidth="2.6" fill="none" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function SeverityTag({ severity }) {
  return <span className={`sev sev-${severity?.toLowerCase()}`}>{severity}</span>;
}

/** Horizontal strip whose segments are proportional to finding counts per severity. */
export function SeverityStrip({ counts = {}, height = 14, showLegend = true }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts[s] || 0), 0);
  return (
    <div className="strip-wrap">
      <div className="strip" style={{ height }} role="img"
        aria-label={SEVERITIES.map((s) => `${counts[s] || 0} ${s}`).join(", ")}>
        {total === 0 ? <span className="strip-empty" /> : SEVERITIES.map((s) =>
          counts[s] ? <span key={s} className={`seg seg-${s.toLowerCase()}`} style={{ flexGrow: counts[s] }} title={`${counts[s]} ${s}`} /> : null)}
      </div>
      {showLegend && (
        <ul className="strip-legend">
          {SEVERITIES.map((s) => (
            <li key={s}><i className={`dot seg-${s.toLowerCase()}`} /><b>{counts[s] || 0}</b> {s}</li>
          ))}
        </ul>
      )}
    </div>
  );
}

export function Score({ label, value, small }) {
  const v = value == null ? null : Math.round(value);
  const tone = v == null ? "" : v >= 75 ? "good" : v >= 50 ? "warn" : "bad";
  return (
    <div className={`score ${small ? "score-sm" : ""}`}>
      <span className={`score-num ${tone}`}>{v ?? "–"}</span>
      <span className="score-label">{label}</span>
    </div>
  );
}

export function GateBadge({ passed, status }) {
  if (status && status !== "completed") return <span className={`gate gate-${status}`}>{status === "failed" ? "Scan failed" : "Scanning"}</span>;
  return <span className={`gate ${passed ? "gate-pass" : "gate-fail"}`}>{passed ? "Gate passed" : "Gate failed"}</span>;
}

export function ErrorNote({ error }) {
  if (!error) return null;
  return <p className="error-note" role="alert">{error}</p>;
}

export function Empty({ title, children }) {
  return <div className="empty"><h3>{title}</h3>{children}</div>;
}
