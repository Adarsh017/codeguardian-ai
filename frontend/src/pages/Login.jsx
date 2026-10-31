import { useState } from "react";
import { api } from "../api.js";
import { ErrorNote, Shield } from "../components/ui.jsx";

export default function Login({ onAuth }) {
  const [mode, setMode] = useState("login");
  const [form, setForm] = useState({ name: "", email: "", password: "" });
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm({ ...form, [k]: e.target.value });

  async function submit(e) {
    e.preventDefault();
    setError(""); setBusy(true);
    try {
      onAuth(mode === "login" ? await api.login(form) : await api.register(form));
    } catch (err) {
      setError(err.message);
    } finally { setBusy(false); }
  }

  return (
    <div className="login">
      <section className="login-intro">
        <div className="brand brand-lg"><Shield size={34} /><span>CodeGuardian AI</span></div>
        <h1>Find the vulnerable line before it ships.</h1>
        <p>Five analysis agents read your code in parallel: security, quality, logic, performance and dependencies.
          An AI reviewer filters the noise, and every finding comes with a fix you can paste.</p>
        <pre className="login-diff" aria-hidden="true">
          <span className="del">- cursor.execute(f"SELECT * FROM users WHERE id = '{"{"}uid{"}"}'")</span>
          <span className="add">+ cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))</span>
        </pre>
      </section>
      <form className="login-card" onSubmit={submit}>
        <h2>{mode === "login" ? "Sign in" : "Create your account"}</h2>
        {mode === "register" && (
          <label>Name<input value={form.name} onChange={set("name")} autoComplete="name" /></label>
        )}
        <label>Email<input type="email" required value={form.email} onChange={set("email")} autoComplete="email" /></label>
        <label>Password<input type="password" required minLength={8} value={form.password} onChange={set("password")}
          autoComplete={mode === "login" ? "current-password" : "new-password"} /></label>
        {mode === "register" && <small className="hint">At least 8 characters.</small>}
        <ErrorNote error={error} />
        <button className="btn btn-primary" disabled={busy}>{busy ? "Please wait…" : mode === "login" ? "Sign in" : "Create account"}</button>
        <p className="switch">
          {mode === "login" ? "New here?" : "Already have an account?"}{" "}
          <button type="button" className="link-btn" onClick={() => { setMode(mode === "login" ? "register" : "login"); setError(""); }}>
            {mode === "login" ? "Create an account" : "Sign in"}
          </button>
        </p>
      </form>
    </div>
  );
}
