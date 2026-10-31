import { useEffect, useState } from "react";
import { Navigate, NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { api, auth } from "./api.js";
import { Shield } from "./components/ui.jsx";
import Login from "./pages/Login.jsx";
import Dashboard from "./pages/Dashboard.jsx";
import NewScan from "./pages/NewScan.jsx";
import Projects from "./pages/Projects.jsx";
import ProjectDetail from "./pages/ProjectDetail.jsx";
import ScanReport from "./pages/ScanReport.jsx";
import Settings from "./pages/Settings.jsx";

function Shell({ user, onLogout, children }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="shell">
      <aside className={`sidebar ${open ? "is-open" : ""}`}>
        <div className="brand">
          <Shield size={26} />
          <span>CodeGuardian AI</span>
          <button className="menu-toggle" aria-label="Toggle menu" onClick={() => setOpen(!open)}>☰</button>
        </div>
        <nav onClick={() => setOpen(false)}>
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/scan/new">New scan</NavLink>
          <NavLink to="/projects">Projects</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <div className="sidebar-foot">
          <div className="who">{user?.name}<small>{user?.email}</small></div>
          <button className="link-btn" onClick={onLogout}>Sign out</button>
        </div>
      </aside>
      <main className="main">{children}</main>
    </div>
  );
}

export default function App() {
  const [user, setUser] = useState(null);
  const [checking, setChecking] = useState(!!auth.token);
  const navigate = useNavigate();

  useEffect(() => {
    if (!auth.token) return;
    api.me().then(setUser).catch(() => auth.set(null)).finally(() => setChecking(false));
  }, []);

  const onAuth = ({ token, user }) => { auth.set(token); setUser(user); navigate("/"); };
  const onLogout = () => { auth.set(null); setUser(null); navigate("/login"); };

  if (checking) return <div className="boot"><Shield size={40} /></div>;
  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login onAuth={onAuth} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }
  return (
    <Shell user={user} onLogout={onLogout}>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/new" element={<NewScan />} />
        <Route path="/projects" element={<Projects />} />
        <Route path="/projects/:id" element={<ProjectDetail />} />
        <Route path="/scans/:id" element={<ScanReport />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Shell>
  );
}
