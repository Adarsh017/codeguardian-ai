// Thin API client for the FastAPI backend. The JWT is kept in localStorage.
const TOKEN_KEY = "cg_token";
// Empty in local dev (Vite proxies /api). Set VITE_API_URL when the backend is hosted elsewhere.
const API_BASE = import.meta.env.VITE_API_URL || "";

export const auth = {
  get token() {
    try { return localStorage.getItem(TOKEN_KEY); } catch { return null; }
  },
  set(token) {
    try { token ? localStorage.setItem(TOKEN_KEY, token) : localStorage.removeItem(TOKEN_KEY); } catch { /* ignore */ }
  },
};

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

async function request(path, { method = "GET", body, form, raw } = {}) {
  const headers = {};
  if (auth.token) headers.Authorization = `Bearer ${auth.token}`;
  let payload;
  if (form) payload = form;
  else if (body !== undefined) { headers["Content-Type"] = "application/json"; payload = JSON.stringify(body); }
  const res = await fetch(API_BASE + path, { method, headers, body: payload });
  if (res.status === 401 && !path.startsWith("/api/auth/")) {
    auth.set(null);
    window.location.assign("/login");
    throw new ApiError("Your session expired. Sign in again.", 401);
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status})`;
    try {
      const data = await res.json();
      if (typeof data.detail === "string") detail = data.detail;
      else if (Array.isArray(data.detail)) detail = data.detail.map((d) => `${d.loc?.slice(-1)[0]}: ${d.msg}`).join("; ");
    } catch { /* not json */ }
    throw new ApiError(detail, res.status);
  }
  return raw ? res : res.json();
}

export const api = {
  register: (data) => request("/api/auth/register", { method: "POST", body: data }),
  login: (data) => request("/api/auth/login", { method: "POST", body: data }),
  me: () => request("/api/auth/me"),
  dashboard: () => request("/api/dashboard"),
  projects: () => request("/api/projects"),
  project: (id) => request(`/api/projects/${id}`),
  // Uses XMLHttpRequest (not fetch) so large uploads can report progress.
  uploadProject: (name, file, onProgress) => new Promise((resolve, reject) => {
    const form = new FormData();
    form.append("name", name);
    form.append("file", file);
    const xhr = new XMLHttpRequest();
    xhr.open("POST", API_BASE + "/api/projects/upload");
    if (auth.token) xhr.setRequestHeader("Authorization", `Bearer ${auth.token}`);
    xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(e.loaded / e.total); };
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch { /* not json */ }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(data);
      if (xhr.status === 401) { auth.set(null); window.location.assign("/login"); }
      const detail = typeof data?.detail === "string" ? data.detail : `Upload failed (${xhr.status})`;
      reject(new ApiError(detail, xhr.status));
    };
    xhr.onerror = () => reject(new ApiError("The upload was interrupted. Check that the server is still running.", 0));
    xhr.send(form);
  }),
  connectGithub: (data) => request("/api/projects/github", { method: "POST", body: data }),
  rescan: (id) => request(`/api/projects/${id}/scans`, { method: "POST", body: {} }),
  deleteProject: (id) => request(`/api/projects/${id}`, { method: "DELETE" }),
  scan: (id) => request(`/api/scans/${id}`),
  findings: (id) => request(`/api/scans/${id}/findings`),
  context: (scanId, findingId) => request(`/api/scans/${scanId}/findings/${findingId}/context`),
  settings: () => request("/api/settings"),
  saveSettings: (data) => request("/api/settings", { method: "PUT", body: data }),
  testLlm: () => request("/api/settings/test-llm", { method: "POST" }),
  async download(scanId, format) {
    const res = await request(`/api/scans/${scanId}/report?format=${format}`, { raw: true });
    const blob = await res.blob();
    const name = (res.headers.get("Content-Disposition") || "").match(/filename="(.+)"/)?.[1] || `report.${format}`;
    const url = URL.createObjectURL(blob);
    const a = Object.assign(document.createElement("a"), { href: url, download: name });
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  },
};

export const SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
export const CATEGORIES = ["Security", "Dependency", "Logic", "Quality", "Performance"];

export function timeAgo(iso) {
  if (!iso) return "";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return new Date(iso).toLocaleDateString(undefined, { day: "numeric", month: "short", year: "numeric" });
}