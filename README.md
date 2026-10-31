# CodeGuardian AI

**Multi-Agent Intelligent Platform for Automated Secure Code Review and Vulnerability Detection**

Upload source code or connect a GitHub repository. Five analysis agents scan it in parallel. An AI Reviewer agent validates the findings in context, and an AI Remediation agent writes secure replacement code. Every scan ends with security and quality scores, a CI/CD quality gate, and PDF / JSON / CSV / SARIF reports.

```
Developer ─▶ React dashboard ─▶ FastAPI backend ─▶ LangGraph orchestrator
                                                    ├─ Security Agent      (SAST rules, secrets, Bandit, Semgrep)
                                                    ├─ Code Quality Agent  (complexity, smells, duplication)
                                                    ├─ Logic Agent         (dead code, wrong conditions, bugs)
                                                    ├─ Performance Agent   (N+1, nested loops, blocking calls)
                                                    └─ Dependency Agent    (CVEs via OSV.dev, pinning, licenses)
                                                          │ (fan-in)
                                                    Aggregation ─▶ AI Reviewer ─▶ AI Remediation ─▶ Report + Gate
```

---

## 1. Run it in VS Code (recommended)

Requirements: **Python 3.10+**, **Node.js 18+** and **VS Code**. On Windows, tick "Add Python to PATH" when installing Python.

1. Unzip the project, then in VS Code choose **File → Open Folder…** and select the `codeguardian-ai` folder (the one containing `README.md`).
2. Click **Install** when VS Code offers the recommended extensions (Python, Python Debugger, Pylance).
3. Run the one-time setup: **Terminal → Run Task… → Setup (run once)**. This creates `.venv`, installs the Python packages, installs the npm packages and builds the dashboard. It takes a few minutes the first time.
4. If VS Code asks you to select a Python interpreter, choose the one in `.venv`.
5. Open **Run and Debug** (`Ctrl+Shift+D`, or `Cmd+Shift+D` on a Mac), pick **CodeGuardian AI (backend + dashboard)** and press **F5**. Your browser opens http://localhost:8000.
6. Create an account, click **New scan**, and upload a ZIP of `samples/vulnerable-app`.

Other configurations in the Run and Debug list:

| Configuration | What it does |
|---|---|
| CodeGuardian AI (backend + dashboard) | Runs the API and the built dashboard on port 8000, with breakpoints in Python |
| Full stack with hot reload | Backend plus the Vite dev server on http://localhost:5173. Use this while editing the React code |
| CLI: scan the sample app | Scans `samples/vulnerable-app` in the terminal and writes PDF/JSON reports to `codeguardian-reports/` |
| CLI: scan a folder… | Asks for any folder path on your computer and scans it |

Tests: open the **Testing** panel (beaker icon) and click **Run Tests**, or use **Terminal → Run Task… → Run tests**.

To set an AI model key, copy `.env.example` to `.env` in the project root and fill it in, or use the **Settings** page in the dashboard.

**Common problems**

* *"python is not recognized"* (Windows): reinstall Python with "Add Python to PATH" ticked. Or edit `.vscode/tasks.json` and change `python -m venv .venv` to `py -m venv .venv`.
* *Running scripts is disabled on this system* (PowerShell): VS Code's tasks don't need activation scripts. For your own terminal, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.
* *Port 8000 already in use*: change `"8000"` in `.vscode/launch.json`, or stop the other program.
* *The page at localhost:8000 shows `{"detail":"Not Found"}`*: the dashboard wasn't built. Run the **Build dashboard** task.

## 1b. Run from a terminal (without VS Code)

```bash
python -m venv .venv                 # macOS/Linux: python3 -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r backend/requirements.txt
cd frontend && npm install && npm run build && cd ..
cd backend
uvicorn app.main:app --port 8000
```

Or double-click `start.bat` (Windows) / run `./start.sh` (macOS/Linux), which does all of the above.

### Docker (PostgreSQL + Redis, as in the architecture)

```bash
cp .env.example .env      # optional: add an LLM key
docker compose up --build
```

Then open http://localhost:8000.

---

## 2. Turning on the AI agents

The platform works fully **without** an LLM: every finding gets a rule-based explanation, CWE/OWASP mapping and, for 30+ rule types, an automatic code fix. When you connect a model, the agents add the following:

* **AI Reviewer Agent:** reads each finding together with the surrounding code. It removes false positives, re-rates severity, assigns confidence and writes a context-specific explanation plus an executive summary.
* **AI Remediation Agent:** writes a secure drop-in replacement and step-by-step fix instructions.

Configure the model in **Settings** in the dashboard (one-click presets), or in `.env`:

| Provider | `LLM_PROVIDER` | `LLM_BASE_URL` | `LLM_MODEL` (example) | Cost |
|---|---|---|---|---|
| Groq | `openai` | `https://api.groq.com/openai/v1` | `llama-3.3-70b-versatile` | free tier |
| Google Gemini | `openai` | `https://generativelanguage.googleapis.com/v1beta/openai` | `gemini-2.0-flash` | free tier |
| Ollama (offline, local) | `openai` | `http://localhost:11434/v1` | `qwen2.5-coder:7b` | free |
| OpenAI | `openai` | `https://api.openai.com/v1` | `gpt-4o-mini` | paid |
| Anthropic | `anthropic` | – | a current Claude model id | paid |

Set `LLM_API_KEY` too (not needed for Ollama). Use **Save and test connection** in Settings to verify it. LLM replies are cached, so rescanning unchanged code costs nothing.

---

## 3. CI/CD integration

The same engine runs as a command-line tool, so it works in any pipeline:

```bash
cd backend
python -m app.cli scan /path/to/project --fail-on high --format pdf,json,sarif -v
```

* Exit code `0` means the quality gate passed; `1` means it failed, which blocks the pipeline.
* `--fail-on critical|high|medium|low|none` sets the gate threshold. `--min-score 70` also requires a minimum security score.
* `--exclude "tests,docs/*"` skips paths. You can also list patterns in a `.codeguardianignore` file.
* `--server http://host:8000 --token <JWT> --project <id>` also sends the scan to the dashboard.

**GitHub Actions:** `.github/workflows/codeguardian.yml` scans on every push and pull request. It then:
1. fails the check when the gate fails,
2. uploads SARIF, so findings appear in the repository's **Security → Code scanning** tab,
3. posts a results table as a PR comment,
4. stores the PDF/JSON reports as build artifacts.

To enable AI review in CI, add `LLM_PROVIDER`, `LLM_API_KEY`, `LLM_BASE_URL` and `LLM_MODEL` as repository secrets. The workflow fails on `critical` by default; change `--fail-on` to match your policy. Jenkins and GitLab CI can run the same `python -m app.cli scan` command.

---

## 4. What each agent detects

| Agent | Examples |
|---|---|
| **Security** | SQL injection (f-string / concat / `%` / `.format`), command injection (`os.system`, `shell=True`, `child_process.exec`), `eval`/`exec`, XSS sinks (`innerHTML`, `render_template_string`, `dangerouslySetInnerHTML`), insecure deserialization (`pickle`, `yaml.load`), weak hashes, disabled TLS verification, JWT without signature check, path traversal, SSRF, insecure randomness for tokens, debug mode, permissive CORS, hardcoded secrets plus Gitleaks-style key signatures (AWS, GitHub, Google, Stripe, Slack, OpenAI, private keys, DB URLs), Dockerfile running as root / `:latest`. Uses light taint tracking from `request.*` to raise confidence, and merges in **Bandit** results (and **Semgrep** if installed). |
| **Code Quality** | Long functions, cyclomatic complexity, too many parameters, deep nesting, bare/swallowed `except`, mutable default arguments, large files, cross-file duplicated code, unused imports, `var` / `==` / `console.log` in JS, TODO/FIXME |
| **Logic** | Unreachable code, `== None`, `is` with literals, constant conditions, self-comparison, duplicate dict keys, duplicate `elif` conditions, identical branches, inconsistent returns, `return` in `finally`, unreachable `except` clauses, off-by-one `range(len(x)+1)`, shadowed built-ins, undefined names, unused variables, infinite `while True`, assignment in JS conditions |
| **Performance** | 3+ nested loops, string `+=` in loops, DB/HTTP/file I/O inside loops (N+1), `in list` inside loops, regex compiled in loops, `time.sleep` in async code, sequential `await` in loops, deep copies in loops, `sorted(x)[0]` |
| **Dependency** | Parses `requirements*.txt`, `pyproject.toml`, `package.json`. Looks up known CVEs on **OSV.dev**, with an offline fallback list. Flags unpinned versions, copyleft licenses, and imports not declared in any manifest |

Languages: deep (AST) analysis for **Python**; pattern-based rules for **JavaScript/TypeScript, Java, PHP**, config files, YAML, `.env` and Dockerfiles.

**Scores:** each finding contributes `severity weight × confidence` (Critical 25, High 10, Medium 4, Low 1). Security score = `100·e^(−penalty/80)` over security and dependency findings. Quality score uses quality, logic and performance findings, normalised by code size (√KLOC). Overall = 60% security + 40% quality.

---

## 5. Project structure (mapped to the architecture slide)

```
backend/app/
├── main.py                    API Backend (FastAPI) – also serves the built dashboard
├── auth.py                    Authentication & Authorization (PBKDF2 + JWT)
├── routers/projects.py        Project & Repository Management
├── services/
│   ├── ingestion.py           Input layer: ZIP upload (zip-slip safe), GitHub import
│   ├── preprocessing.py       Preprocessing layer: extraction, parsing, deps, normalization
│   ├── orchestrator.py        Agent Orchestration Engine (LangGraph StateGraph)
│   ├── scan_service.py        Scan Orchestration & Scheduling (worker pool, progress)
│   ├── scoring.py             Security / quality scores, quality gate
│   ├── report.py              Report Generator: PDF, JSON, CSV, SARIF
│   ├── notifications.py       Notification Service (Slack/Discord/Teams webhook)
│   ├── llm.py                 LLM API client (OpenAI-compatible + Anthropic)
│   └── cache.py               Cache (Redis, or in-memory)
├── agents/
│   ├── security.py  quality.py  logic.py  performance.py  dependency.py
│   ├── reviewer.py            AI Reviewer Agent (dedupe, FP removal, explanations)
│   ├── remediation.py         AI Remediation Agent (LLM fixes + rule-based auto-fixes)
│   └── rules.py               Rule knowledge base (CWE / OWASP Top 10 mapping)
└── cli.py                     CI/CD command-line scanner
frontend/src/                  React dashboard: upload, GitHub connect, live scan status,
                               dashboard, reports & findings, settings
.vscode/                       Run/debug configurations, setup tasks, test discovery
samples/vulnerable-app/        Intentionally vulnerable demo project (Python, JS, configs)
.github/workflows/             GitHub Actions integration
```

**Database:** SQLite by default, so no setup is needed. Set `DATABASE_URL` to use PostgreSQL. Tables: `users`, `projects`, `scans`, `findings`.

---

## 6. Tests

```bash
cd backend
python -m pytest -q
```

The 18 tests cover every agent, deduplication, rule-based fixes, the LangGraph pipeline on the sample app, the full API flow (register → upload → background scan → findings → all four report formats → access control), zip-slip protection, the OSV.dev client and both LLM clients (with mocked HTTP).

---

## 7. Demo script (for the review)

1. `python -m app.cli scan ../samples/vulnerable-app -v`. This shows the agents, scores and suggested fixes in the terminal, and the gate failing with exit code 1.
2. In the dashboard, upload the sample ZIP and watch the 7-stage pipeline progress live.
3. Open the report: gate verdict, scores, severity strip. Click a SQL-injection finding to show the highlighted line, the red/green fix diff, and CWE-89 / OWASP A03.
4. Export the PDF report.
5. Settings: connect Groq or Gemini (free), rescan, and show the AI-written explanations, removed false positives and AI fixes under **How this scan ran**.
6. Show the GitHub Actions workflow and a SARIF upload in the Security tab.

## Limitations and future work

* Deep semantic analysis is Python-only. Other languages use pattern rules (could be extended with tree-sitter).
* Taint tracking is intra-file and approximate. The AI Reviewer compensates by checking context.
* "Continuous improvement" (stage 9) is supported through LLM response caching and editable rules. Learning from developer feedback (mark as false positive → suppress) is the natural next step.
