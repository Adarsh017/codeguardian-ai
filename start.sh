#!/usr/bin/env bash
# One-command local start for CodeGuardian AI (macOS / Linux)
set -e
cd "$(dirname "$0")"
if [ ! -d .venv ]; then python3 -m venv .venv; fi
source .venv/bin/activate
pip install -q -r backend/requirements.txt
if [ ! -d frontend/dist ]; then (cd frontend && npm install && npm run build); fi
cd backend
echo "CodeGuardian AI running at http://localhost:8000"
uvicorn app.main:app --port 8000
