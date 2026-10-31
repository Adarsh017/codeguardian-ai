@echo off
REM One-command local start for CodeGuardian AI (Windows)
cd /d "%~dp0"
if not exist .venv python -m venv .venv
call .venv\Scripts\activate.bat
pip install -q -r backend\requirements.txt
if not exist frontend\dist (
  cd frontend
  call npm install
  call npm run build
  cd ..
)
cd backend
echo CodeGuardian AI running at http://localhost:8000
uvicorn app.main:app --port 8000
