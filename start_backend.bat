@echo off
echo ========================================================
echo Starting KavachX FastAPI Backend on http://localhost:8000
echo ========================================================
cd /d %~dp0PhishLens\backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
