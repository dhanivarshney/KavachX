@echo off
echo ========================================================
echo Starting KavachX React Dashboard on http://localhost:5173
echo ========================================================
cd /d %~dp0PhishLens\dashboard
npm run dev
pause
