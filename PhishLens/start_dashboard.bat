@echo off
echo ========================================================
echo Starting PhishLens React Dashboard on http://localhost:5173
echo ========================================================
cd /d %~dp0dashboard
npm run dev
pause
