@echo off
echo ========================================================
echo Launching KavachX Backend & Dashboard...
echo ========================================================
start "KavachX Backend (:8000)" cmd /k "%~dp0start_backend.bat"
start "KavachX Dashboard (:5173)" cmd /k "%~dp0start_dashboard.bat"
echo Services launched in separate windows!
