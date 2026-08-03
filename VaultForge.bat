@echo off
where python >nul 2>nul || (
  echo Python is not installed. Get it from https://python.org/downloads
  echo and tick "Add Python to PATH" during setup, then run this again.
  pause & exit /b
)
python "%~dp0VaultForge_Windows.py"
if errorlevel 1 pause
