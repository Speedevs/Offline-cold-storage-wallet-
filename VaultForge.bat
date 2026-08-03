@echo off
REM VaultForge desktop launcher (Windows). Needs Python 3 from python.org.
cd /d "%~dp0"
python VaultForge_Desktop.py %*
if errorlevel 1 pause
