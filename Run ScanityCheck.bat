@echo off
rem Double-click launcher for the ScanityCheck popup.
setlocal
cd /d "%~dp0"

where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw "%~dp0app.py"
    exit /b 0
)

where python >nul 2>nul
if %errorlevel%==0 (
    python "%~dp0app.py"
    exit /b 0
)

echo Python 3.10 or newer is required. Install it from https://www.python.org/downloads/
pause
