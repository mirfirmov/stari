@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "PYTHON_EXE="
if exist ".venv\Scripts\python.exe" goto :launch

for %%P in (py python python3) do (
  if not defined PYTHON_EXE (
    %%P -c "import sys; raise SystemExit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
    if not errorlevel 1 set "PYTHON_EXE=%%P"
  )
)
if not defined PYTHON_EXE goto :no_python

echo [stari] Creating local environment...
"%PYTHON_EXE%" -m venv .venv
if errorlevel 1 goto :install_error

echo [stari] Installing STARI and dependencies (first launch only)...
.venv\Scripts\python.exe -m pip install --disable-pip-version-check -e .
if errorlevel 1 goto :install_error

:launch
.venv\Scripts\python.exe -m stari %*
exit /b %errorlevel%

:no_python
echo [error] Python 3.11+ was not found. Install it from https://www.python.org/downloads/windows/
echo Enable "Add python.exe to PATH" during installation.
pause
exit /b 1

:install_error
echo [error] STARI setup failed. Check the message above and your internet connection.
pause
exit /b 1
