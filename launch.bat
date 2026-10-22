@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo Install first: python -m venv .venv
  echo Then: .venv\Scripts\python -m pip install -r requirements.txt
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -m app.main %*
