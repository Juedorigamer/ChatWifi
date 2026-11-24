@echo off
cd /d "%~dp0"
py -c "import cryptography" >nul 2>&1
if errorlevel 1 py -m pip install cryptography
py chat.py
if errorlevel 1 pause
