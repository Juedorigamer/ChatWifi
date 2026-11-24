@echo off
setlocal
cd /d "%~dp0"
chcp 65001 >nul
set PYTHONIOENCODING=utf-8

echo Iniciando servidor de la beta...
echo.

python android_beta_server.py

echo.
pause
