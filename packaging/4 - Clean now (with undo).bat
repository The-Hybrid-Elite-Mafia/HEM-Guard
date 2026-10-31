@echo off
chcp 65001 >nul
cd /d "%~dp0"
hem_guard_cli.exe clean --apply
echo.
pause
