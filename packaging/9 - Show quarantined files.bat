@echo off
chcp 65001 >nul
cd /d "%~dp0"
hem_guard_cli.exe quarantine list
echo.
echo To bring one back, open a Command Prompt here and type:  hem_guard_cli.exe quarantine restore ID
pause
