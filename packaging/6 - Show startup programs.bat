@echo off
chcp 65001 >nul
cd /d "%~dp0"
hem_guard_cli.exe startup list
echo.
echo To turn one off, open a Command Prompt here and type:  hem_guard_cli.exe startup disable NUMBER
pause
