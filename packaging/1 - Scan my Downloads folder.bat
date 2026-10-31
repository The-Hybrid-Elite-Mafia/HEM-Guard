@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo HEM Guard - scanning your Downloads folder (this only READS files)
hem_guard_cli.exe scan "%USERPROFILE%\Downloads"
echo.
pause
