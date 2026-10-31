@echo off
chcp 65001 >nul
cd /d "%~dp0"
set /p FOLDER=Type or paste the folder to scan, then press Enter: 
hem_guard_cli.exe scan "%FOLDER%"
echo.
pause
