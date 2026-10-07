@echo off
setlocal enabledelayedexpansion
title DefenXis — Sentinel CLI Daemon

:: Check for Administrator permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c \"\"%~dp0run_headless.bat\"\"' -Verb RunAs"
    exit /B
)

pushd "%CD%"
CD /D "%~dp0"

echo Starting DefenXis in Headless / Daemon mode...
python defender.py --cli
pause
