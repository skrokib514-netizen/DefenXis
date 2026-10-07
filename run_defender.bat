@echo off
setlocal enabledelayedexpansion
title DefenXis — Anti-Throttling Sentinel

:: Check for Administrator permissions
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges for DefenXis...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin_defenxis.vbs"
    set "params=%*"
    echo UAC.ShellExecute "cmd.exe", "/c ""%~dp0run_defender.bat"" %params%", "", "runas", 1 >> "%temp%\getadmin_defenxis.vbs"
    "%temp%\getadmin_defenxis.vbs"
    del "%temp%\getadmin_defenxis.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"

:: Check Python installation
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in system PATH.
    echo Please install Python 3.9 or higher and check "Add Python to PATH".
    pause
    exit /B 1
)

:: Run Defender
python defender.py %*

if errorlevel 1 (
    echo.
    echo  [!] DefenXis exited with error code: %ERRORLEVEL%
    pause
)
