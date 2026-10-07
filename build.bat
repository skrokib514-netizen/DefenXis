@echo off
title Build DefenXis Standalone EXE
pushd "%CD%"
CD /D "%~dp0"

echo ========================================================
echo        Building DefenXis Standalone EXE
echo ========================================================
python build_exe.py

echo.
pause
