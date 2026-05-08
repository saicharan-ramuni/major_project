@echo off
title Healthcare Authentication Launcher
echo =====================================================
echo   Healthcare Authentication System - Launcher
echo =====================================================
echo.
echo Starting launcher on http://localhost:5000
echo.
cd /d "%~dp0"
start "" "http://localhost:5000"
python launcher.py
pause
