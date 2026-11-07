@echo off
title AegisTrust Automated Test Suite
echo =====================================================================
echo  Running AegisTrust Test Suite (Core Modules + Security API Endpoints)
echo =====================================================================
echo.
cd /d "%~dp0"
python -m pytest backend/tests -v
echo.
pause
