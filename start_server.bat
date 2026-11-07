@echo off
title AegisTrust Security Platform
echo =====================================================================
echo  Starting AegisTrust Threat Intelligence and Web3 Verification Server
echo =====================================================================
echo.
cd /d "%~dp0\backend"
echo [1/2] Checking Python environment...
python --version
echo.
echo [2/2] Launching FastAPI uvicorn daemon on http://localhost:8000 ...
echo - Live SOC Console:        http://localhost:8000/
echo - Evaluation Sandbox:      http://localhost:8000/sandbox
echo - Interactive OpenAPI Docs: http://localhost:8000/docs
echo.
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
pause
