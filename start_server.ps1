# AegisTrust Turnkey PowerShell Launcher
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " AegisTrust Threat Intelligence and Web3 Verification Platform" -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Cyan

$backendDir = Join-Path $PSScriptRoot "backend"
Set-Location $backendDir

Write-Host "`n[+] Python Environment:" -ForegroundColor Yellow
python --version

Write-Host "`n[+] Launching FastAPI Service on http://localhost:8000 ..." -ForegroundColor Green
Write-Host " - Live SOC Console:         http://localhost:8000/" -ForegroundColor White
Write-Host " - Evaluation Sandbox:       http://localhost:8000/sandbox" -ForegroundColor White
Write-Host " - Interactive OpenAPI Docs: http://localhost:8000/docs`n" -ForegroundColor White

python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
