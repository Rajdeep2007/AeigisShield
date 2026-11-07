# AegisTrust Automated Test Suite Launcher
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Running AegisTrust Automated Test Suite" -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Cyan

Set-Location $PSScriptRoot
python -m pytest backend/tests -v
