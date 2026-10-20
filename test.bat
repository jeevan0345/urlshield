@echo off
title URLShield - Test Suite Runner
echo ========================================================
echo   Running URLShield Pytest Verification Suite
echo ========================================================
echo.

if exist .venv\Scripts\pytest.exe (
    .venv\Scripts\pytest.exe -v
) else (
    pytest -v
)

echo.
pause
