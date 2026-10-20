@echo off
title URLShield - Phishing Intelligence Dashboard
echo ========================================================
echo   Starting URLShield Phishing Intelligence Dashboard
echo ========================================================
echo.

if exist .venv\Scripts\python.exe (
    echo [OK] Using virtual environment (.venv)
    echo [INFO] Access the web UI at: http://localhost:5000
    echo [INFO] Press Ctrl+C to stop the server
    echo.
    .venv\Scripts\python.exe run.py
) else (
    echo [WARN] Virtual environment not found, attempting system python...
    python run.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Application stopped with an error.
    pause
)
