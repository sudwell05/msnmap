@echo off
echo 🔍 Enhanced Network Scanner - Windows Setup
echo ==========================================

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)

echo ✅ Python found
echo.

REM Run the setup script
echo Running setup script...
python setup.py

if errorlevel 1 (
    echo.
    echo ❌ Setup failed
    pause
    exit /b 1
)

echo.
echo 🎉 Setup completed!
echo.
echo To start the application:
echo 1. Activate virtual environment: .\venv\Scripts\Activate.ps1
echo 2. Run application: python run.py
echo.
pause
