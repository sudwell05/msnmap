@echo off
REM Enhanced Network Scanner Application - Windows Startup Script
REM =============================================================

echo.
echo ============================================================
echo    Enhanced Network Scanner Application
echo ============================================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

echo Python found: 
python --version

REM Check if virtual environment exists
if exist "venv\Scripts\activate.bat" (
    echo.
    echo Activating virtual environment...
    call venv\Scripts\activate.bat
    echo Virtual environment activated
) else (
    echo.
    echo No virtual environment found. Creating one...
    python -m venv venv
    call venv\Scripts\activate.bat
    echo Virtual environment created and activated
    
    echo.
    echo Installing dependencies...
    pip install -r requirements.txt
    if errorlevel 1 (
        echo WARNING: Some dependencies failed to install
        echo The application may not work correctly
    )
)

REM Check if config.env exists
if not exist "config.env" (
    echo.
    echo Creating configuration file...
    (
        echo SECRET_KEY=change-this-in-production
        echo # Optional settings
        echo # SHODAN_API_KEY=your-shodan-key
        echo # NMAP_PATH=C:\\Program Files ^(x86^)\\Nmap\\nmap.exe
        echo # SMAP_PATH=C:\\path\\to\\smap.exe
        echo # MAX_CONCURRENT_SCANS=5
        echo # SCAN_TIMEOUT=3600
    ) > config.env
    echo Configuration file created: config.env
    echo Please edit config.env with your settings if needed
)

REM Create necessary directories
if not exist "logs" mkdir logs
if not exist "scan_results" mkdir scan_results
if not exist "exports" mkdir exports
if not exist "reports" mkdir reports
if not exist "uploads" mkdir uploads

echo.
echo Starting Enhanced Network Scanner Application...
echo.
echo The web interface will automatically open in your browser
echo URL: http://127.0.0.1:5000
echo.
echo Press Ctrl+C to stop the server
echo ============================================================
echo.

REM Start the application
python run.py

echo.
echo Application stopped
pause