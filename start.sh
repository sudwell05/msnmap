#!/bin/bash
# Enhanced Network Scanner Application - Linux/macOS Startup Script
# =============================================================

echo ""
echo "============================================================"
echo "    Enhanced Network Scanner Application"
echo "============================================================"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

echo "Python found:"
python3 --version

# Check if virtual environment exists
if [ -f "venv/bin/activate" ]; then
    echo ""
    echo "Activating virtual environment..."
    source venv/bin/activate
    echo "Virtual environment activated"
else
    echo ""
    echo "No virtual environment found. Creating one..."
    python3 -m venv venv
    source venv/bin/activate
    echo "Virtual environment created and activated"
    
    echo ""
    echo "Installing dependencies..."
    pip install --upgrade pip
    pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "WARNING: Some dependencies failed to install"
        echo "The application may not work correctly"
    fi
fi

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo ""
    echo "Creating configuration file..."
    cat > config.env << EOF
SECRET_KEY=change-this-in-production
# Optional settings
# SHODAN_API_KEY=your-shodan-key

# Linux/macOS paths
# NMAP_PATH=/usr/bin/nmap
# SMAP_PATH=/usr/local/bin/smap

# General settings
# MAX_CONCURRENT_SCANS=5
# SCAN_TIMEOUT=3600
EOF
    echo "Configuration file created: config.env"
    echo "Please edit config.env with your settings if needed"
fi

# Create necessary directories
mkdir -p logs scan_results exports reports uploads

echo ""
echo "Starting Enhanced Network Scanner Application..."
echo ""
echo "The web interface will automatically open in your browser"
echo "URL: http://127.0.0.1:5000"
echo ""
echo "Press Ctrl+C to stop the server"
echo "============================================================"
echo ""

# Start the application
python3 run.py

echo ""
echo "Application stopped"