#!/bin/bash

echo "🔍 Enhanced Network Scanner - Linux/macOS Setup"
echo "=============================================="

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed or not in PATH"
    echo "Please install Python 3.8+ from your package manager"
    exit 1
fi

echo "✅ Python found: $(python3 --version)"
echo

# Make setup.py executable and run it
chmod +x setup.py
python3 setup.py

if [ $? -ne 0 ]; then
    echo
    echo "❌ Setup failed"
    exit 1
fi

echo
echo "🎉 Setup completed!"
echo
echo "To start the application:"
echo "1. Activate virtual environment: source venv/bin/activate"
echo "2. Run application: python3 run.py"
echo
