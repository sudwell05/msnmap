#!/usr/bin/env python3
"""
Setup script for Enhanced Network Scanner Application
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    if sys.version_info < (3, 8):
        print("❌ Error: Python 3.8 or higher is required")
        print(f"Current version: {sys.version}")
        return False
    print(f"✅ Python version: {sys.version.split()[0]}")
    return True

def check_nmap():
    """Check if Nmap is installed"""
    nmap_paths = ['nmap', 'nmap.exe']
    
    for path in nmap_paths:
        if shutil.which(path):
            print(f"✅ Nmap found: {path}")
            return True
    
    print("❌ Nmap not found in PATH")
    print("Please install Nmap:")
    print("  Windows: Download from https://nmap.org/download.html")
    print("  Linux: sudo apt install nmap (Ubuntu/Debian)")
    print("  macOS: brew install nmap (Homebrew)")
    return False

def create_virtual_env():
    """Create virtual environment"""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return True
    
    try:
        print("Creating virtual environment...")
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✅ Virtual environment created")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to create virtual environment")
        return False

def get_pip_command():
    """Get the correct pip command for the virtual environment"""
    if os.name == 'nt':  # Windows
        return str(Path("venv/Scripts/pip.exe"))
    else:  # Linux/macOS
        return str(Path("venv/bin/pip"))

def install_dependencies():
    """Install Python dependencies"""
    pip_cmd = get_pip_command()
    
    if not Path(pip_cmd).exists():
        print("❌ Virtual environment not found")
        return False
    
    try:
        print("Installing dependencies...")
        subprocess.run([pip_cmd, "install", "--upgrade", "pip"], check=True)
        subprocess.run([pip_cmd, "install", "-r", "requirements.txt"], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to install dependencies")
        return False

def create_config_file():
    """Create config.env from example if it doesn't exist"""
    config_path = Path("config.env")
    example_path = Path("config.env.example")
    
    if config_path.exists():
        print("✅ config.env already exists")
        return True
    
    if not example_path.exists():
        print("❌ config.env.example not found")
        return False
    
    try:
        shutil.copy(example_path, config_path)
        print("✅ config.env created from example")
        print("⚠️  Please edit config.env with your settings before running the application")
        return True
    except Exception as e:
        print(f"❌ Failed to create config.env: {e}")
        return False

def create_directories():
    """Create necessary directories"""
    directories = ["logs", "scan_results", "reports", "exports", "uploads"]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
    
    print("✅ Required directories created")
    return True

def main():
    """Main setup function"""
    print("🔍 Enhanced Network Scanner - Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check Nmap
    if not check_nmap():
        print("\n⚠️  Warning: Nmap is required for scanning functionality")
        print("You can continue setup and install Nmap later")
    
    # Create virtual environment
    if not create_virtual_env():
        return False
    
    # Install dependencies
    if not install_dependencies():
        return False
    
    # Create config file
    if not create_config_file():
        return False
    
    # Create directories
    if not create_directories():
        return False
    
    print("\n" + "=" * 40)
    print("🎉 Setup completed successfully!")
    print("\nNext steps:")
    print("1. Edit config.env with your settings")
    print("2. Activate virtual environment:")
    
    if os.name == 'nt':  # Windows
        print("   .\\venv\\Scripts\\Activate.ps1")
        print("3. Run the application:")
        print("   python run.py")
    else:  # Linux/macOS
        print("   source venv/bin/activate")
        print("3. Run the application:")
        print("   python3 run.py")
    
    print("\nFor more information, see README.md")
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
