# 🔍 Enhanced Network Scanner Application

A comprehensive, production-ready network scanning application built with Python Flask, featuring multiple scanning engines, rich reporting, and a modern web interface.

## ✨ Features

### 🚀 Multiple Scanning Engines
- Nmap: Comprehensive active port scanning with OS detection, service enumeration, and NSE scripts
- Smap: Fast network scanning for quick reconnaissance (optional)
- Shodan: Passive intelligence gathering (requires API key)
- Combined: Use multiple engines simultaneously for comprehensive results

### 🎯 Advanced Scanning Capabilities
- Host discovery and enumeration
- Port scanning with customizable ranges
- Service detection and version identification
- Operating system detection
- NSE script execution
- Customizable timing templates (T1-T5)
- Support for IP ranges, networks, and hostnames

### 📊 Rich Reporting & Export
- HTML Reports: Beautiful, structured reports with statistics
- JSON Export: Machine-readable data format
- CSV Export: Spreadsheet-compatible format
- Real-time Progress: Live scan status and progress tracking

### 🗄️ Scan History Management
- Persistent storage in SQLite database
- Complete scan history with metadata
- Search and filter capabilities
- Bulk operations (cleanup, export all)

### 🌐 Modern Web Interface
- Responsive design with dark/light theme support
- Real-time updates and notifications
- Interactive scan controls (Start/Stop/View/Delete)
- Mobile-friendly interface

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Nmap installed and accessible in PATH
- (Optional) Smap for fast network scanning
- (Optional) Shodan API key

### Easy Installation (Recommended)

#### Windows
```powershell
# 1) Clone or download the project
# 2) Run the setup script
setup.bat
```

#### Linux/macOS
```bash
# 1) Clone or download the project
# 2) Make setup script executable and run
chmod +x setup.sh
./setup.sh
```

#### Manual Installation

#### Windows

```powershell
# 1) Create and activate virtualenv
python -m venv venv
.\venv\Scripts\Activate.ps1

# 2) Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 3) Install Nmap
# Option A: Download from https://nmap.org/download.html
# Option B: Using chocolatey: choco install nmap
# Option C: Using winget: winget install Nmap.Nmap

# 4) Install Smap (optional, for fast scanning)
# Download from: https://github.com/s0md3v/Smap/releases
# Extract and add to PATH, or set SMAP_PATH in config.env
```

#### Linux (Ubuntu/Debian)

```bash
# 1) Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# 2) Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3) Install Nmap
sudo apt update
sudo apt install nmap

# 4) Install Smap (optional)
# Download from: https://github.com/s0md3v/Smap/releases
# chmod +x smap && sudo mv smap /usr/local/bin/
```

#### Linux (CentOS/RHEL/Fedora)

```bash
# 1) Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# 2) Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3) Install Nmap
# CentOS/RHEL: sudo yum install nmap
# Fedora: sudo dnf install nmap

# 4) Install Smap (optional)
# Download from: https://github.com/s0md3v/Smap/releases
# chmod +x smap && sudo mv smap /usr/local/bin/
```

#### macOS

```bash
# 1) Create and activate virtualenv
python3 -m venv venv
source venv/bin/activate

# 2) Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3) Install Nmap
# Option A: Using Homebrew: brew install nmap
# Option B: Using MacPorts: sudo port install nmap

# 4) Install Smap (optional)
# Download from: https://github.com/s0md3v/Smap/releases
# chmod +x smap && sudo mv smap /usr/local/bin/
```

### Configure

#### Windows
```powershell
# Copy the example configuration file
copy config.env.example config.env

# Edit with your values
notepad.exe config.env
```

#### Linux/macOS
```bash
# Copy the example configuration file
cp config.env.example config.env

# Edit with your values
nano config.env
# or
vim config.env
```

Example `config.env` content:

```env
SECRET_KEY=change-this-in-production
# Optional settings
# SHODAN_API_KEY=your-shodan-key

# Windows paths
# NMAP_PATH=C:\\Program Files (x86)\\Nmap\\nmap.exe
# SMAP_PATH=C:\\path\\to\\smap.exe

# Linux/macOS paths
# NMAP_PATH=/usr/bin/nmap
# SMAP_PATH=/usr/local/bin/smap

# General settings
# MAX_CONCURRENT_SCANS=5
# SCAN_TIMEOUT=3600
```

### Run

#### Windows
```powershell
# Run the application
python run.py
# or use the batch file
start.bat
```

#### Linux/macOS
```bash
# Run the application
python3 run.py
# or use the startup script
chmod +x start.sh
./start.sh
```

### Access

- Automatically opens in your default browser
- Default URL: http://127.0.0.1:5000

## 🔧 Configuration

### Environment Variables
- `FLASK_ENV`: Application environment (development/production)
- `DATABASE_URL`: Database connection string (default: SQLite)
- `SHODAN_API_KEY`: Shodan API key for passive scanning
- `NMAP_PATH`: Path to Nmap executable
- `SMAP_PATH`: Path to Smap executable (optional)
- `MAX_CONCURRENT_SCANS`: Maximum simultaneous scans
- `SCAN_TIMEOUT`: Maximum scan duration in seconds

### Scan Options
- **Port Ranges**: Custom port specifications (e.g., "80,443,8080" or "1-1000")
- **Timing Templates**: T1 (Paranoid) to T5 (Insane)
- **NSE Scripts**: Custom script selection for enhanced detection
- **Scan Modes**: Quick, Detailed, or Full port coverage

## 📁 Project Structure

```
agtaramaapp/
├── app/                          # Flask application
│   ├── __init__.py              # Application factory
│   ├── models/                  # Database models
│   ├── routes/                  # API endpoints
│   └── services/                # Business logic
├── scanner_modules/             # Scanning engines
│   ├── nmap_scanner.py         # Nmap integration
│   ├── smap_scanner.py         # Smap integration
│   └── shodan_scanner.py       # Shodan integration
├── static/                      # Frontend assets
│   ├── css/                     # Stylesheets
│   └── js/                      # JavaScript
├── templates/                   # HTML templates
├── config/                      # Configuration
├── logs/                        # Application logs
├── scan_results/                # Scan outputs
├── exports/                     # Report exports
└── reports/                     # Generated reports
```

## 🛡️ Security Features

- Input validation and sanitization
- Rate limiting for API endpoints
- Secure file handling
- CORS configuration
- Environment-based configuration

## 📊 Performance Features

- Asynchronous scan execution
- Concurrent scan support
- Efficient database queries
- Optimized memory usage
- Background task processing

## 🚨 Troubleshooting

### Common Issues

1. **Nmap not found**
   - **Windows**: Ensure Nmap is installed and in PATH, or set `NMAP_PATH` in config.env
   - **Linux**: `sudo apt install nmap` (Ubuntu/Debian) or `sudo yum install nmap` (CentOS/RHEL)
   - **macOS**: `brew install nmap` (Homebrew) or `sudo port install nmap` (MacPorts)

2. **Smap not found**
   - Download Smap from GitHub releases
   - **Windows**: Extract and add to PATH, or set `SMAP_PATH` in config.env
   - **Linux/macOS**: `chmod +x smap && sudo mv smap /usr/local/bin/`

3. **Database errors**
   - Check database permissions
   - Verify `DATABASE_URL` configuration

4. **Permission denied**
   - **Windows**: Run PowerShell as Administrator
   - **Linux/macOS**: Check file/directory access rights, use `sudo` if needed

5. **Scan timeouts**
   - Adjust `SCAN_TIMEOUT` in configuration
   - Use appropriate timing templates

6. **Virtualenv issues**
   - Ensure Python 3.8+ is installed
   - **Windows**: Run PowerShell as Administrator
   - **Linux/macOS**: Ensure python3-venv is installed (`sudo apt install python3-venv`)
   - Dependencies might need specific versions

7. **Python version issues**
   - **Windows**: Use `python` command
   - **Linux/macOS**: Use `python3` command
   - Ensure correct Python version (3.8+)

### Logs
- Application logs: `logs/app.log`
- Scan logs: `logs/scanner.log`
- Check logs for detailed error information

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- Nmap development team for the excellent scanning tool
- Flask community for the robust web framework
- Python community for the rich ecosystem of packages

## 📞 Support

For support and questions:
- Check the documentation
- Open an issue on GitHub
- Check the logs for error details

---

**⚠️ Disclaimer**: This tool is for authorized network testing and security research only. Always ensure you have proper authorization before scanning any network or system.