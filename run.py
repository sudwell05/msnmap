#!/usr/bin/env python3
"""
Network Scanner Flask Application Entry Point
"""
import os
import sys
import webbrowser
import threading
import time
import logging
from app import create_app
from config.config import config


def load_env_file(env_path: str = "config.env") -> None:
    """Load environment variables from a simple KEY=VALUE file if it exists.
    Lines starting with # or empty lines are ignored. Existing os.environ keys are preserved.
    """
    try:
        if not os.path.exists(env_path):
            return
        with open(env_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception as e:
        print(f"Warning: Could not load environment from {env_path}: {e}")


def open_browser(host: str, port: int, delay: float = 1.5):
    """Open web browser after a short delay with error handling"""
    try:
        time.sleep(delay)
        url = f'http://{host}:{port}'
        webbrowser.open(url)
        print(f"Opened browser at: {url}")
    except Exception as e:
        print(f"Warning: Could not open browser automatically: {e}")
        print(f"Please manually open: http://{host}:{port}")


def setup_environment():
    """Setup environment variables and configuration"""
    # Load from config.env first (does not override existing env vars)
    load_env_file("config.env")

    # Set default environment if not already set
    if not os.environ.get('FLASK_ENV'):
        os.environ['FLASK_ENV'] = 'development'
    
    # Set default host and port if not already set
    if not os.environ.get('FLASK_HOST'):
        os.environ['FLASK_HOST'] = '127.0.0.1'
    
    if not os.environ.get('FLASK_PORT'):
        os.environ['FLASK_PORT'] = '5000'


def main():
    """Main application entry point with comprehensive error handling"""
    try:
        # Setup environment
        setup_environment()
        
        # Get configuration
        config_name = os.environ.get('FLASK_ENV', 'default')
        host = os.environ.get('FLASK_HOST', '127.0.0.1')
        port = int(os.environ.get('FLASK_PORT', 5000))
        
        # Create Flask application
        try:
            app = create_app(config[config_name])
        except Exception as e:
            print(f"Error creating Flask application: {e}")
            sys.exit(1)
        
        # Print startup information
        print("=" * 60)
        print("Network Scanner Application")
        print("=" * 60)
        print(f"Environment: {config_name}")
        print(f"Debug mode: {app.config.get('DEBUG', False)}")
        print(f"Scan output directory: {app.config.get('SCAN_OUTPUT_DIR', 'Not set')}")
        print(f"Web interface: http://{host}:{port}")
        print("=" * 60)
        
        # Start browser opening in background thread
        if host in ['127.0.0.1', 'localhost', '0.0.0.0']:
            browser_thread = threading.Thread(
                target=open_browser, 
                args=(host, port),
                daemon=True
            )
            browser_thread.start()
        
        return app, host, port
        
    except Exception as e:
        print(f"Error during application startup: {e}")
        sys.exit(1)


if __name__ == "__main__":
    try:
        app, host, port = main()
        
        print(f"\nStarting server on {host}:{port}...")
        print("Press Ctrl+C to stop the server")
        print("-" * 60)
        
        app.run(
            host=host,
            port=port,
            debug=False,  # Disable debug mode to prevent double browser opening
            use_reloader=False  # Disable reloader to prevent issues with multiprocessing
        )
        
    except KeyboardInterrupt:
        print("\n" + "=" * 60)
        print("Shutting down Network Scanner Application...")
        print("=" * 60)
    except Exception as e:
        print(f"\nError starting application: {e}")
        sys.exit(1)
