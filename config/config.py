"""
Configuration settings for the Network Scanner Application
"""
import os
from datetime import timedelta


class Config:
    """Base configuration class"""
    
    # Flask Configuration
    SECRET_KEY = os.environ.get("SECRET_KEY") or "dev-secret-key-change-in-production"
    DEBUG = False
    TESTING = False
    
    # Database Configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///scanner.db"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 300,
    }
    
    # Scan Configuration
    SCAN_OUTPUT_DIR = os.environ.get("SCAN_OUTPUT_DIR") or "scan_results"
    MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "5"))
    SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "3600"))  # 1 hour
    
    # API Configuration
    SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY")
    NMAP_PATH = os.environ.get("NMAP_PATH")
    
    # Logging Configuration
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    LOG_FILE = os.environ.get("LOG_FILE", "logs/scanner.log")
    LOG_MAX_SIZE = int(os.environ.get("LOG_MAX_SIZE", "10485760"))  # 10MB
    LOG_BACKUP_COUNT = int(os.environ.get("LOG_BACKUP_COUNT", "5"))
    
    # Security Configuration
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # File Upload Configuration
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = "uploads"
    ALLOWED_EXTENSIONS = {'txt', 'csv', 'json'}
    
    @staticmethod
    def init_app(app):
        """Initialize application with configuration"""
        # Create necessary directories
        directories = [
            app.config.get("SCAN_OUTPUT_DIR", "scan_results"),
            "logs",
            "reports",
            "exports",
            "uploads"
        ]
        
        for directory in directories:
            try:
                os.makedirs(directory, exist_ok=True)
            except Exception as e:
                print(f"Warning: Could not create directory {directory}: {e}")


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    
    # Development-specific settings
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///scanner_dev.db"
    
    # Enable detailed error pages
    TRAP_HTTP_EXCEPTIONS = True
    TRAP_BAD_REQUEST_ERRORS = True


class TestingConfig(Config):
    """Testing configuration"""
    TESTING = True
    DEBUG = True
    LOG_LEVEL = "DEBUG"
    
    # Use in-memory database for testing
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    
    # Disable CSRF protection for testing
    WTF_CSRF_ENABLED = False
    
    # Use test secret key
    SECRET_KEY = "test-secret-key"
    
    # Disable logging to file during tests
    LOG_FILE = None


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    TESTING = False
    LOG_LEVEL = "INFO"
    
    def __init__(self):
        super().__init__()
        # Check for required environment variables in production
        if not os.environ.get("SECRET_KEY"):
            raise ValueError("SECRET_KEY environment variable must be set in production")
        
        # Production-specific settings
        self.SESSION_COOKIE_SECURE = True
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Strict"
        
        # Use PostgreSQL in production if available
        if os.environ.get("DATABASE_URL"):
            self.SQLALCHEMY_DATABASE_URI = os.environ["DATABASE_URL"]
        
        # Enhanced security settings
        self.PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
        self.MAX_CONCURRENT_SCANS = int(os.environ.get("MAX_CONCURRENT_SCANS", "3"))


# Configuration mapping
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}
