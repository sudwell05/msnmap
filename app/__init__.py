"""
Flask Application Factory
"""
from flask import Flask
from flask_cors import CORS
import os
import logging
from logging.handlers import RotatingFileHandler

def create_app(config_object=None):
    """Application factory function"""
    # Get the current directory and set template folder
    current_dir = os.path.dirname(os.path.abspath(__file__))
    template_dir = os.path.join(os.path.dirname(current_dir), 'templates')
    static_dir = os.path.join(os.path.dirname(current_dir), 'static')
    
    app = Flask(__name__, 
                template_folder=template_dir,
                static_folder=static_dir)
    
    # Load configuration
    if config_object:
        app.config.from_object(config_object)
    else:
        # Default configuration with fallbacks
        app.config.update(
            SECRET_KEY=os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production'),
            SCAN_OUTPUT_DIR=os.environ.get('SCAN_OUTPUT_DIR', os.path.join(os.getcwd(), 'scan_results')),
            SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL', 'sqlite:///scanner.db'),
            SQLALCHEMY_TRACK_MODIFICATIONS=False,
            SHODAN_API_KEY=os.environ.get('SHODAN_API_KEY'),
            DEBUG=os.environ.get('FLASK_DEBUG', 'False').lower() == 'true',
            LOG_LEVEL=os.environ.get('LOG_LEVEL', 'INFO'),
            MAX_CONCURRENT_SCANS=int(os.environ.get('MAX_CONCURRENT_SCANS', '5')),
            SCAN_TIMEOUT=int(os.environ.get('SCAN_TIMEOUT', '3600')),
            NMAP_PATH=os.environ.get('NMAP_PATH')
        )
    
    # Initialize database
    try:
        from .models.database import init_db
        init_db(app)
        app.logger.info("Database initialized successfully")
    except Exception as e:
        app.logger.error(f"Database initialization failed: {e}")
    
    # Setup logging
    setup_logging(app)
    
    # Enable CORS
    CORS(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Create necessary directories
    create_directories(app)
    
    app.logger.info("Flask application created successfully")
    return app


def setup_logging(app):
    """Setup application logging"""
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        logs_dir = 'logs'
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir, exist_ok=True)
        
        # File handler
        file_handler = RotatingFileHandler(
            os.path.join(logs_dir, 'app.log'), 
            maxBytes=10240000, 
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        
        app.logger.setLevel(logging.INFO)
        app.logger.info('Scanner startup')


def register_blueprints(app):
    """Register Flask blueprints"""
    try:
        from .routes import register_blueprints as register_routes
        register_routes(app)
        app.logger.info("All blueprints registered successfully")
    except Exception as e:
        app.logger.error(f"Failed to register blueprints: {e}")
        # Fallback to direct registration
        try:
            from .routes.scan_routes import bp as scan_bp
            app.register_blueprint(scan_bp)
            app.logger.info("Scan routes registered (fallback)")
        except Exception as e2:
            app.logger.error(f"Failed to register scan routes (fallback): {e2}")
        
        try:
            from .routes.history_routes import bp as history_bp
            app.register_blueprint(history_bp)
            app.logger.info("History routes registered (fallback)")
        except Exception as e2:
            app.logger.error(f"Failed to register history routes (fallback): {e2}")
        
        try:
            from .routes.main_routes import bp as main_bp
            app.register_blueprint(main_bp)
            app.logger.info("Main routes registered (fallback)")
        except Exception as e2:
            app.logger.error(f"Failed to register main routes (fallback): {e2}")


def register_error_handlers(app):
    """Register error handlers"""
    @app.errorhandler(404)
    def not_found_error(error):
        return {'error': 'Not found'}, 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return {'error': 'Internal server error'}, 500
    
    @app.errorhandler(400)
    def bad_request_error(error):
        return {'error': 'Bad request'}, 400


def create_directories(app):
    """Create necessary directories"""
    directories = [
        app.config.get('SCAN_OUTPUT_DIR', 'scan_results'),
        'logs',
        'exports',
        'uploads',
        'reports'
    ]
    
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
            app.logger.info(f"Created directory: {directory}")
        except Exception as e:
            app.logger.warning(f"Could not create directory {directory}: {e}")
