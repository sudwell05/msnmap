"""Routes package initialization"""

def register_blueprints(app):
    """Register all blueprints with the Flask application"""
    from .scan_routes import bp as scan_bp
    from .history_routes import bp as history_bp
    from .main_routes import bp as main_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(history_bp)

__all__ = ['register_blueprints']
