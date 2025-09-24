"""
Main routes for serving the web interface
"""
from flask import Blueprint, render_template, current_app
import os

bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    """Serve the main application page"""
    try:
        return render_template('index.html')
    except Exception as e:
        current_app.logger.error(f"Error rendering index template: {e}")
        return f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Enhanced Network Scanner - Error</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .error {{ color: red; }}
                .info {{ color: blue; }}
            </style>
        </head>
        <body>
            <h1>Enhanced Network Scanner Application</h1>
            <div class="error">
                <h2>Template Error</h2>
                <p>There was an error loading the main template: {e}</p>
            </div>
            <div class="info">
                <h3>Available Routes:</h3>
                <ul>
                    <li><a href="/api/scan/active">Active Scans</a></li>
                    <li><a href="/api/history/scans">Scan History</a></li>
                </ul>
            </div>
        </body>
        </html>
        """, 500

@bp.route('/health')
def health():
    """Health check endpoint"""
    return {'status': 'healthy', 'service': 'Enhanced Network Scanner'}

@bp.route('/favicon.ico')
def favicon():
    """Serve favicon or return 204"""
    return '', 204
