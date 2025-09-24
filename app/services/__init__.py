"""Services package initialization"""

# Note: Services are now imported directly where needed
# This file is kept for package structure but doesn't import specific services

def init_services(app):
    """Initialize application services with app configuration"""
    # Services are now initialized per-request, not globally
    # This function is kept for compatibility but doesn't create global instances
    pass

__all__ = ['init_services']
