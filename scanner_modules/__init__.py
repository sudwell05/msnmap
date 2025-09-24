"""Scanner modules package"""
from .nmap_scanner import NmapScanner
from .shodan_scanner import ShodanScanner

# Try to import SmapScanner if it exists
try:
    from .smap_scanner import SmapScanner
except ImportError:
    SmapScanner = None

__all__ = [
    'NmapScanner',
    'ShodanScanner',
    'SmapScanner'
]
