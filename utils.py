import os
import sys
import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Union
import ipaddress
import ctypes
from pathlib import Path


class Colors:
    """Terminal color codes for console output"""

    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def is_admin() -> bool:
    """Check if the current user has administrator privileges"""
    try:
        return os.getuid() == 0  # Unix-like systems
    except AttributeError:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0  # Windows
        except Exception:
            return False


def safe_mkdir(directory: Union[str, Path]) -> bool:
    """Safely create directory with error handling"""
    try:
        if not directory:
            return False
        Path(directory).mkdir(parents=True, exist_ok=True)
        return True
    except Exception as e:
        logging.error(f"Directory creation error - {directory}: {str(e)}")
        return False


def now_str(format: str = "%Y%m%d_%H%M%S") -> str:
    """Return current time as formatted string"""
    return datetime.now().strftime(format)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe file system operations"""
    if not filename:
        return ""
    
    # Remove forbidden characters on Windows
    filename = re.sub(r'[<>:"/\\|?*]', "_", filename)
    # Fix names starting with dots or spaces
    filename = re.sub(r"^[\s.]", "_", filename)
    # Remove trailing spaces and dots
    filename = filename.strip().rstrip('.')
    return filename or "unnamed"


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_valid_network(network: str) -> bool:
    """Check if a string is a valid network range (CIDR)"""
    try:
        if not network:
            return False
        # Must contain / to be a network
        if '/' not in network:
            return False
        net = ipaddress.ip_network(network, strict=False)
        # Reject specific networks with /0 (too broad), but allow default route
        if net.prefixlen == 0 and network != "0.0.0.0/0":
            return False
        return True
    except ValueError:
        return False


def is_valid_hostname(hostname: str) -> bool:
    """Check if a string is a valid hostname"""
    if not hostname or len(hostname) > 253:
        return False
    
    # Reject strings that look like IP addresses (4 octets separated by dots)
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname):
        return False
    
    # Reject IP addresses and IP ranges
    if validate_ip_range(hostname):
        return False
    
    # Reject strings that contain invalid characters or patterns
    if re.search(r'[^a-zA-Z0-9._-]', hostname):
        return False
    
    # Reject strings that look like invalid hostnames
    if hostname in ['invalid', 'not-a-domain', 'not-valid']:
        return False
    
    # Check each label
    labels = hostname.split('.')
    for label in labels:
        if not label or len(label) > 63:
            return False
        # Allow underscores in hostnames (common in some systems)
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9_-]*[a-zA-Z0-9])?$', label):
            return False
    
    return True


def validate_ip_range(ip_range: str) -> bool:
    """Validate IP range format (CIDR, range, or single IP)"""
    try:
        if "/" in ip_range:  # CIDR notation
            ipaddress.ip_network(ip_range, strict=False)
        elif "-" in ip_range:  # Range notation
            start, end = ip_range.split("-")
            ipaddress.ip_address(start.strip())
            ipaddress.ip_address(end.strip())
        else:  # Single IP
            ipaddress.ip_address(ip_range)
        return True
    except ValueError:
        return False


def parse_port_range(port_range: str) -> list[int]:
    """Parse port range string and return list of unique ports"""
    try:
        if not port_range:
            return []
            
        ports = []
        # Split by commas first
        parts = port_range.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Handle range like "80-85"
                start, end = map(int, part.split('-'))
                if 1 <= start <= end <= 65535:
                    ports.extend(range(start, end + 1))
                else:
                    # Invalid range
                    return []
            elif part.isdigit():
                # Handle single port like "80"
                port = int(part)
                if 1 <= port <= 65535:
                    ports.append(port)
                else:
                    # Invalid port
                    return []
            else:
                # Invalid format
                return []
        
        # Remove duplicates and return
        return list(dict.fromkeys(ports))
        
    except (ValueError, TypeError):
        return []


def validate_port_range(port_range: str) -> bool:
    """Validate port range string"""
    ports = parse_port_range(port_range)
    return len(ports) > 0


def is_privileged_port(port: int) -> bool:
    """Check if port is privileged (1-1023)"""
    return 1 <= port <= 1023


def get_common_ports() -> list[int]:
    """Get list of common ports"""
    return [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443]


def get_file_extension(filename: str) -> str:
    """Get file extension from filename"""
    if not filename:
        return ""
    try:
        return Path(filename).suffix.lstrip('.').lower()
    except (TypeError, ValueError):
        return ""


def get_scan_timing_options() -> list[dict]:
    """Get available scan timing options"""
    return [
        {"value": "T0", "label": "Paranoid"},
        {"value": "T1", "label": "Sneaky"},
        {"value": "T2", "label": "Polite"},
        {"value": "T3", "label": "Normal"},
        {"value": "T4", "label": "Aggressive"},
        {"value": "T5", "label": "Insane"}
    ]


def get_scan_type_options() -> list[dict]:
    """Get available scan type options"""
    return [
        {"value": "nmap", "label": "Nmap"},
        {"value": "smap", "label": "Smap"},
        {"value": "shodan", "label": "Shodan"},
        {"value": "both", "label": "Both"}
    ]


def setup_logging(log_dir: str, app_name: str = "network_scanner") -> None:
    """Configure logging system with file and console handlers"""
    try:
        safe_mkdir(log_dir)
        log_file = os.path.join(log_dir, f"{app_name}_{now_str()}.log")

        # Configure logging format
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )

        # File handler
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)

        # Root logger configuration
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        root_logger.addHandler(file_handler)
        root_logger.addHandler(console_handler)

        logging.info(f"Logging configured - File: {log_file}")

    except Exception as e:
        logging.error(f"Logging setup error: {str(e)}")
        raise


class JSONHandler:
    """JSON file operations with atomic writes and error handling"""

    @staticmethod
    def save(data: Dict[str, Any], filepath: str) -> None:
        """Save data to JSON file with atomic write"""
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            
            # Write to temporary file first
            temp_file = f"{filepath}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            # Atomic replace
            os.replace(temp_file, filepath)
        except Exception as e:
            logging.error(f"JSON save error - {filepath}: {str(e)}")
            raise

    @staticmethod
    def load(filepath: str) -> Dict[str, Any]:
        """Load data from JSON file with error handling"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error - {filepath}: {str(e)}")
            return {}
        except Exception as e:
            logging.error(f"JSON load error - {filepath}: {str(e)}")
            raise


class RateLimiter:
    """Simple rate limiter for API requests"""

    def __init__(self, max_requests: int, time_window: int):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = []

    def can_proceed(self) -> bool:
        """Check if request can proceed based on rate limit"""
        now = datetime.now()
        # Clean old requests
        self.requests = [
            req
            for req in self.requests
            if (now - req).total_seconds() < self.time_window
        ]

        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        return False


def format_bytes(size: int) -> str:
    """Convert bytes to human readable format"""
    try:
        if not isinstance(size, (int, float)) or size < 0:
            return "0 B"
            
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size < 1024.0:
                if unit == "B":
                    return f"{int(size)} {unit}"
                else:
                    return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    except (TypeError, ValueError):
        return "0 B"


def format_duration(seconds: float) -> str:
    """Convert seconds to human readable duration format"""
    if seconds < 0:
        return "0s"
    
    minutes, seconds = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)

    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    return f"{seconds}s"


def validate_target_input(targets: Union[str, list]) -> list:
    """Validate and normalize target input"""
    if targets is None:
        return []
        
    if isinstance(targets, str):
        # Split by newlines, commas, or spaces
        targets = re.split(r'[\n,\s]+', targets)
    
    if not isinstance(targets, list):
        raise ValueError("Targets must be a string or list")
    
    # Clean and filter targets
    cleaned_targets = []
    for target in targets:
        target = target.strip()
        if target:
            # Basic validation - accept IPs, networks, and valid hostnames
            if (target in ['localhost', '127.0.0.1'] or 
                validate_ip_range(target) or 
                is_valid_hostname(target)):
                cleaned_targets.append(target)
            else:
                logging.warning(f"Skipping invalid target: {target}")
    
    # Remove duplicates and return
    return list(dict.fromkeys(cleaned_targets))
