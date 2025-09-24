from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.ext.mutable import MutableDict
import json

db = SQLAlchemy()

def utc_now():
    """Get current UTC time"""
    return datetime.now(timezone.utc)

class Scan(db.Model):
    """Database model for storing scan information"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), unique=True, nullable=False, index=True)
    targets = db.Column(db.Text, nullable=False)  # JSON string of targets
    ports = db.Column(db.String(100), default="1-1000")
    timing = db.Column(db.String(10), default="T3")
    scan_type = db.Column(db.String(20), default="nmap")  # nmap, shodan, or both
    status = db.Column(db.String(20), default="pending")  # pending, running, completed, failed, stopped
    progress = db.Column(db.Integer, default=0)
    start_time = db.Column(db.DateTime, default=utc_now)
    end_time = db.Column(db.DateTime)
    output_dir = db.Column(db.String(500))
    error_message = db.Column(db.Text)
    scan_options = db.Column(db.Text)  # Store as JSON string for SQLite compatibility
    
    # Relationships
    hosts = db.relationship('Host', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Scan {self.scan_id}>'
    
    def to_dict(self):
        """Convert scan to dictionary"""
        # Normalize JSON/text fields to Python objects
        try:
            parsed_targets = json.loads(self.targets) if isinstance(self.targets, str) else self.targets
        except Exception:
            parsed_targets = self.targets
        try:
            parsed_scan_options = json.loads(self.scan_options) if isinstance(self.scan_options, str) else self.scan_options
        except Exception:
            parsed_scan_options = self.scan_options

        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'targets': parsed_targets,
            'ports': self.ports,
            'timing': self.timing,
            'scan_type': self.scan_type,
            'status': self.status,
            'progress': self.progress,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'output_dir': self.output_dir,
            'error_message': self.error_message,
            'scan_options': parsed_scan_options,
            'hosts_count': len(self.hosts)
        }

class Host(db.Model):
    """Database model for storing host information"""
    __tablename__ = 'hosts'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.scan_id'), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    hostname = db.Column(db.String(255))
    status = db.Column(db.String(20), default="up")
    os_info = db.Column(db.Text)  # Store as JSON string for SQLite compatibility
    mac_address = db.Column(db.String(17))
    vendor = db.Column(db.String(255))
    scan_time = db.Column(db.DateTime, default=utc_now)
    
    # Relationships
    ports = db.relationship('Port', backref='host', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Host {self.ip_address}>'
    
    def to_dict(self):
        """Convert host to dictionary"""
        try:
            parsed_os_info = json.loads(self.os_info) if isinstance(self.os_info, str) else self.os_info
        except Exception:
            parsed_os_info = self.os_info
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'status': self.status,
            'os_info': parsed_os_info,
            'mac_address': self.mac_address,
            'vendor': self.vendor,
            'scan_time': self.scan_time.isoformat() if self.scan_time else None,
            'ports_count': len(self.ports),
            'open_ports_count': len([p for p in self.ports if p.state == 'open'])
        }

class Port(db.Model):
    """Database model for storing port information"""
    __tablename__ = 'ports'
    
    id = db.Column(db.Integer, primary_key=True)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    state = db.Column(db.String(20), default="closed")
    service_name = db.Column(db.String(100))
    service_version = db.Column(db.String(255))
    service_product = db.Column(db.String(255))
    service_extrainfo = db.Column(db.Text)
    banner = db.Column(db.Text)
    script_output = db.Column(db.Text)  # Store as JSON string for SQLite compatibility
    scan_time = db.Column(db.DateTime, default=utc_now)
    
    def __repr__(self):
        return f'<Port {self.port_number}/{self.protocol}>'
    
    def to_dict(self):
        """Convert port to dictionary"""
        try:
            parsed_script_output = json.loads(self.script_output) if isinstance(self.script_output, str) else self.script_output
        except Exception:
            parsed_script_output = self.script_output
        return {
            'id': self.id,
            'host_id': self.host_id,
            'port_number': self.port_number,
            'protocol': self.protocol,
            'state': self.state,
            'service_name': self.service_name,
            'service_version': self.service_version,
            'service_product': self.service_product,
            'service_extrainfo': self.service_extrainfo,
            'banner': self.banner,
            'script_output': parsed_script_output,
            'scan_time': self.scan_time.isoformat() if self.scan_time else None
        }

class Vulnerability(db.Model):
    """Database model for storing vulnerability information"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.String(50), db.ForeignKey('scans.scan_id'), nullable=False)
    host_id = db.Column(db.Integer, db.ForeignKey('hosts.id'), nullable=False)
    port_id = db.Column(db.Integer, db.ForeignKey('ports.id'))
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    severity = db.Column(db.String(20), default="medium")
    cve_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    # Store as text for SQLite portability; JSON is normalized in to_dict
    references = db.Column(db.Text)
    discovered_at = db.Column(db.DateTime, default=utc_now)
    
    def __repr__(self):
        return f'<Vulnerability {self.title}>'
    
    def to_dict(self):
        """Convert vulnerability to dictionary"""
        try:
            parsed_refs = json.loads(self.references) if isinstance(self.references, str) else self.references
        except Exception:
            parsed_refs = self.references
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'host_id': self.host_id,
            'port_id': self.port_id,
            'title': self.title,
            'description': self.description,
            'severity': self.severity,
            'cve_id': self.cve_id,
            'cvss_score': self.cvss_score,
            'references': parsed_refs,
            'discovered_at': self.discovered_at.isoformat() if self.discovered_at else None
        }

def init_db(app):
    """Initialize database with Flask app"""
    db.init_app(app)
    with app.app_context():
        db.create_all()
        print("Database initialized successfully")

def get_db():
    """Get database instance"""
    return db
