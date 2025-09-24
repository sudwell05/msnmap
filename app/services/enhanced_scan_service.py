"""
Enhanced Scan Service with proper process management
"""
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import signal
import os

from ..models.database import db, Scan, Host, Port, Vulnerability
from scanner_modules.nmap_scanner import NmapScanner
from scanner_modules.smap_scanner import SmapScanner
from scanner_modules.shodan_scanner import ShodanScanner

def utc_now():
    """Get current UTC time"""
    return datetime.now(timezone.utc)

class EnhancedScanService:
    """Enhanced scan service with proper process management"""
    
    def __init__(self, db_session=None, app=None):
        """Initialize the enhanced scan service"""
        self.logger = logging.getLogger(__name__)
        self.db_session = db_session
        self.app = app  # Store Flask app reference
        
        # Initialize scanners
        self.nmap_scanner = NmapScanner()
        self.smap_scanner = SmapScanner()
        self.shodan_scanner = ShodanScanner()
        
        # Active scans tracking with process management
        self.active_scans = {}  # scan_id -> scan_info
        self._lock = threading.Lock()
        # Size thread pool based on configuration/environment for better performance
        try:
            max_scans = None
            if self.app and hasattr(self.app, 'config'):
                max_scans = int(self.app.config.get('MAX_CONCURRENT_SCANS', 5))
            if max_scans is None:
                max_scans = int(os.environ.get('MAX_CONCURRENT_SCANS', '5'))
            max_workers = max(1, min(16, max_scans))
        except Exception:
            max_workers = 5
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # Log scanner availability
        self.logger.info(f"Scanner availability: Nmap={self.nmap_scanner.is_available()}, Smap={self.smap_scanner.is_available()}, Shodan={self.shodan_scanner.is_available()}")
    
    def start_scan(self, scan_config: Dict, targets: List[str]) -> str:
        """Start a new scan with proper process management"""
        try:
            # Generate unique scan ID
            scan_id = str(uuid.uuid4())
            
            # Create output directory
            output_dir = f"scan_results/{scan_id}"
            os.makedirs(output_dir, exist_ok=True)
            
            # Track active scan with process info
            with self._lock:
                self.active_scans[scan_id] = {
                    "scan_id": scan_id,
                    "config": scan_config,
                    "targets": targets,
                    "output_dir": output_dir,
                    "status": "running",
                    "start_time": time.time(),
                    "processes": [],  # List of subprocess handles
                    "thread": None
                }
            
            # Start scan in background thread with app context
            scan_thread = threading.Thread(
                target=self._run_enhanced_scan_with_context,
                args=(scan_id, scan_config, targets, output_dir),
                daemon=True
            )
            
            with self._lock:
                self.active_scans[scan_id]["thread"] = scan_thread
            
            scan_thread.start()
            
            self.logger.info(f"Scan {scan_id} started successfully")
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Failed to start scan: {e}")
            raise
    
    def _create_scan_record(self, scan_id: str, scan_config: Dict, targets: List[str], output_dir: str) -> Scan:
        """Create scan record in database"""
        try:
            # Get a fresh database session for this thread
            from ..models.database import db
            db_session = db.session if db else None
            
            if not db_session:
                self.logger.error("No database session available for scan record creation")
                raise Exception("No database session available")
            
            scan_record = Scan(
                scan_id=scan_id,
                targets=json.dumps(targets),
                ports=scan_config.get("ports", "1-1000"),
                timing=scan_config.get("timing", "T3"),
                scan_type=scan_config.get("scan_type", "nmap"),
                status="running",
                progress=0,
                start_time=utc_now(),
                output_dir=output_dir,
                scan_options=json.dumps(scan_config)
            )
            
            db_session.add(scan_record)
            db_session.commit()
            self.logger.info(f"Scan record created and committed to database: {scan_id}")
            
            return scan_record
            
        except Exception as e:
            self.logger.error(f"Failed to create scan record: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            raise

    def _run_enhanced_scan(self, scan_id: str, scan_config: Dict, targets: List[str], output_dir: str):
        """Run the enhanced scan with proper process management"""
        try:
            self.logger.info(f"Starting enhanced scan {scan_id} for targets: {targets}")
            
            # Create scan record in this thread's database context FIRST
            scan_record = self._create_scan_record(scan_id, scan_config, targets, output_dir)
            self.logger.info(f"Scan record created successfully for {scan_id}")
            
            # Now update scan status (scan record should exist)
            self._update_scan_status(scan_id, "running", 0, "Starting scan...")
            
            # Perform host discovery
            live_hosts = self._discover_hosts(targets, scan_config)
            self._update_scan_status(scan_id, "running", 10, f"Found {len(live_hosts)} live hosts")
            
            if not live_hosts:
                self._update_scan_status(scan_id, "completed", 100, "No live hosts found")
                return
            
            # Perform detailed scanning
            scan_type = scan_config.get("scan_type", "nmap")
            total_hosts = len(live_hosts)
            
            for i, host in enumerate(live_hosts):
                # Check if scan was stopped
                with self._lock:
                    if scan_id not in self.active_scans or self.active_scans[scan_id]["status"] == "stopped":
                        self.logger.info(f"Scan {scan_id} was stopped, aborting")
                        return
                
                try:
                    progress = int(10 + (i / total_hosts) * 80)
                    self._update_scan_status(scan_id, "running", progress, f"Scanning host: {host}")
                    
                    # Perform scan based on type
                    if scan_type == "nmap":
                        self._scan_host_nmap(scan_id, host, scan_config, output_dir)
                    elif scan_type == "smap":
                        self._scan_host_smap(scan_id, host, scan_config, output_dir)
                    elif scan_type == "shodan":
                        self._scan_host_shodan(scan_id, host, scan_config)
                    elif scan_type == "both":
                        # Use both Nmap and Smap if available
                        if self.nmap_scanner:
                            self._scan_host_nmap(scan_id, host, scan_config, output_dir)
                        if self.smap_scanner:
                            self._scan_host_smap(scan_id, host, scan_config, output_dir)
                        if self.shodan_scanner:
                            self._scan_host_shodan(scan_id, host, scan_config)
                    
                except Exception as e:
                    self.logger.error(f"Error scanning host {host}: {e}")
                    continue
            
            # Complete scan
            self._update_scan_status(scan_id, "completed", 100, "Scan completed successfully")
            self.logger.info(f"Enhanced scan {scan_id} completed successfully")
            
        except Exception as e:
            self.logger.error(f"Enhanced scan {scan_id} failed: {e}")
            self._update_scan_status(scan_id, "failed", 0, f"Scan failed: {str(e)}")
        finally:
            # Clean up
            with self._lock:
                if scan_id in self.active_scans:
                    del self.active_scans[scan_id]

    def _run_enhanced_scan_with_context(self, scan_id: str, scan_config: Dict, targets: List[str], output_dir: str):
        """Run the enhanced scan with proper Flask app context"""
        if self.app:
            with self.app.app_context():
                self._run_enhanced_scan(scan_id, scan_config, targets, output_dir)
        else:
            self.logger.warning("No Flask app context available, running scan without context")
            self._run_enhanced_scan(scan_id, scan_config, targets, output_dir)

    def _discover_hosts(self, targets: List[str], scan_config: Dict) -> List[str]:
        """Discover live hosts using available scanners"""
        live_hosts = []
        
        try:
            # For single IP targets, assume they're live and skip discovery
            if len(targets) == 1 and not targets[0].endswith('/24'):
                self.logger.info(f"Single IP target detected: {targets[0]}, skipping host discovery")
                live_hosts = targets
            else:
                # Try different scanners for host discovery
                if self.smap_scanner and self.smap_scanner.is_available():
                    self.logger.info("Using Smap for host discovery...")
                    live_hosts = self._discover_with_smap(targets)
                elif self.nmap_scanner and self.nmap_scanner.is_available():
                    self.logger.info("Using Nmap for host discovery...")
                    live_hosts = self._discover_with_nmap(targets)
                else:
                    # Fallback: assume all targets are live
                    self.logger.info("No scanners available, assuming all targets are live")
                    live_hosts = targets
                
        except Exception as e:
            self.logger.error(f"Host discovery failed: {e}")
            # Fallback: assume all targets are live
            live_hosts = targets
        
        self.logger.info(f"Host discovery completed. Found {len(live_hosts)} live hosts: {live_hosts}")
        return live_hosts

    def _discover_with_nmap(self, targets: List[str]) -> List[str]:
        """Discover hosts using Nmap"""
        live_hosts = []
        for target in targets:
            try:
                result = self.nmap_scanner.host_discovery(target)
                if result and result.get("hosts"):
                    for host in result["hosts"]:
                        if host.get("status") == "up":
                            live_hosts.append(host["ip"])
                else:
                    # If no result, assume target is live
                    live_hosts.append(target)
            except Exception as e:
                self.logger.warning(f"Nmap host discovery failed for {target}: {e}")
                live_hosts.append(target)
        return live_hosts

    def _discover_with_smap(self, targets: List[str]) -> List[str]:
        """Discover hosts using Smap"""
        live_hosts = []
        for target in targets:
            try:
                result = self.smap_scanner.host_discovery(target)
                if result and result.get("hosts"):
                    for host in result["hosts"]:
                        if host.get("status") == "up":
                            live_hosts.append(host["ip"])
                else:
                    # If no result, assume target is live
                    live_hosts.append(target)
            except Exception as e:
                self.logger.warning(f"Smap host discovery failed for {target}: {e}")
                live_hosts.append(target)
        return live_hosts

    def _scan_host_nmap(self, scan_id: str, host: str, scan_config: Dict, output_dir: str):
        """Scan host using Nmap with proper process management"""
        if not self.nmap_scanner:
            return
        
        try:
            # Check if scan was stopped
            with self._lock:
                if scan_id not in self.active_scans or self.active_scans[scan_id]["status"] == "stopped":
                    return
            
            self.logger.info(f"Starting Nmap scan for host {host} with config: {scan_config}")
            
            # Determine scan method based on scan_mode
            scan_mode = scan_config.get("scan_mode", "detailed")
            ports = scan_config.get("ports", "1-1000")
            
            if scan_mode == "quick":
                result = self.nmap_scanner.quick_scan(target=host)
            elif scan_mode == "full":
                result = self.nmap_scanner.full_scan(target=host)
            else:  # detailed
                result = self.nmap_scanner.detailed_scan(
                    target=host,
                    ports=ports,
                    timing=scan_config.get("timing", "T3"),
                    scripts=scan_config.get("scripts")
                )
            
            self.logger.info(f"Nmap scan result for {host}: {result}")
            
            if result and not result.get("error"):
                self.logger.info(f"Saving Nmap results to database for {host}")
                self._save_nmap_results_to_db(scan_id, host, result)
                self.logger.info(f"Successfully saved Nmap results for {host}")
            else:
                self.logger.warning(f"Nmap scan failed or returned error for {host}: {result}")
                
        except Exception as e:
            self.logger.error(f"Nmap scan failed for {host}: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")

    def _scan_host_smap(self, scan_id: str, host: str, scan_config: Dict, output_dir: str):
        """Scan host using Smap with proper process management"""
        if not self.smap_scanner:
            return
        
        try:
            # Check if scan was stopped
            with self._lock:
                if scan_id not in self.active_scans or self.active_scans[scan_id]["status"] == "stopped":
                    return
            
            # Perform detailed Smap scan and track process via Popen interception
            # Best-effort: run a parallel Popen just to track and be able to kill
            import subprocess
            cmd = [
                self.smap_scanner.smap_path,
                '--detailed-scan',
                '--ports', scan_config.get("ports", "1-1000"),
                '--timing', scan_config.get("timing", "T3"),
                '--json',
                host
            ]
            scripts = scan_config.get("scripts")
            if scripts:
                cmd.extend(['--scripts', scripts])

            process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            with self._lock:
                self.active_scans.get(scan_id, {}).setdefault("processes", []).append(process)

            try:
                stdout, stderr = process.communicate(timeout=1800)
            except subprocess.TimeoutExpired:
                try:
                    process.terminate()
                except Exception:
                    pass
                return

            if process.returncode != 0:
                self.logger.warning(f"Smap process failed for {host}: {stderr}")
                return

            try:
                result = json.loads(stdout)
                parsed = self.smap_scanner._parse_smap_output(result)
            except Exception as e:
                self.logger.warning(f"Failed to parse Smap output for {host}: {e}")
                return
            
            if parsed:
                # parsed structure includes hosts list; if scanning single host, flatten
                if parsed.get("hosts"):
                    for h in parsed["hosts"]:
                        if h.get("ip") == host:
                            single = {
                                "status": h.get("status"),
                                "hostname": h.get("hostname"),
                                "os_info": h.get("os_info", {}),
                                "mac_address": h.get("mac_address"),
                                "vendor": h.get("vendor"),
                                "ports": h.get("ports", [])
                            }
                            self._save_smap_results_to_db(scan_id, host, single)
                            break
                else:
                    self._save_smap_results_to_db(scan_id, host, parsed)
                
        except Exception as e:
            self.logger.error(f"Smap scan failed for {host}: {e}")

    def _scan_host_shodan(self, scan_id: str, host: str, scan_config: Dict):
        """Scan host using Shodan with proper process management"""
        if not self.shodan_scanner:
            return
        
        try:
            # Check if scan was stopped
            with self._lock:
                if scan_id not in self.active_scans or self.active_scans[scan_id]["status"] == "stopped":
                    return
            
            # Perform Shodan scan
            result = self.shodan_scanner.search_host(host)
            
            if result:
                self._save_shodan_results_to_db(scan_id, host, result)
                
        except Exception as e:
            self.logger.error(f"Shodan scan failed for {host}: {e}")

    def _save_nmap_results_to_db(self, scan_id: str, host_ip: str, nmap_result: Dict):
        """Save Nmap results to database with comprehensive data"""
        try:
            # Get a fresh database session for this thread
            from ..models.database import db
            db_session = db.session if db else None
            
            if not db_session:
                self.logger.error("No database session available")
                return
            
            self.logger.info(f"Saving Nmap results for {host_ip} to database")
            
            # Create or update host record
            host_record = db_session.query(Host).filter_by(
                scan_id=scan_id, 
                ip_address=host_ip
            ).first()
            
            if not host_record:
                host_record = Host(
                    scan_id=scan_id,
                    ip_address=host_ip,
                    status=nmap_result.get("status", "up"),
                    hostname=nmap_result.get("hostname"),
                    os_info=json.dumps(nmap_result.get("os_info", {})),
                    mac_address=nmap_result.get("mac_address"),
                    vendor=str(nmap_result.get("vendor", "")),
                    scan_time=utc_now()
                )
                db_session.add(host_record)
                db_session.flush()  # Get the ID
                self.logger.info(f"Created host record for {host_ip}")
            else:
                self.logger.info(f"Updated existing host record for {host_ip}")
            
            # Save ports with comprehensive information
            for port_data in nmap_result.get("ports", []):
                port_record = Port(
                    host_id=host_record.id,
                    port_number=port_data["port"],
                    protocol=port_data.get("protocol", "tcp"),
                    state=port_data.get("state", "unknown"),
                    service_name=port_data.get("service", {}).get("name"),
                    service_version=port_data.get("service", {}).get("version"),
                    service_product=port_data.get("service", {}).get("product"),
                    service_extrainfo=port_data.get("service", {}).get("extrainfo"),
                    banner=port_data.get("banner"),
                    script_output=json.dumps(port_data.get("scripts", {})),
                    scan_time=utc_now()
                )
                db_session.add(port_record)
                self.logger.info(f"Added port record: {port_data['port']}/{port_data.get('protocol', 'tcp')}")
            
            db_session.commit()
            self.logger.info(f"Successfully committed Nmap results for {host_ip} to database")
            
        except Exception as e:
            self.logger.error(f"Failed to save Nmap results to database: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            # Try to rollback
            try:
                if db_session:
                    db_session.rollback()
            except:
                pass

    def _save_smap_results_to_db(self, scan_id: str, host_ip: str, smap_result: Dict):
        """Save Smap results to database"""
        try:
            if not self.db_session:
                return
            
            # Create or update host record
            host_record = self.db_session.query(Host).filter_by(
                scan_id=scan_id, 
                ip_address=host_ip
            ).first()
            
            if not host_record:
                host_record = Host(
                    scan_id=scan_id,
                    ip_address=host_ip,
                    status=smap_result.get("status", "up"),
                    hostname=smap_result.get("hostname"),
                    os_info=json.dumps(smap_result.get("os_info", {})),
                    mac_address=smap_result.get("mac_address"),
                    vendor=str(smap_result.get("vendor", "")),
                    scan_time=utc_now()
                )
                self.db_session.add(host_record)
                self.db_session.flush()
            
            # Save ports
            for port_data in smap_result.get("ports", []):
                port_record = Port(
                    host_id=host_record.id,
                    port_number=port_data["port"],
                    protocol=port_data.get("protocol", "tcp"),
                    state=port_data.get("state", "unknown"),
                    service_name=port_data.get("service", {}).get("name"),
                    service_version=port_data.get("service", {}).get("version"),
                    service_product=port_data.get("service", {}).get("product"),
                    service_extrainfo=port_data.get("service", {}).get("extrainfo"),
                    banner=port_data.get("banner"),
                    script_output=json.dumps(port_data.get("scripts", {})),
                    scan_time=utc_now()
                )
                self.db_session.add(port_record)
            
            self.db_session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to save Smap results to database: {e}")

    def _save_shodan_results_to_db(self, scan_id: str, host_ip: str, shodan_result: Dict):
        """Save Shodan results to database"""
        try:
            if not self.db_session:
                return
            
            # Create or update host record
            host_record = self.db_session.query(Host).filter_by(
                scan_id=scan_id, 
                ip_address=host_ip
            ).first()
            
            if not host_record:
                host_record = Host(
                    scan_id=scan_id,
                    ip_address=host_ip,
                    status="up",
                    scan_time=utc_now()
                )
                self.db_session.add(host_record)
                self.db_session.flush()
            
            # Update host information
            if shodan_result.get("hostname"):
                host_record.hostname = shodan_result["hostname"]
            
            if shodan_result.get("os"):
                host_record.os_info = json.dumps({"name": shodan_result["os"]})
            
            # Save ports
            for port_data in shodan_result.get("ports", []):
                port_record = Port(
                    host_id=host_record.id,
                    port_number=port_data["port"],
                    protocol="tcp",
                    state="open",
                    service_name=port_data.get("service"),
                    service_version=port_data.get("version"),
                    service_product=port_data.get("product"),
                    banner=port_data.get("data"),
                    scan_time=utc_now()
                )
                self.db_session.add(port_record)
            
            self.db_session.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to save Shodan results to database: {e}")

    def _update_scan_status(self, scan_id: str, status: str, progress: int, message: str):
        """Update scan status in database"""
        try:
            # Get a fresh database session for this thread
            from ..models.database import db
            db_session = db.session if db else None
            
            if not db_session:
                self.logger.error("No database session available for status update")
                return
            
            scan_record = db_session.query(Scan).filter_by(scan_id=scan_id).first()
            if scan_record:
                scan_record.status = status
                scan_record.progress = progress
                if status in ["completed", "failed", "stopped"]:
                    scan_record.end_time = utc_now()
                
                db_session.commit()
                self.logger.info(f"Updated scan {scan_id} status to {status} with progress {progress}%")
            else:
                self.logger.warning(f"Scan record not found for {scan_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to update scan status: {e}")
            import traceback
            self.logger.error(f"Traceback: {traceback.format_exc()}")
            # Try to rollback
            try:
                if db_session:
                    db_session.rollback()
            except:
                pass

    def get_scan_status(self, scan_id: str) -> Optional[Dict]:
        """Get scan status"""
        try:
            if not self.db_session:
                return None
            
            scan_record = self.db_session.query(Scan).filter_by(scan_id=scan_id).first()
            if scan_record:
                return scan_record.to_dict()
            
            return None
            
        except Exception as e:
            self.logger.error(f"Failed to get scan status: {e}")
            return None

    def get_scan_results(self, scan_id: str) -> Optional[Dict]:
        """Get complete scan results"""
        try:
            if not self.db_session:
                return None
            
            scan_record = self.db_session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan_record:
                return None
            
            # Get hosts
            hosts = []
            for host_record in scan_record.hosts:
                host_data = host_record.to_dict()
                
                # Get ports for this host
                ports = []
                for port_record in host_record.ports:
                    ports.append(port_record.to_dict())
                
                host_data["ports"] = ports
                hosts.append(host_data)
            
            return {
                "scan": scan_record.to_dict(),
                "hosts": hosts
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get scan results: {e}")
            return None

    def list_scans(self) -> List[Dict]:
        """List all scans"""
        try:
            if not self.db_session:
                return []
            
            scans = self.db_session.query(Scan).order_by(Scan.start_time.desc()).all()
            return [scan.to_dict() for scan in scans]
            
        except Exception as e:
            self.logger.error(f"Failed to list scans: {e}")
            return []

    def stop_scan(self, scan_id: str) -> bool:
        """Stop a running scan with proper process termination"""
        try:
            with self._lock:
                if scan_id not in self.active_scans:
                    return False
                
                scan_info = self.active_scans[scan_id]
                scan_info["status"] = "stopped"
                
                # Terminate any running processes
                for process in scan_info.get("processes", []):
                    try:
                        if process and process.poll() is None:  # Process is still running
                            process.terminate()
                            process.wait(timeout=5)  # Wait for graceful shutdown
                    except Exception as e:
                        self.logger.warning(f"Error terminating process: {e}")
                        try:
                            process.kill()  # Force kill if needed
                        except:
                            pass
                
                # Update database status
                self._update_scan_status(scan_id, "stopped", 0, "Scan stopped by user")
                
                # Remove from active scans
                del self.active_scans[scan_id]
            
            self.logger.info(f"Scan {scan_id} stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to stop scan: {e}")
            return False

    def delete_scan(self, scan_id: str) -> bool:
        """Delete a scan and all its data"""
        try:
            # Stop scan if running
            if scan_id in self.active_scans:
                self.stop_scan(scan_id)
            
            if not self.db_session:
                return False
            
            scan_record = self.db_session.query(Scan).filter_by(scan_id=scan_id).first()
            if scan_record:
                self.db_session.delete(scan_record)
                self.db_session.commit()
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to delete scan: {e}")
            return False

    def get_available_scanners(self) -> Dict[str, bool]:
        """Get information about available scanners"""
        return {
            "nmap": self.nmap_scanner is not None and self.nmap_scanner.is_available(),
            "smap": self.smap_scanner is not None and self.smap_scanner.is_available(),
            "shodan": self.shodan_scanner is not None and self.shodan_scanner.is_available()
        }

    def get_active_scans(self) -> List[Dict]:
        """Get list of active scans"""
        with self._lock:
            return [
                {
                    "scan_id": scan_id,
                    "status": info["status"],
                    "start_time": info["start_time"],
                    "targets": info["targets"]
                }
                for scan_id, info in self.active_scans.items()
            ]

    def cleanup_completed_scans(self) -> int:
        """Clean up completed, failed, and stopped scans"""
        try:
            if not self.db_session:
                return 0
            
            # Find scans to clean up
            scans_to_cleanup = self.db_session.query(Scan).filter(
                Scan.status.in_(["completed", "failed", "stopped"])
            ).all()
            
            count = len(scans_to_cleanup)
            
            for scan in scans_to_cleanup:
                self.db_session.delete(scan)
            
            self.db_session.commit()
            self.logger.info(f"Cleaned up {count} completed scans")
            return count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup scans: {e}")
            return 0
