"""
Smap Scanner Module for fast network scanning
"""
import os
import json
import logging
import subprocess
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class SmapScanner:
    """Smap scanner for fast network scanning"""
    
    def __init__(self, smap_path: str = None):
        """Initialize Smap scanner"""
        self.smap_path = smap_path or os.environ.get('SMAP_PATH', 'smap')
        self.available = self._check_availability()
        
        if self.available:
            logger.info("Smap scanner initialized successfully")
        else:
            logger.warning("Smap scanner not available")
    
    def _check_availability(self) -> bool:
        """Check if Smap is available on the system"""
        try:
            result = subprocess.run(
                [self.smap_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False
    
    def is_available(self) -> bool:
        """Check if Smap scanning is available"""
        return self.available
    
    def host_discovery(self, target: str) -> Optional[Dict[str, Any]]:
        """Perform host discovery using Smap"""
        if not self.is_available():
            logger.error("Smap scanner not available")
            return None
        
        try:
            logger.info(f"Performing Smap host discovery for: {target}")
            
            # Run Smap host discovery
            cmd = [
                self.smap_path,
                '--host-discovery',
                '--json',
                target
            ]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=300)
            if process.returncode != 0:
                logger.error(f"Smap host discovery failed: {stderr}")
                return None

            try:
                output = json.loads(stdout)
                return self._parse_smap_output(output)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Smap output: {e}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Smap host discovery timed out")
            return None
        except Exception as e:
            logger.error(f"Smap host discovery error: {e}")
            return None
    
    def quick_scan(self, target: str, ports: str = "1-1000") -> Optional[Dict[str, Any]]:
        """Perform quick scan using Smap"""
        if not self.is_available():
            logger.error("Smap scanner not available")
            return None
        
        try:
            logger.info(f"Performing Smap quick scan for: {target}")
            
            # Run Smap quick scan
            cmd = [
                self.smap_path,
                '--quick-scan',
                '--ports', ports,
                '--json',
                target
            ]

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=600)
            if process.returncode != 0:
                logger.error(f"Smap quick scan failed: {stderr}")
                return None

            try:
                output = json.loads(stdout)
                return self._parse_smap_output(output)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Smap output: {e}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Smap quick scan timed out")
            return None
        except Exception as e:
            logger.error(f"Smap quick scan error: {e}")
            return None
    
    def detailed_scan(self, target: str, ports: str = "1-1000", timing: str = "T3", scripts: str = None) -> Optional[Dict[str, Any]]:
        """Perform detailed scan using Smap"""
        if not self.is_available():
            logger.error("Smap scanner not available")
            return None
        
        try:
            logger.info(f"Performing Smap detailed scan for: {target}")
            
            # Build command
            cmd = [
                self.smap_path,
                '--detailed-scan',
                '--ports', ports,
                '--timing', timing,
                '--json',
                target
            ]

            if scripts:
                cmd.extend(['--scripts', scripts])

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate(timeout=1800)
            if process.returncode != 0:
                logger.error(f"Smap detailed scan failed: {stderr}")
                return None

            try:
                output = json.loads(stdout)
                return self._parse_smap_output(output)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Smap output: {e}")
                return None
                
        except subprocess.TimeoutExpired:
            logger.error("Smap detailed scan timed out")
            return None
        except Exception as e:
            logger.error(f"Smap detailed scan error: {e}")
            return None
    
    def _parse_smap_output(self, output: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Smap output and convert to standard format"""
        try:
            parsed = {
                "scanner": "smap",
                "scan_time": datetime.now().isoformat(),
                "hosts": []
            }
            
            # Process hosts
            for host_data in output.get("hosts", []):
                host = {
                    "ip": host_data.get("ip"),
                    "status": host_data.get("status", "unknown"),
                    "hostname": host_data.get("hostname"),
                    "os_info": host_data.get("os_info", {}),
                    "mac_address": host_data.get("mac_address"),
                    "vendor": host_data.get("vendor"),
                    "ports": []
                }
                
                # Process ports
                for port_data in host_data.get("ports", []):
                    port = {
                        "port": port_data.get("port"),
                        "protocol": port_data.get("protocol", "tcp"),
                        "state": port_data.get("state", "unknown"),
                        "service": {
                            "name": port_data.get("service_name"),
                            "version": port_data.get("service_version"),
                            "product": port_data.get("service_product"),
                            "extrainfo": port_data.get("service_extrainfo")
                        },
                        "banner": port_data.get("banner"),
                        "scripts": port_data.get("scripts", {})
                    }
                    host["ports"].append(port)
                
                parsed["hosts"].append(host)
            
            return parsed
            
        except Exception as e:
            logger.error(f"Failed to parse Smap output: {e}")
            return {
                "scanner": "smap",
                "scan_time": datetime.now().isoformat(),
                "error": f"Failed to parse output: {str(e)}",
                "hosts": []
            }
