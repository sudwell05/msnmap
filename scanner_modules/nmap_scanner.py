"""
Enhanced Nmap Scanner Module with comprehensive scanning capabilities
"""
import os
import json
import logging
import socket
import threading
import time
from datetime import datetime
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

logger = logging.getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning("Nmap library not available. Install with: pip install python-nmap")


class NmapScanner:
    """Enhanced Nmap scanner with comprehensive scanning capabilities"""
    
    def __init__(self):
        """Initialize Nmap scanner"""
        if NMAP_AVAILABLE:
            self.nm = nmap.PortScanner()
        else:
            self.nm = None
            logger.error("Nmap scanner not available")
    
    def is_available(self) -> bool:
        """Check if Nmap scanning is available"""
        return NMAP_AVAILABLE and self.nm is not None
    
    def host_discovery(self, target: str) -> Dict[str, Any]:
        """Perform host discovery scan"""
        if not self.is_available():
            logger.error("Nmap scanner not available")
            return {"hosts": [{"ip": target, "status": "up"}]}
        
        try:
            logger.info(f"Starting host discovery for target: {target}")
            
            # Perform ping scan
            scan_args = "-sn -PE -PP -PS21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080"
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Get live hosts
            hosts = []
            for host in self.nm.all_hosts():
                host_info = {
                    "ip": host,
                    "status": self.nm[host].state(),
                    "hostname": self.nm[host].hostname() if self.nm[host].hostname() else None
                }
                hosts.append(host_info)
            
            logger.info(f"Host discovery completed. Found {len(hosts)} hosts")
            return {"hosts": hosts}
            
        except Exception as e:
            logger.error(f"Host discovery error: {str(e)}")
            return {"hosts": [{"ip": target, "status": "up"}]}
    
    def detailed_scan(self, target: str, ports: str = "1-1000", 
                     timing: str = "T3", scripts: str = None) -> Dict[str, Any]:
        """Perform detailed port scan with enhanced options"""
        if not self.is_available():
            logger.error("Nmap scanner not available")
            return {"error": "Nmap scanner not available"}
        
        try:
            logger.info(f"Starting detailed scan for {target}")
            
            # Build scan arguments
            scan_args = f"-sS -sV -O -T{timing.replace('T', '')}"
            
            # Add script scanning if specified
            if scripts:
                scan_args += f" --script={scripts}"
            else:
                # Default scripts for enhanced results
                scan_args += " --script=banner,http-title,ssl-cert,ssh-hostkey"
            
            # Add version detection
            scan_args += " --version-intensity 5"
            
            # Perform the scan
            self.nm.scan(hosts=target, ports=ports, arguments=scan_args)
            
            # Process results
            result = self._process_scan_results(target)
            
            logger.info(f"Detailed scan completed for {target}")
            return result
            
        except Exception as e:
            logger.error(f"Detailed scan error for {target}: {str(e)}")
            return {"error": str(e)}
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform quick port scan"""
        if not self.is_available():
            logger.error("Nmap scanner not available")
            return {"error": "Nmap scanner not available"}
        
        try:
            logger.info(f"Starting quick scan for {target}")
            
            # Quick scan with common ports
            scan_args = "-sS -sV -T4 --top-ports 100"
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Process results
            result = self._process_scan_results(target)
            
            logger.info(f"Quick scan completed for {target}")
            return result
            
        except Exception as e:
            logger.error(f"Quick scan error for {target}: {str(e)}")
            return {"error": str(e)}
    
    def full_scan(self, target: str) -> Dict[str, Any]:
        """Perform full port scan"""
        if not self.is_available():
            logger.error("Nmap scanner not available")
            return {"error": "Nmap scanner not available"}
        
        try:
            logger.info(f"Starting full scan for {target}")
            
            # Full scan with all ports
            scan_args = "-sS -sV -O -T4 -p- --script=banner,http-title,ssl-cert,ssh-hostkey"
            self.nm.scan(hosts=target, arguments=scan_args)
            
            # Process results
            result = self._process_scan_results(target)
            
            logger.info(f"Full scan completed for {target}")
            return result
            
        except Exception as e:
            logger.error(f"Full scan error for {target}: {str(e)}")
            return {"error": str(e)}
    
    def _process_scan_results(self, target: str) -> Dict[str, Any]:
        """Process Nmap scan results"""
        try:
            # If the provided target key isn't directly present, fallback to first scanned host
            all_hosts = self.nm.all_hosts()
            if not all_hosts:
                return {"error": "No hosts found in scan results"}
            host_key = target if target in all_hosts else all_hosts[0]
            host_data = self.nm[host_key]
            
            # Basic host information
            result = {
                "ip": target,
                "status": host_data.state(),
                "hostname": host_data.hostname() if host_data.hostname() else None,
                "ports": [],
                "os_info": {},
                "mac_address": None,
                "vendor": None
            }
            
            # Get OS information
            if 'osmatch' in host_data and host_data['osmatch']:
                try:
                    best = max(host_data['osmatch'], key=lambda om: int(om.get('accuracy', 0)))
                    result["os_info"] = {
                        "name": best.get('name'),
                        "accuracy": best.get('accuracy')
                    }
                except Exception:
                    pass
            
            # Get MAC address and vendor
            if 'addresses' in host_data:
                if 'mac' in host_data['addresses']:
                    result["mac_address"] = host_data['addresses']['mac']
                if 'vendor' in host_data:
                    result["vendor"] = host_data['vendor']
            
            # Process ports
            for proto in host_data.all_protocols():
                ports = host_data[proto].keys()
                for port in ports:
                    port_data = host_data[proto][port]
                    
                    port_info = {
                        "port": port,
                        "protocol": proto,
                        "state": port_data['state'],
                        "service": {
                            "name": port_data.get('name', ''),
                            "product": port_data.get('product', ''),
                            "version": port_data.get('version', ''),
                            "extrainfo": port_data.get('extrainfo', '')
                        },
                        "banner": port_data.get('script', {}).get('banner', ''),
                        "scripts": {}
                    }
                    
                    # Get script results
                    for script_name, script_data in port_data.get('script', {}).items():
                        if script_name != 'banner':
                            port_info["scripts"][script_name] = script_data
                    
                    result["ports"].append(port_info)
            
            return result
            
        except Exception as e:
            logger.error(f"Error processing scan results for {target}: {str(e)}")
            return {"error": f"Error processing results: {str(e)}"}
    
    def _grab_banner(self, target: str, port: int, protocol: str = "tcp") -> str:
        """Grab banner from a specific port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((target, port))
            if result == 0:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                return banner.strip()
            sock.close()
        except Exception as e:
            logger.debug(f"Banner grab failed for {target}:{port}: {e}")
        return ""


# Export functions for backward compatibility
def nmap_host_discovery(targets: List[str], output_dir: str = None) -> List[str]:
    """Host discovery function for backward compatibility"""
    scanner = NmapScanner()
    if not targets:
        return []
    
    live_hosts = []
    for target in targets:
        result = scanner.host_discovery(target)
        for host in result.get("hosts", []):
            if host.get("status") == "up":
                live_hosts.append(host["ip"])
    
    return live_hosts

def nmap_detailed_scan(target: str, output_dir: str = None, ports: str = "1-1000", 
                      timing: str = "T3", scripts: str = None) -> Dict[str, Any]:
    """Detailed scan function for backward compatibility"""
    scanner = NmapScanner()
    return scanner.detailed_scan(target, ports, timing, scripts)

def nmap_quick_scan(target: str, output_dir: str = None) -> Dict[str, Any]:
    """Quick scan function for backward compatibility"""
    scanner = NmapScanner()
    return scanner.quick_scan(target)

def nmap_full_scan(target: str, output_dir: str = None) -> Dict[str, Any]:
    """Full scan function for backward compatibility"""
    scanner = NmapScanner()
    return scanner.full_scan(target)

def parse_nmap_xml(xml_file: str) -> Optional[Dict]:
    """Parse Nmap XML output file"""
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        
        result = {
            "summary": {
                "total_hosts": 0,
                "up_hosts": 0,
                "down_hosts": 0
            },
            "hosts": []
        }
        
        for host in root.findall('.//host'):
            try:
                host_data = {
                    "ip": host.find('.//address[@addrtype="ipv4"]').get('addr'),
                    "status": host.find('.//status').get('state'),
                    "hostname": None,
                    "os_info": {},
                    "ports": []
                }
                
                # Get hostname
                hostname_elem = host.find('.//hostname')
                if hostname_elem is not None:
                    host_data["hostname"] = hostname_elem.get('name')
                
                # Get OS information
                os_elem = host.find('.//os/osmatch')
                if os_elem is not None:
                    host_data["os_info"] = {
                        "name": os_elem.get('name'),
                        "accuracy": os_elem.get('accuracy')
                    }
                
                # Get ports
                for port_elem in host.findall('.//port'):
                    port_data = {
                        "port": port_elem.get('portid'),
                        "protocol": port_elem.get('protocol'),
                        "state": port_elem.find('.//state').get('state') if port_elem.find('.//state') is not None else "unknown"
                    }
                    
                    # Get service information
                    service_elem = port_elem.find('.//service')
                    if service_elem is not None:
                        port_data["service"] = {
                            "name": service_elem.get('name'),
                            "product": service_elem.get('product'),
                            "version": service_elem.get('version'),
                            "extrainfo": service_elem.get('extrainfo')
                        }
                    
                    host_data["ports"].append(port_data)
                
                result["hosts"].append(host_data)
                
            except Exception as e:
                logger.warning(f"Error parsing host data: {e}")
                continue
        
        # Update summary
        result["summary"]["total_hosts"] = len(result["hosts"])
        result["summary"]["up_hosts"] = len([h for h in result["hosts"] if h.get("status") == "up"])
        result["summary"]["down_hosts"] = len([h for h in result["hosts"] if h.get("status") == "down"])
        
        return result
        
    except Exception as e:
        logger.error(f"Error parsing Nmap XML: {e}")
        return None


# Export functions
__all__ = [
    'NmapScanner',
    'nmap_host_discovery',
    'nmap_detailed_scan',
    'nmap_quick_scan',
    'nmap_full_scan',
    'parse_nmap_xml'
]
