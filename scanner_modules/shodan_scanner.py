"""
Shodan Scanner Module for passive network reconnaissance
"""
import os
import json
import logging
import time
from typing import Dict, List, Optional, Any
from datetime import datetime

logger = logging.getLogger(__name__)

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.warning("Shodan library not available. Install with: pip install shodan")

class ShodanScanner:
    """Shodan scanner for passive network reconnaissance"""
    
    def __init__(self, api_key: Optional[str] = None):
        """Initialize Shodan scanner"""
        self.api_key = api_key or os.environ.get('SHODAN_API_KEY')
        self.api = None
        
        if SHODAN_AVAILABLE and self.api_key:
            try:
                self.api = shodan.Shodan(self.api_key)
                logger.info("Shodan scanner initialized successfully")
            except Exception as e:
                logger.error(f"Failed to initialize Shodan scanner: {e}")
                self.api = None
        else:
            logger.warning("Shodan scanner not available - API key required")
    
    def is_available(self) -> bool:
        """Check if Shodan scanning is available"""
        return SHODAN_AVAILABLE and self.api is not None and self.api_key is not None
    
    def search_host(self, host: str) -> Optional[Dict[str, Any]]:
        """Search for information about a specific host"""
        if not self.is_available():
            logger.error("Shodan scanner not available")
            return None
        
        try:
            logger.info(f"Searching Shodan for host: {host}")
            
            # Search for the host
            results = self.api.host(host)
            
            # Process results
            processed_results = self._process_host_results(host, results)
            
            logger.info(f"Shodan search completed for {host}")
            return processed_results
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error for {host}: {e}")
            return None
        except Exception as e:
            logger.error(f"Shodan search error for {host}: {str(e)}")
            return None
    
    def search_network(self, network: str) -> Optional[Dict[str, Any]]:
        """Search for information about a network range"""
        if not self.is_available():
            logger.error("Shodan scanner not available")
            return None
        
        try:
            logger.info(f"Searching Shodan for network: {network}")
            
            # Search for the network
            query = f"net:{network}"
            results = self.api.search(query, limit=100)
            
            # Process results
            processed_results = self._process_network_results(network, results)
            
            logger.info(f"Shodan network search completed for {network}")
            return processed_results
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error for network {network}: {e}")
            return None
        except Exception as e:
            logger.error(f"Shodan network search error for {network}: {str(e)}")
            return None
    
    def search_service(self, service: str, port: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Search for specific services"""
        if not self.is_available():
            logger.error("Shodan scanner not available")
            return None
        
        try:
            logger.info(f"Searching Shodan for service: {service}")
            
            # Build query
            query = f"product:{service}"
            if port:
                query += f" port:{port}"
            
            # Search for the service
            results = self.api.search(query, limit=50)
            
            # Process results
            processed_results = self._process_service_results(service, results)
            
            logger.info(f"Shodan service search completed for {service}")
            return processed_results
            
        except shodan.APIError as e:
            logger.error(f"Shodan API error for service {service}: {e}")
            return None
        except Exception as e:
            logger.error(f"Shodan service search error for {service}: {str(e)}")
            return None
    
    def _process_host_results(self, host: str, results: Dict) -> Dict[str, Any]:
        """Process Shodan host results"""
        try:
            processed = {
                "ip": host,
                "hostname": results.get("hostnames", [None])[0] if results.get("hostnames") else None,
                "os": results.get("os", "Unknown"),
                "ports": [],
                "vulns": results.get("vulns", []),
                "tags": results.get("tags", []),
                "last_update": results.get("last_update"),
                "country": results.get("country_name"),
                "city": results.get("city"),
                "org": results.get("org"),
                "isp": results.get("isp")
            }
            
            # Process ports and services
            for port_data in results.get("data", []):
                port_info = {
                    "port": port_data.get("port"),
                    "protocol": port_data.get("transport", "tcp"),
                    "service": port_data.get("product"),
                    "version": port_data.get("version"),
                    "product": port_data.get("product"),
                    "data": port_data.get("data", "")[:500],  # Limit banner length
                    "timestamp": port_data.get("timestamp"),
                    "ssl": port_data.get("ssl", {}),
                    "http": port_data.get("http", {})
                }
                processed["ports"].append(port_info)
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing host results for {host}: {e}")
            return {"ip": host, "error": f"Failed to process results: {str(e)}"}
    
    def _process_network_results(self, network: str, results: Dict) -> Dict[str, Any]:
        """Process Shodan network search results"""
        try:
            processed = {
                "network": network,
                "total_results": results.get("total", 0),
                "hosts": []
            }
            
            # Process each host found
            for host_data in results.get("matches", []):
                host_info = {
                    "ip": host_data.get("ip_str"),
                    "port": host_data.get("port"),
                    "protocol": host_data.get("transport", "tcp"),
                    "service": host_data.get("product"),
                    "version": host_data.get("version"),
                    "data": host_data.get("data", "")[:200],
                    "timestamp": host_data.get("timestamp"),
                    "country": host_data.get("location", {}).get("country_name"),
                    "city": host_data.get("location", {}).get("city")
                }
                processed["hosts"].append(host_info)
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing network results for {network}: {e}")
            return {"network": network, "error": f"Failed to process results: {str(e)}"}
    
    def _process_service_results(self, service: str, results: Dict) -> Dict[str, Any]:
        """Process Shodan service search results"""
        try:
            processed = {
                "service": service,
                "total_results": results.get("total", 0),
                "instances": []
            }
            
            # Process each service instance found
            for instance in results.get("matches", []):
                instance_info = {
                    "ip": instance.get("ip_str"),
                    "port": instance.get("port"),
                    "protocol": instance.get("transport", "tcp"),
                    "version": instance.get("version"),
                    "data": instance.get("data", "")[:200],
                    "country": instance.get("location", {}).get("country_name"),
                    "city": instance.get("location", {}).get("city"),
                    "org": instance.get("org")
                }
                processed["instances"].append(instance_info)
            
            return processed
            
        except Exception as e:
            logger.error(f"Error processing service results for {service}: {e}")
            return {"service": service, "error": f"Failed to process results: {str(e)}"}
    
    def get_api_info(self) -> Optional[Dict[str, Any]]:
        """Get information about the Shodan API account"""
        if not self.is_available():
            return None
        
        try:
            info = self.api.info()
            return {
                "plan": info.get("plan"),
                "credits": info.get("credits"),
                "query_credits": info.get("query_credits"),
                "scan_credits": info.get("scan_credits"),
                "monitored_ips": info.get("monitored_ips")
            }
        except Exception as e:
            logger.error(f"Failed to get Shodan API info: {e}")
            return None
    
    def rate_limit_check(self) -> bool:
        """Check if we're within rate limits"""
        if not self.is_available():
            return False
        
        try:
            # Simple rate limiting - wait between requests
            time.sleep(1)  # Basic rate limiting
            return True
        except Exception as e:
            logger.error(f"Rate limit check failed: {e}")
            return False

# Export functions for backward compatibility
def shodan_search_host(host: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """Search for host information using Shodan"""
    scanner = ShodanScanner(api_key)
    return scanner.search_host(host)

def shodan_search_network(network: str, api_key: Optional[str] = None) -> Optional[Dict]:
    """Search for network information using Shodan"""
    scanner = ShodanScanner(api_key)
    return scanner.search_network(network)

def shodan_search_service(service: str, port: Optional[int] = None, api_key: Optional[str] = None) -> Optional[Dict]:
    """Search for service information using Shodan"""
    scanner = ShodanScanner(api_key)
    return scanner.search_service(service, port)

# Export functions
__all__ = [
    'ShodanScanner',
    'shodan_search_host',
    'shodan_search_network',
    'shodan_search_service'
]
