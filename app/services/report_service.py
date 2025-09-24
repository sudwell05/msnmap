"""
Report Service for generating and managing scan reports
"""
from typing import Dict, List, Optional, Any
from datetime import datetime
import os
import json
import csv
import io
import logging

from ..models.database import db, Scan, Host, Port, Vulnerability
from utils import now_str

class ReportService:
    """Service for generating scan reports in various formats"""
    
    def __init__(self, db_session=None):
        self.db_session = db_session
        self.logger = logging.getLogger(__name__)

    def generate_report(self, scan_id: str, format_type: str = "html") -> Optional[str]:
        """Generate scan report in specified format"""
        try:
            # Get scan data
            scan_data = self._get_scan_data(scan_id)
            if not scan_data:
                return None
            
            # Generate report based on format
            if format_type == "html":
                return self._generate_html_report(scan_data)
            elif format_type == "json":
                return self._generate_json_report(scan_data)
            elif format_type == "csv":
                return self._generate_csv_report(scan_data)
            else:
                raise ValueError(f"Unsupported format: {format_type}")
                
        except Exception as e:
            self.logger.error(f"Failed to generate report: {e}")
            return None

    def _get_scan_data(self, scan_id: str) -> Optional[Dict]:
        """Get complete scan data for report generation"""
        try:
            if not self.db_session:
                return None
            
            scan_record = self.db_session.query(Scan).filter_by(scan_id=scan_id).first()
            if not scan_record:
                return None
            
            # Get hosts and ports
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
            self.logger.error(f"Failed to get scan data: {e}")
            return None

    def _generate_html_report(self, scan_data: Dict) -> str:
        """Generate HTML report"""
        try:
            scan = scan_data.get("scan", {})
            hosts = scan_data.get("hosts", [])
            
            html = f"""
            <!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Network Scan Report - {scan.get('scan_id', 'Unknown')}</title>
                <style>
                    body {{ 
                        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                        margin: 0; 
                        padding: 20px; 
                        background-color: #f5f5f5; 
                    }}
                    .container {{ 
                        max-width: 1200px; 
                        margin: 0 auto; 
                        background-color: white; 
                        padding: 30px; 
                        border-radius: 8px; 
                        box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
                    }}
                    .header {{ 
                        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                        color: white; 
                        padding: 30px; 
                        border-radius: 8px; 
                        margin-bottom: 30px; 
                        text-align: center; 
                    }}
                    .header h1 {{ margin: 0; font-size: 2.5em; }}
                    .summary {{ 
                        background-color: #f8f9fa; 
                        padding: 20px; 
                        border-radius: 8px; 
                        margin-bottom: 30px; 
                        border-left: 4px solid #007bff; 
                    }}
                    .summary-grid {{ 
                        display: grid; 
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                        gap: 20px; 
                        margin-top: 20px; 
                    }}
                    .summary-item {{ 
                        text-align: center; 
                        padding: 15px; 
                        background-color: white; 
                        border-radius: 6px; 
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1); 
                    }}
                    .summary-item h3 {{ margin: 0; color: #007bff; }}
                    .summary-item p {{ margin: 5px 0; font-size: 1.2em; font-weight: bold; }}
                    .host-section {{ 
                        margin-bottom: 40px; 
                        border: 1px solid #dee2e6; 
                        border-radius: 8px; 
                        overflow: hidden; 
                    }}
                    .host-header {{ 
                        background-color: #e9ecef; 
                        padding: 20px; 
                        border-bottom: 1px solid #dee2e6; 
                    }}
                    .host-header h2 {{ margin: 0; color: #495057; }}
                    .host-info {{ 
                        padding: 20px; 
                        background-color: #f8f9fa; 
                        border-bottom: 1px solid #dee2e6; 
                    }}
                    .host-info p {{ margin: 5px 0; }}
                    .ports-table {{ 
                        width: 100%; 
                        border-collapse: collapse; 
                        margin: 0; 
                    }}
                    .ports-table th, .ports-table td {{ 
                        border: 1px solid #dee2e6; 
                        padding: 12px; 
                        text-align: left; 
                    }}
                    .ports-table th {{ 
                        background-color: #007bff; 
                        color: white; 
                        font-weight: 600; 
                    }}
                    .ports-table tr:nth-child(even) {{ background-color: #f8f9fa; }}
                    .status-open {{ color: #28a745; font-weight: bold; }}
                    .status-closed {{ color: #dc3545; }}
                    .status-filtered {{ color: #ffc107; font-weight: bold; }}
                    .status-unknown {{ color: #6c757d; }}
                    .footer {{ 
                        text-align: center; 
                        margin-top: 40px; 
                        padding: 20px; 
                        color: #6c757d; 
                        border-top: 1px solid #dee2e6; 
                    }}
                    @media (max-width: 768px) {{
                        .container {{ padding: 15px; }}
                        .header {{ padding: 20px; }}
                        .header h1 {{ font-size: 2em; }}
                        .summary-grid {{ grid-template-columns: 1fr; }}
                    }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔍 Network Scan Report</h1>
                        <p>Comprehensive network security assessment results</p>
                    </div>
                    
                    <div class="summary">
                        <h2>📊 Scan Summary</h2>
                        <div class="summary-grid">
                            <div class="summary-item">
                                <h3>Scan ID</h3>
                                <p>{scan.get('scan_id', 'Unknown')}</p>
                            </div>
                            <div class="summary-item">
                                <h3>Status</h3>
                                <p class="status-{scan.get('status', 'unknown')}">{scan.get('status', 'Unknown')}</p>
                            </div>
                            <div class="summary-item">
                                <h3>Scan Type</h3>
                                <p>{scan.get('scan_type', 'Unknown')}</p>
                            </div>
                            <div class="summary-item">
                                <h3>Targets</h3>
                                <p>{scan.get('targets', 'N/A')}</p>
                            </div>
                            <div class="summary-item">
                                <h3>Hosts Found</h3>
                                <p>{len(hosts)}</p>
                            </div>
                            <div class="summary-item">
                                <h3>Start Time</h3>
                                <p>{scan.get('start_time', 'N/A')}</p>
                            </div>
                        </div>
                    </div>
            """
            
            # Add host details
            for host in hosts:
                ports = host.get("ports", [])
                open_ports = [p for p in ports if p.get("state") == "open"]
                
                html += f"""
                    <div class="host-section">
                        <div class="host-header">
                            <h2>🖥️ Host: {host.get('ip_address', 'Unknown')}</h2>
                        </div>
                        
                        <div class="host-info">
                            <p><strong>Status:</strong> <span class="status-{host.get('status', 'unknown')}">{host.get('status', 'Unknown')}</span></p>
                            {f'<p><strong>Hostname:</strong> {host.get("hostname")}</p>' if host.get('hostname') else ''}
                            {f'<p><strong>OS:</strong> {host.get("os_info", {}).get("name", "Unknown")}</p>' if host.get('os_info') else ''}
                            {f'<p><strong>MAC Address:</strong> {host.get("mac_address")}</p>' if host.get('mac_address') else ''}
                            {f'<p><strong>Vendor:</strong> {host.get("vendor")}</p>' if host.get('vendor') else ''}
                            <p><strong>Open Ports:</strong> {len(open_ports)}</p>
                        </div>
                        
                        <div class="ports-section">
                            <h3>🔌 Port Scan Results</h3>
                            <table class="ports-table">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Protocol</th>
                                        <th>State</th>
                                        <th>Service</th>
                                        <th>Version</th>
                                        <th>Product</th>
                                        <th>Banner</th>
                                    </tr>
                                </thead>
                                <tbody>
                """
                
                for port in ports:
                    state_class = f"status-{port.get('state', 'unknown')}"
                    html += f"""
                                    <tr>
                                        <td>{port.get('port_number', '')}</td>
                                        <td>{port.get('protocol', '')}</td>
                                        <td class="{state_class}">{port.get('state', '')}</td>
                                        <td>{port.get('service_name', '')}</td>
                                        <td>{port.get('service_version', '')}</td>
                                        <td>{port.get('service_product', '')}</td>
                                        <td>{port.get('banner', '')[:100] if port.get('banner') else ''}</td>
                                    </tr>
                    """
                
                html += """
                                </tbody>
                            </table>
                        </div>
                    </div>
                """
            
            html += """
                    <div class="footer">
                        <p>Report generated on """ + datetime.now().strftime("%Y-%m-%d %H:%M:%S") + """</p>
                        <p>Enhanced Network Scanner Application</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            return html
            
        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {e}")
            return f"<html><body><h1>Error</h1><p>Failed to generate report: {str(e)}</p></body></html>"

    def _generate_json_report(self, scan_data: Dict) -> str:
        """Generate JSON report"""
        try:
            return json.dumps(scan_data, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {e}")
            return json.dumps({"error": f"Failed to generate report: {str(e)}"})

    def _generate_csv_report(self, scan_data: Dict) -> str:
        """Generate CSV report"""
        try:
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow([
                'Scan ID', 'Target', 'IP Address', 'Hostname', 'Status', 'Port', 'Protocol',
                'Port State', 'Service', 'Version', 'Product', 'Banner'
            ])
            
            # Write data
            scan = scan_data.get('scan', {})
            scan_id = scan.get('scan_id', 'Unknown')
            
            for host in scan_data.get('hosts', []):
                ip_address = host.get('ip_address', '')
                hostname = host.get('hostname', '')
                status = host.get('status', '')
                
                for port in host.get('ports', []):
                    writer.writerow([
                        scan_id,
                        scan.get('targets', ''),
                        ip_address,
                        hostname,
                        status,
                        port.get('port_number', ''),
                        port.get('protocol', ''),
                        port.get('state', ''),
                        port.get('service_name', ''),
                        port.get('service_version', ''),
                        port.get('service_product', ''),
                        port.get('banner', '')[:100] if port.get('banner') else ''
                    ])
            
            return output.getvalue()
            
        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {e}")
            return "Error converting to CSV"

    def save_report(self, scan_id: str, format_type: str, report_content: str, output_dir: str) -> Optional[str]:
        """Save report to file"""
        try:
            # Create output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)
            
            # Generate filename
            timestamp = now_str()
            filename = f"{scan_id}_report_{timestamp}.{format_type}"
            filepath = os.path.join(output_dir, filename)
            
            # Write report to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            self.logger.info(f"Report saved to: {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to save report: {e}")
            return None

    def get_report_formats(self) -> List[str]:
        """Get list of supported report formats"""
        return ["html", "json", "csv"]
