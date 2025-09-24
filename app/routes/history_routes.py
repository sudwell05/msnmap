"""
History Routes for managing scan history and viewing past scans
"""
from flask import Blueprint, request, jsonify, current_app
from ..services.enhanced_scan_service import EnhancedScanService
from ..models.database import get_db
import os
import logging
import csv
import io

# Blueprint
bp = Blueprint("history", __name__, url_prefix="/api/history")

def get_enhanced_scan_service():
    """Get enhanced scan service with database session and Flask app"""
    # Get database session from Flask-SQLAlchemy
    from ..models.database import db
    db_session = db.session if db else None
    
    # Get Flask app from current_app
    from flask import current_app
    app = current_app._get_current_object() if current_app else None
    
    return EnhancedScanService(db_session=db_session, app=app)


@bp.route("/scans")
def list_scan_history():
    """List scan history with pagination and filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        status_filter = request.args.get('status')
        scan_type_filter = request.args.get('scan_type')
        
        scan_service = get_enhanced_scan_service()
        all_scans = scan_service.list_scans()
        
        # Apply filters
        if status_filter:
            all_scans = [s for s in all_scans if s.get('status') == status_filter]
        
        if scan_type_filter:
            all_scans = [s for s in all_scans if s.get('scan_type') == scan_type_filter]
        
        # Pagination
        total_scans = len(all_scans)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        scans = all_scans[start_idx:end_idx]
        
        return jsonify({
            "status": "success",
            "scans": scans,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total": total_scans,
                "pages": (total_scans + per_page - 1) // per_page
            }
        })
        
    except Exception as e:
        current_app.logger.error(f"History list error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to list scan history: {str(e)}"}), 500


@bp.route("/scans/<scan_id>")
def get_scan_details(scan_id):
    """Get detailed information about a specific scan"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        results = scan_service.get_scan_results(scan_id)
        
        if results:
            return jsonify({
                "status": "success",
                "scan": results
            })
        else:
            return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    except Exception as e:
        current_app.logger.error(f"Scan details error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get scan details: {str(e)}"}), 500


@bp.route("/scans/<scan_id>/delete", methods=["DELETE"])
def delete_scan_from_history(scan_id):
    """Delete a scan from history"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        success = scan_service.delete_scan(scan_id)
        
        if success:
            current_app.logger.info(f"Deleted scan {scan_id} from history")
            return jsonify({
                "status": "success",
                "message": "Scan deleted successfully"
            })
        else:
            return jsonify({
                "status": "error",
                "message": "Scan not found or could not be deleted"
            }), 404
            
    except Exception as e:
        current_app.logger.error(f"Delete scan error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to delete scan: {str(e)}"}), 500


@bp.route("/scans/<scan_id>/export")
def export_scan_results(scan_id):
    """Export scan results in various formats"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        format_type = request.args.get('format', 'json').lower()
        if format_type not in ['json', 'csv', 'html']:
            return jsonify({"status": "error", "message": "Unsupported format"}), 400
        
        scan_service = get_enhanced_scan_service()
        results = scan_service.get_scan_results(scan_id)
        
        if not results:
            return jsonify({"status": "error", "message": "Scan not found"}), 404
        
        # Export based on format
        if format_type == 'json':
            return jsonify({
                "status": "success",
                "format": "json",
                "data": results
            })
        elif format_type == 'csv':
            csv_data = convert_to_csv(results)
            return jsonify({
                "status": "success",
                "format": "csv",
                "data": csv_data
            })
        elif format_type == 'html':
            html_data = convert_to_html(results)
            return jsonify({
                "status": "success",
                "format": "html",
                "data": html_data
            })
        
    except Exception as e:
        current_app.logger.error(f"Export error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to export scan: {str(e)}"}), 500


@bp.route("/statistics")
def get_history_statistics():
    """Get comprehensive scan history statistics"""
    try:
        scan_service = get_enhanced_scan_service()
        scans = scan_service.list_scans()
        
        if not scans:
            return jsonify({
                "status": "success",
                "statistics": {
                    "total_scans": 0,
                    "completed_scans": 0,
                    "failed_scans": 0,
                    "running_scans": 0,
                    "success_rate": 0,
                    "scan_types": {},
                    "recent_activity": [],
                    "top_targets": []
                }
            })
        
        # Basic statistics
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.get('status') == 'completed'])
        failed_scans = len([s for s in scans if s.get('status') == 'failed'])
        running_scans = len([s for s in scans if s.get('status') == 'running'])
        
        # Scan type distribution
        scan_types = {}
        for scan in scans:
            scan_type = scan.get('scan_type', 'unknown')
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        # Recent activity (last 10 scans)
        recent_activity = sorted(scans, key=lambda x: x.get('start_time', ''), reverse=True)[:10]
        
        # Top targets (most scanned)
        target_counts = {}
        for scan in scans:
            targets = scan.get('targets', '')
            if targets:
                try:
                    import json
                    target_list = json.loads(targets) if isinstance(targets, str) else targets
                    for target in target_list:
                        target_counts[target] = target_counts.get(target, 0) + 1
                except:
                    pass
        
        top_targets = sorted(target_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        
        statistics = {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "running_scans": running_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "scan_types": scan_types,
            "recent_activity": recent_activity,
            "top_targets": [{"target": t[0], "count": t[1]} for t in top_targets]
        }
        
        return jsonify({
            "status": "success",
            "statistics": statistics
        })
        
    except Exception as e:
        current_app.logger.error(f"Statistics error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get statistics: {str(e)}"}), 500


def convert_to_csv(results):
    """Convert scan results to CSV format"""
    try:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Scan ID', 'Target', 'IP Address', 'Hostname', 'Status', 'Port', 'Protocol',
            'Port State', 'Service', 'Version', 'Product', 'Banner'
        ])
        
        # Write data
        scan = results.get('scan', {})
        scan_id = scan.get('scan_id', 'Unknown')
        
        for host in results.get('hosts', []):
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
        current_app.logger.error(f"CSV conversion error: {str(e)}")
        return "Error converting to CSV"


def convert_to_html(results):
    """Convert scan results to HTML format"""
    try:
        scan = results.get('scan', {})
        hosts = results.get('hosts', [])
        
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Scan Report - {scan.get('scan_id', 'Unknown')}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f0f0f0; padding: 20px; border-radius: 5px; }}
                .host {{ margin: 20px 0; border: 1px solid #ddd; border-radius: 5px; }}
                .host-header {{ background-color: #e0e0e0; padding: 10px; }}
                .ports-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
                .ports-table th, .ports-table td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                .ports-table th {{ background-color: #f5f5f5; }}
                .status-open {{ color: green; font-weight: bold; }}
                .status-closed {{ color: red; }}
                .status-filtered {{ color: orange; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Scan Report</h1>
                <p><strong>Scan ID:</strong> {scan.get('scan_id', 'Unknown')}</p>
                <p><strong>Status:</strong> {scan.get('status', 'Unknown')}</p>
                <p><strong>Scan Type:</strong> {scan.get('scan_type', 'Unknown')}</p>
                <p><strong>Targets:</strong> {scan.get('targets', 'Unknown')}</p>
                <p><strong>Start Time:</strong> {scan.get('start_time', 'Unknown')}</p>
                <p><strong>End Time:</strong> {scan.get('end_time', 'Unknown')}</p>
            </div>
        """
        
        for host in hosts:
            html += f"""
            <div class="host">
                <div class="host-header">
                    <h2>Host: {host.get('ip_address', 'Unknown')}</h2>
                    <p><strong>Hostname:</strong> {host.get('hostname', 'Unknown')}</p>
                    <p><strong>Status:</strong> {host.get('status', 'Unknown')}</p>
                    <p><strong>OS:</strong> {host.get('os_info', {}).get('name', 'Unknown')}</p>
                </div>
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
            
            for port in host.get('ports', []):
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
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
        
    except Exception as e:
        current_app.logger.error(f"HTML conversion error: {str(e)}")
        return f"<html><body><h1>Error</h1><p>Error converting to HTML: {str(e)}</p></body></html>"
