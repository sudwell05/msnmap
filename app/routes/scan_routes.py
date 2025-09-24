from flask import Blueprint, request, jsonify, current_app
from ..services.enhanced_scan_service import EnhancedScanService
from ..models.database import get_db
from utils import now_str, validate_target_input, validate_port_range, RateLimiter
import os
import logging
from typing import Tuple

# Blueprint
bp = Blueprint("scan", __name__, url_prefix="/api")

# Simple rate limiter instances (e.g., 10 requests per 30 seconds)
start_rate_limiter = RateLimiter(max_requests=10, time_window=30)
control_rate_limiter = RateLimiter(max_requests=30, time_window=30)

def validate_scan_request(data: dict) -> Tuple[bool, str]:
    """Validate scan request data with comprehensive checks"""
    if not isinstance(data, dict):
        return False, "Invalid request data"
    
    targets = data.get("targets")
    if targets is None:
        return False, "Targets not specified"

    # Validate targets
    try:
        validated_targets = validate_target_input(targets)
        if not validated_targets:
            return False, "No valid targets found"
    except Exception as e:
        return False, f"Target validation error: {str(e)}"

    # Validate ports if provided
    ports = data.get("ports", "1-1000")
    if ports and isinstance(ports, str):
        if not validate_port_range(ports):
            return False, "Invalid port specification"

    # Validate timing if provided
    timing = data.get("timing", "T3")
    if timing and timing not in ["T0", "T1", "T2", "T3", "T4", "T5"]:
        return False, "Invalid timing value"

    # Validate scan type
    scan_type = data.get("scan_type", "nmap")
    if scan_type not in ["nmap", "smap", "shodan", "both"]:
        return False, "Invalid scan type"

    return True, ""


def get_enhanced_scan_service():
    """Get enhanced scan service with database session and Flask app"""
    # Get database session from Flask-SQLAlchemy
    from ..models.database import db
    db_session = db.session if db else None
    
    # Get Flask app from current_app
    from flask import current_app
    app = current_app._get_current_object() if current_app else None
    
    return EnhancedScanService(db_session=db_session, app=app)


@bp.route("/scan/start", methods=["POST"])
def start_scan():
    """Start a new network scan with enhanced capabilities"""
    try:
        # Rate limit start requests
        if not start_rate_limiter.can_proceed():
            return jsonify({
                "status": "error",
                "message": "Too many requests. Please try again shortly."
            }), 429
        # Check content type and handle JSON parsing errors
        if not request.is_json:
            current_app.logger.warning(f"Invalid content type: {request.content_type}")
            return jsonify({
                "status": "error", 
                "message": "Content-Type must be application/json"
            }), 400
        
        try:
            data = request.get_json()
            current_app.logger.info(f"Received scan data: {data}")
        except Exception as e:
            current_app.logger.error(f"JSON parsing error: {str(e)}")
            current_app.logger.error(f"Request content: {request.get_data(as_text=True)}")
            return jsonify({
                "status": "error", 
                "message": f"Invalid JSON data: {str(e)}"
            }), 400
            
        if data is None:
            return jsonify({"status": "error", "message": "No data provided"}), 400

        # Validate request data
        current_app.logger.info(f"Validating scan request data: {data}")
        valid, error = validate_scan_request(data)
        current_app.logger.info(f"Validation result: valid={valid}, error={error}")
        if not valid:
            return jsonify({"status": "error", "message": error}), 400

        # Create scan configuration
        scan_config = {
            "targets": data.get("targets", []),
            "ports": data.get("ports", "1-1000"),
            "timing": data.get("timing", "T3"),
            "scan_type": data.get("scan_type", "nmap"),
            "scan_mode": data.get("scan_mode", "detailed"),
            "scripts": data.get("scripts"),
            "output_dir": os.path.join(
                current_app.config.get("SCAN_OUTPUT_DIR", "scan_results"),
                now_str()
            ),
        }

        # Start scan
        scan_service = get_enhanced_scan_service()
        scan_id = scan_service.start_scan(scan_config, data.get("targets", []))

        current_app.logger.info(f"Started enhanced scan {scan_id} for targets: {scan_config['targets']}")

        return jsonify({
            "status": "success",
            "message": "Scan started successfully",
            "scan_id": scan_id,
            "targets": scan_config["targets"],
            "ports": scan_config["ports"],
            "timing": scan_config["timing"],
            "scan_type": scan_config["scan_type"]
        })

    except ValueError as e:
        current_app.logger.warning(f"Scan start validation error: {str(e)}")
        return jsonify({"status": "error", "message": f"Validation error: {str(e)}"}), 400
    except Exception as e:
        current_app.logger.error(f"Scan start error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to start scan: {str(e)}"}), 500


@bp.route("/scan/status/<scan_id>")
def get_scan_status(scan_id):
    """Get scan status with enhanced information"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        status = scan_service.get_scan_status(scan_id)
        
        if status:
            return jsonify(status)
        
        return jsonify({"status": "error", "message": "Scan not found"}), 404
        
    except Exception as e:
        current_app.logger.error(f"Scan status error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get scan status: {str(e)}"}), 500


@bp.route("/scan/results/<scan_id>")
def get_scan_results(scan_id):
    """Get complete scan results - FIXED View button functionality"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        results = scan_service.get_scan_results(scan_id)
        
        if results:
            return jsonify({
                "status": "success",
                "results": results
            })
        else:
            return jsonify({"status": "error", "message": "Scan not found or no results available"}), 404
        
    except Exception as e:
        current_app.logger.error(f"Scan results error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get scan results: {str(e)}"}), 500


@bp.route("/scan/stop/<scan_id>", methods=["POST"])
def stop_scan(scan_id):
    """Stop a running scan - FIXED Stop button functionality"""
    try:
        # Rate limit control requests
        if not control_rate_limiter.can_proceed():
            return jsonify({
                "status": "error",
                "message": "Too many requests. Please try again shortly."
            }), 429
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        success = scan_service.stop_scan(scan_id)
        
        if success:
            current_app.logger.info(f"Stopped scan {scan_id}")
            return jsonify({
                "status": "success", 
                "message": "Scan stopped successfully"
            })
        else:
            return jsonify({
                "status": "error", 
                "message": "Scan not found or already stopped"
            }), 404
            
    except Exception as e:
        current_app.logger.error(f"Scan stop error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to stop scan: {str(e)}"}), 500


@bp.route("/scan/list")
def list_scans():
    """List all scans with enhanced information"""
    try:
        scan_service = get_enhanced_scan_service()
        scans = scan_service.list_scans()
        
        return jsonify({
            "status": "success",
            "scans": scans,
            "count": len(scans)
        })
        
    except Exception as e:
        current_app.logger.error(f"Scan list error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to list scans: {str(e)}"}), 500


@bp.route("/scan/active")
def get_active_scans():
    """Get list of currently active scans"""
    try:
        scan_service = get_enhanced_scan_service()
        all_scans = scan_service.list_scans()
        active_scans = [scan for scan in all_scans if scan.get("status") == "running"]
        
        return jsonify({
            "status": "success",
            "active_scans": active_scans,
            "count": len(active_scans)
        })
        
    except Exception as e:
        current_app.logger.error(f"Active scans error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get active scans: {str(e)}"}), 500


@bp.route("/scan/delete/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    """Delete a scan and all its data"""
    try:
        if not scan_id or not scan_id.strip():
            return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
        
        scan_service = get_enhanced_scan_service()
        success = scan_service.delete_scan(scan_id)
        
        if success:
            current_app.logger.info(f"Deleted scan {scan_id}")
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
        current_app.logger.error(f"Scan delete error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to delete scan: {str(e)}"}), 500


@bp.route("/scan/export/<scan_id>")
def export_scan(scan_id):
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
            from ..routes.history_routes import convert_to_csv
            csv_data = convert_to_csv(results)
            return jsonify({
                "status": "success",
                "format": "csv",
                "data": csv_data
            })
        elif format_type == 'html':
            from ..routes.history_routes import convert_to_html
            html_data = convert_to_html(results)
            return jsonify({
                "status": "success",
                "format": "html",
                "data": html_data
            })
        
    except Exception as e:
        current_app.logger.error(f"Scan export error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to export scan: {str(e)}"}), 500


@bp.route("/scan/statistics")
def get_scan_statistics():
    """Get scan statistics and summary"""
    try:
        scan_service = get_enhanced_scan_service()
        scans = scan_service.list_scans()
        
        # Calculate statistics
        total_scans = len(scans)
        completed_scans = len([s for s in scans if s.get('status') == 'completed'])
        failed_scans = len([s for s in scans if s.get('status') == 'failed'])
        running_scans = len([s for s in scans if s.get('status') == 'running'])
        
        # Scan type distribution
        scan_types = {}
        for scan in scans:
            scan_type = scan.get('scan_type', 'unknown')
            scan_types[scan_type] = scan_types.get(scan_type, 0) + 1
        
        statistics = {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "failed_scans": failed_scans,
            "running_scans": running_scans,
            "success_rate": (completed_scans / total_scans * 100) if total_scans > 0 else 0,
            "scan_types": scan_types
        }
        
        return jsonify({
            "status": "success",
            "statistics": statistics
        })
        
    except Exception as e:
        current_app.logger.error(f"Scan statistics error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get statistics: {str(e)}"}), 500


@bp.route("/scan/scanners")
def get_scanner_status():
    """Get status of available scanning engines"""
    try:
        scan_service = get_enhanced_scan_service()
        scanners = scan_service.get_available_scanners()
        
        return jsonify({
            "status": "success",
            "scanners": scanners
        })
        
    except Exception as e:
        current_app.logger.error(f"Scanner status error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to get scanner status: {str(e)}"}), 500


@bp.route("/scan/cleanup", methods=["POST"])
def cleanup_completed_scans():
    """Clean up completed scans to free up space"""
    try:
        scan_service = get_enhanced_scan_service()
        all_scans = scan_service.list_scans()
        
        # Find completed scans
        completed_scans = [scan for scan in all_scans if scan.get('status') in ['completed', 'failed', 'stopped']]
        
        # Delete completed scans
        deleted_count = 0
        for scan in completed_scans:
            try:
                if scan_service.delete_scan(scan['scan_id']):
                    deleted_count += 1
            except Exception as e:
                current_app.logger.warning(f"Failed to delete scan {scan['scan_id']}: {e}")
                continue
        
        return jsonify({
            "status": "success",
            "message": f"Cleanup completed. Deleted {deleted_count} scans.",
            "deleted_count": deleted_count
        })
        
    except Exception as e:
        current_app.logger.error(f"Cleanup error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to cleanup scans: {str(e)}"}), 500


@bp.route("/scan/export-all")
def export_all_scans():
    """Export all scan results as a single file"""
    try:
        scan_service = get_enhanced_scan_service()
        all_scans = scan_service.list_scans()
        
        if not all_scans:
            return jsonify({"status": "error", "message": "No scans found"}), 404
        
        # Get detailed results for all scans
        all_results = []
        for scan in all_scans:
            try:
                results = scan_service.get_scan_results(scan['scan_id'])
                if results:
                    all_results.append(results)
            except Exception as e:
                current_app.logger.warning(f"Failed to get results for scan {scan['scan_id']}: {e}")
                continue
        
        return jsonify({
            "status": "success",
            "format": "json",
            "data": all_results,
            "total_scans": len(all_results)
        })
        
    except Exception as e:
        current_app.logger.error(f"Export all error: {str(e)}")
        return jsonify({"status": "error", "message": f"Failed to export all scans: {str(e)}"}), 500
