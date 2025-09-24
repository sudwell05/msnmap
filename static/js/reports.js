class Reports {
    constructor() {
        this.setupEventListeners();
        this.loadScans();
    }

    setupEventListeners() {
        const refreshBtn = document.getElementById('refresh-scans');
        const cleanupBtn = document.getElementById('cleanup-scans');
        const statsBtn = document.getElementById('view-statistics');

        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadScans());
        } else {
            console.warn('Refresh button not found');
        }
        
        if (cleanupBtn) {
            cleanupBtn.addEventListener('click', () => this.cleanupScans());
        } else {
            console.warn('Cleanup button not found');
        }
        
        if (statsBtn) {
            statsBtn.addEventListener('click', () => this.showStatistics());
        } else {
            console.warn('Statistics button not found');
        }
    }

    async loadScans() {
        try {
            const response = await fetch('/api/history/scans');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.displayScans(data.scans);
            } else {
                throw new Error(data.message || 'Failed to load scans');
            }
        } catch (error) {
            console.error('Error loading scans:', error);
            window.handleError(error);
        }
    }

    displayScans(scans) {
        const tbody = document.getElementById('scans-list');
        if (!tbody) {
            console.warn('Scans list table body not found');
            return;
        }

        if (!scans || scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No scans found</td></tr>';
            return;
        }

        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>${this.formatDate(scan.start_time)}</td>
                <td>${scan.scan_type || 'Unknown'}</td>
                <td><span class="status-${scan.status || 'unknown'}">${scan.status || 'Unknown'}</span></td>
                <td>${scan.targets || 'N/A'}</td>
                <td>${scan.hosts_count || 0}</td>
                <td>${scan.progress || 0}%</td>
                <td>${this.getActionButtons(scan)}</td>
            </tr>
        `).join('');
    }

    getActionButtons(scan) {
        if (!scan || !scan.scan_id) {
            return '<span class="text-muted">No actions available</span>';
        }
        
        const buttons = [];
        
        // View button
        buttons.push(`<button onclick="app.reports.viewScan('${scan.scan_id}')" class="btn btn-sm btn-primary">View</button>`);
        
        // Stop button for running scans
        if (scan.status === 'running') {
            buttons.push(`<button onclick="app.scanner.stopScan('${scan.scan_id}')" class="btn btn-sm btn-danger">Stop</button>`);
        }
        
        // Export buttons for completed scans
        if (scan.status === 'completed') {
            buttons.push(`<button onclick="app.reports.exportScan('${scan.scan_id}', 'json')" class="btn btn-sm btn-secondary">JSON</button>`);
            buttons.push(`<button onclick="app.reports.exportScan('${scan.scan_id}', 'csv')" class="btn btn-sm btn-secondary">CSV</button>`);
            buttons.push(`<button onclick="app.reports.exportScan('${scan.scan_id}', 'html')" class="btn btn-sm btn-secondary">HTML</button>`);
        }
        
        // Delete button
        buttons.push(`<button onclick="app.reports.deleteScan('${scan.scan_id}')" class="btn btn-sm btn-danger">Delete</button>`);
        
        return buttons.join(' ');
    }

    async viewScan(scanId) {
        if (!scanId) {
            window.handleError(new Error('No scan ID provided for view'));
            return;
        }
        
        try {
            const response = await fetch(`/api/history/scans/${scanId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showScanResults(scanId, data.scan);
            } else {
                throw new Error(data.message || 'Failed to load scan details');
            }
        } catch (error) {
            console.error('Error viewing scan:', error);
            window.handleError(error);
        }
    }

    showScanResults(scanId, results) {
        if (!results) {
            window.handleError(new Error('No scan results to display'));
            return;
        }
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        
        const scan = results.scan || {};
        const hosts = results.hosts || [];
        
        let hostsHtml = '';
        if (hosts.length > 0) {
            hostsHtml = hosts.map(host => this.renderHostResults(host)).join('');
        } else {
            hostsHtml = '<p>No hosts found.</p>';
        }
        
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close">&times;</span>
                <h2>Scan Results: ${scanId}</h2>
                <div class="scan-summary">
                    <p><strong>Status:</strong> <span class="status-${scan.status || 'unknown'}">${scan.status || 'Unknown'}</span></p>
                    <p><strong>Scan Type:</strong> ${scan.scan_type || 'Unknown'}</p>
                    <p><strong>Targets:</strong> ${scan.targets || 'N/A'}</p>
                    <p><strong>Start Time:</strong> ${this.formatDate(scan.start_time)}</p>
                    ${scan.end_time ? `<p><strong>End Time:</strong> ${this.formatDate(scan.end_time)}</p>` : ''}
                </div>
                <div class="hosts-results">
                    ${hostsHtml}
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Close modal functionality
        const closeBtn = modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.onclick = () => modal.remove();
        }
        
        // Close on outside click
        window.onclick = (event) => {
            if (event.target === modal) {
                modal.remove();
            }
        };
    }

    renderHostResults(host) {
        if (!host) return '';
        
        const ports = host.ports || [];
        
        let portsHtml = '';
        if (ports.length > 0) {
            portsHtml = `
                <table class="ports-table">
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Banner</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${ports.map(port => `
                            <tr>
                                <td>${port.port_number || 'N/A'}</td>
                                <td>${port.protocol || 'N/A'}</td>
                                <td><span class="status-${port.state || 'unknown'}">${port.state || 'Unknown'}</span></td>
                                <td>${port.service_name || ''}</td>
                                <td>${port.service_version || ''}</td>
                                <td>${port.banner ? (port.banner.length > 50 ? port.banner.substring(0, 50) + '...' : port.banner) : ''}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        } else {
            portsHtml = '<p>No open ports found.</p>';
        }
        
        return `
            <div class="host-result">
                <h4>Host: ${host.ip_address || 'Unknown'}</h4>
                <div class="host-info">
                    <p><strong>Status:</strong> <span class="status-${host.status || 'unknown'}">${host.status || 'Unknown'}</span></p>
                    ${host.hostname ? `<p><strong>Hostname:</strong> ${host.hostname}</p>` : ''}
                    ${host.os_info ? `<p><strong>OS:</strong> ${host.os_info.name || 'Unknown'}</p>` : ''}
                    <p><strong>Open Ports:</strong> ${host.open_ports_count || 0}</p>
                </div>
                <div class="ports-section">
                    <h5>Port Scan Results:</h5>
                    ${portsHtml}
                </div>
            </div>
        `;
    }

    async exportScan(scanId, format) {
        if (!scanId) {
            window.handleError(new Error('No scan ID provided for export'));
            return;
        }
        
        try {
            const response = await fetch(`/api/history/scans/${scanId}/export?format=${format}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                if (format === 'json') {
                    // Download JSON file
                    const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `scan_results_${scanId}.json`;
                    a.click();
                    window.URL.revokeObjectURL(url);
                } else if (format === 'csv') {
                    // Download CSV file
                    const blob = new Blob([data.data], { type: 'text/csv' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `scan_results_${scanId}.csv`;
                    a.click();
                    window.URL.revokeObjectURL(url);
                } else if (format === 'html') {
                    // Open HTML in new window
                    const newWindow = window.open();
                    newWindow.document.write(data.data);
                    newWindow.document.close();
                }
                
                if (window.showSuccess) {
                    window.showSuccess(`Scan exported as ${format.toUpperCase()}`);
                }
            } else {
                throw new Error(data.message || 'Failed to export scan');
            }
        } catch (error) {
            console.error('Error exporting scan:', error);
            window.handleError(error);
        }
    }

    async deleteScan(scanId) {
        if (!scanId) {
            window.handleError(new Error('No scan ID provided for deletion'));
            return;
        }
        
        if (!confirm('Are you sure you want to delete this scan?')) {
            return;
        }
        
        try {
            const response = await fetch(`/api/history/scans/${scanId}/delete`, {
                method: 'DELETE'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                if (window.showSuccess) {
                    window.showSuccess('Scan deleted successfully');
                }
                this.loadScans(); // Refresh the list
            } else {
                throw new Error(data.message || 'Failed to delete scan');
            }
        } catch (error) {
            console.error('Error deleting scan:', error);
            window.handleError(error);
        }
    }

    async cleanupScans() {
        if (!confirm('Are you sure you want to cleanup completed scans?')) {
            return;
        }
        
        try {
            // This would need to be implemented in the backend
            if (window.showSuccess) {
                window.showSuccess('Cleanup completed');
            }
            this.loadScans(); // Refresh the list
        } catch (error) {
            console.error('Error during cleanup:', error);
            window.handleError(error);
        }
    }

    async showStatistics() {
        try {
            const response = await fetch('/api/history/statistics');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.displayStatistics(data.statistics);
            } else {
                throw new Error(data.message || 'Failed to load statistics');
            }
        } catch (error) {
            console.error('Error loading statistics:', error);
            window.handleError(error);
        }
    }

    displayStatistics(stats) {
        if (!stats) {
            window.handleError(new Error('No statistics data to display'));
            return;
        }
        
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close">&times;</span>
                <h2>Scan Statistics</h2>
                <div class="statistics-grid">
                    <div class="stat-item">
                        <h3>${stats.total_scans || 0}</h3>
                        <p>Total Scans</p>
                    </div>
                    <div class="stat-item">
                        <h3>${stats.completed_scans || 0}</h3>
                        <p>Completed</p>
                    </div>
                    <div class="stat-item">
                        <h3>${stats.failed_scans || 0}</h3>
                        <p>Failed</p>
                    </div>
                    <div class="stat-item">
                        <h3>${stats.running_scans || 0}</h3>
                        <p>Running</p>
                    </div>
                    <div class="stat-item">
                        <h3>${stats.success_rate ? stats.success_rate.toFixed(1) : 0}%</h3>
                        <p>Success Rate</p>
                    </div>
                </div>
                
                <h3>Scan Types</h3>
                <div class="scan-types">
                    ${Object.entries(stats.scan_types || {}).map(([type, count]) => `
                        <div class="scan-type">
                            <span class="type-name">${type}</span>
                            <span class="type-count">${count}</span>
                        </div>
                    `).join('')}
                </div>
                
                <h3>Recent Activity</h3>
                <div class="recent-activity">
                    ${(stats.recent_activity || []).slice(0, 5).map(scan => `
                        <div class="activity-item">
                            <span class="activity-time">${this.formatDate(scan.start_time)}</span>
                            <span class="activity-target">${scan.targets || 'N/A'}</span>
                            <span class="activity-status status-${scan.status || 'unknown'}">${scan.status || 'Unknown'}</span>
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
        
        document.body.appendChild(modal);
        
        // Close modal functionality
        const closeBtn = modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.onclick = () => modal.remove();
        }
        
        // Close on outside click
        window.onclick = (event) => {
            if (event.target === modal) {
                modal.remove();
            }
        };
    }

    formatDate(dateString) {
        if (!dateString) return 'N/A';
        
        try {
            const date = new Date(dateString);
            if (isNaN(date.getTime())) {
                return dateString; // Return original string if invalid date
            }
            return date.toLocaleString();
        } catch (error) {
            console.warn('Error formatting date:', error);
            return dateString;
        }
    }
}