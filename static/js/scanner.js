class Scanner {
    constructor() {
        this.statusCheckInterval = null;
        this.currentScanId = null;
        this.setupEventListeners();
        this.loadScannerStatus();
    }

    setupEventListeners() {
        const scanForm = document.getElementById('scan-form');
        if (scanForm) {
            scanForm.addEventListener('submit', (e) => this.handleScanSubmit(e));
        } else {
            console.warn('Scan form not found');
        }

        // Setup scan mode change listener
        const scanModeSelect = document.getElementById('scan_mode');
        if (scanModeSelect) {
            scanModeSelect.addEventListener('change', (e) => this.handleScanModeChange(e));
        }

        // Setup port range change listener
        const portsInput = document.getElementById('ports');
        if (portsInput) {
            portsInput.addEventListener('input', (e) => this.handlePortRangeChange(e));
        }

        // Setup scan history controls
        const refreshBtn = document.getElementById('refresh-scans');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.refreshScanHistory());
        }

        const cleanupBtn = document.getElementById('cleanup-scans');
        if (cleanupBtn) {
            cleanupBtn.addEventListener('click', () => this.cleanupCompletedScans());
        }

        const statsBtn = document.getElementById('view-statistics');
        if (statsBtn) {
            statsBtn.addEventListener('click', () => this.showStatistics());
        }

        const exportAllBtn = document.getElementById('export-all');
        if (exportAllBtn) {
            exportAllBtn.addEventListener('click', () => this.exportAllScans());
        }
    }

    handleScanModeChange(event) {
        const scanMode = event.target.value;
        const portsInput = document.getElementById('ports');
        
        if (!portsInput) return;

        // Update port range based on scan mode
        switch (scanMode) {
            case 'quick':
                portsInput.value = '1-100';
                portsInput.placeholder = 'Top 100 ports (auto-set)';
                break;
            case 'detailed':
                portsInput.value = '1-1000';
                portsInput.placeholder = '1-1000 or 80,443,8080 or 22,80,443,3306';
                break;
            case 'full':
                portsInput.value = '1-65535';
                portsInput.placeholder = 'All 65535 ports (auto-set)';
                break;
            default:
                portsInput.value = '1-1000';
                portsInput.placeholder = '1-1000 or 80,443,8080 or 22,80,443,3306';
        }

        // Add visual feedback
        portsInput.style.backgroundColor = '#e8f5e8';
        setTimeout(() => {
            portsInput.style.backgroundColor = '';
        }, 1000);
    }

    handlePortRangeChange(event) {
        const portRange = event.target.value;
        const scanModeSelect = document.getElementById('scan_mode');
        
        if (!scanModeSelect) return;

        // Update scan mode based on port range
        if (portRange === '1-100' || portRange === '1-1000') {
            // Check if it matches predefined ranges
            if (portRange === '1-100') {
                scanModeSelect.value = 'quick';
            } else if (portRange === '1-1000') {
                scanModeSelect.value = 'detailed';
            }
        } else if (portRange === '1-65535') {
            scanModeSelect.value = 'full';
        } else {
            // Custom port range - set to detailed as default
            scanModeSelect.value = 'detailed';
        }

        // Add visual feedback
        scanModeSelect.style.backgroundColor = '#e8f5e8';
        setTimeout(() => {
            scanModeSelect.style.backgroundColor = '';
        }, 1000);
    }

    async loadScannerStatus() {
        try {
            const response = await fetch('/api/scan/scanners');
            if (response.ok) {
                const data = await response.json();
                this.updateScannerStatus(data.scanners);
            }
        } catch (error) {
            console.warn('Could not load scanner status:', error);
        }
    }

    updateScannerStatus(scanners) {
        const statusDiv = document.getElementById('scanner-availability');
        if (!statusDiv) return;

        let statusHtml = '<div class="scanner-grid">';
        for (const [name, available] of Object.entries(scanners)) {
            const status = available ? '✅ Available' : '❌ Not Available';
            const statusClass = available ? 'available' : 'unavailable';
            statusHtml += `
                <div class="scanner-item ${statusClass}">
                    <strong>${name.toUpperCase()}:</strong> ${status}
                </div>
            `;
        }
        statusHtml += '</div>';
        statusDiv.innerHTML = statusHtml;
    }

    async handleScanSubmit(e) {
        e.preventDefault();
        const formData = new FormData(e.target);
        
        // Get targets with proper validation
        const targetsInput = formData.get('targets');
        if (!targetsInput || typeof targetsInput !== 'string') {
            window.handleError(new Error('Please enter valid targets'));
            return;
        }
        
        const targets = targetsInput.split('\n')
            .map(t => t.trim())
            .filter(t => t && t.length > 0);
            
        if (targets.length === 0) {
            window.handleError(new Error('Please enter at least one valid target'));
            return;
        }
        
        // Convert form data to JSON with enhanced options
        const scanData = {
            targets: targets,
            ports: formData.get('ports') || '1-1000',
            timing: formData.get('timing') || 'T3',
            scan_type: formData.get('scan_type') || 'nmap',
            scan_mode: formData.get('scan_mode') || 'detailed',
            scripts: formData.get('scripts') || ''
        };

        try {
            // Debug: Log the data being sent
            console.log('Sending scan data:', scanData);
            
            const response = await fetch('/api/scan/start', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(scanData)
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();

            if (data.status === 'success') {
                this.currentScanId = data.scan_id;
                this.startStatusCheck(data.scan_id);
                this.showStatusPanel();
                this.updateStatusUI({
                    message: 'Scan started successfully',
                    progress: 0,
                    status: 'running'
                });
                
                // Disable form during scan
                this.setFormEnabled(false);
                
                // Show success notification
                if (window.showSuccess) {
                    window.showSuccess('Scan started successfully');
                }
                
                // Refresh scan history
                this.refreshScanHistory();
                
            } else {
                throw new Error(data.message || 'Failed to start scan');
            }
        } catch (error) {
            console.error('Error starting scan:', error);
            window.handleError(error);
        }
    }

    async checkStatus(scanId) {
        try {
            const response = await fetch(`/api/scan/status/${scanId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const status = await response.json();
            
            if (status.error) {
                throw new Error(status.error);
            }
            
            this.updateStatusUI(status);

            if (status.status !== 'running') {
                this.stopStatusCheck();
                this.loadResults(scanId);
                this.setFormEnabled(true);
                this.refreshScanHistory(); // Refresh history when scan completes
            }
        } catch (error) {
            console.error('Error checking status:', error);
            window.handleError(error);
            this.stopStatusCheck();
            this.setFormEnabled(true);
        }
    }

    updateStatusUI(status) {
        const statusPanel = document.getElementById('status-panel');
        if (!statusPanel) return;
        
        const progressBar = status.progress || 0;
        const message = status.message || 'Unknown status';
        const isRunning = status.status === 'running';
        
        statusPanel.innerHTML = `
            <h3>📊 Scan Status</h3>
            <div class="status-info">
                <p><strong>Message:</strong> ${message}</p>
                <p><strong>Progress:</strong> ${progressBar}%</p>
                <p><strong>Status:</strong> <span class="status-${status.status || 'unknown'}">${status.status || 'Unknown'}</span></p>
                ${status.total_hosts ? `<p><strong>Hosts:</strong> ${status.scanned_hosts || 0}/${status.total_hosts}</p>` : ''}
                ${status.scan_type ? `<p><strong>Scan Type:</strong> ${status.scan_type}</p>` : ''}
            </div>
            <div class="progress-bar">
                <div class="progress-fill" style="width: ${progressBar}%"></div>
            </div>
            ${isRunning ? `<button onclick="app.scanner.stopScan('${this.currentScanId}')" class="btn btn-danger">🛑 Stop Scan</button>` : ''}
        `;
        
        statusPanel.style.display = 'block';
    }

    startStatusCheck(scanId) {
        if (this.statusCheckInterval) {
            clearInterval(this.statusCheckInterval);
        }
        this.statusCheckInterval = setInterval(() => this.checkStatus(scanId), 2000);
    }

    stopStatusCheck() {
        if (this.statusCheckInterval) {
            clearInterval(this.statusCheckInterval);
            this.statusCheckInterval = null;
        }
    }

    async stopScan(scanId) {
        if (!scanId) {
            console.warn('No scan ID provided to stop');
            return;
        }
        
        try {
            const response = await fetch(`/api/scan/stop/${scanId}`, {
                method: 'POST'
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.updateStatusUI({
                    message: 'Scan stopped by user',
                    progress: 0,
                    status: 'stopped'
                });
                this.stopStatusCheck();
                this.setFormEnabled(true);
                this.refreshScanHistory(); // Refresh history
                
                if (window.showSuccess) {
                    window.showSuccess('Scan stopped successfully');
                }
            } else {
                throw new Error(data.message || 'Failed to stop scan');
            }
        } catch (error) {
            console.error('Error stopping scan:', error);
            window.handleError(error);
        }
    }

    showStatusPanel() {
        const statusPanel = document.getElementById('status-panel');
        if (statusPanel) {
            statusPanel.style.display = 'block';
        }
    }

    setFormEnabled(enabled) {
        const form = document.getElementById('scan-form');
        if (form) {
            const inputs = form.querySelectorAll('input, textarea, select, button');
            inputs.forEach(input => {
                input.disabled = !enabled;
            });
        }
    }

    async loadResults(scanId) {
        if (!scanId) {
            console.warn('No scan ID provided to load results');
            return;
        }
        
        try {
            console.log(`Loading results for scan: ${scanId}`);
            
            // Get scan results using the new endpoint
            const response = await fetch(`/api/scan/results/${scanId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showScanResults(scanId, data.results);
            } else {
                throw new Error(data.message || 'Failed to load results');
            }
        } catch (error) {
            console.error('Error loading results:', error);
            window.handleError(error);
        }
    }

    showScanResults(scanId, results) {
        const reportContainer = document.getElementById('report-container');
        if (!reportContainer) return;
        
        const scan = results.scan || {};
        const hosts = results.hosts || [];
        
        let hostsHtml = '';
        if (hosts.length > 0) {
            hostsHtml = hosts.map(host => this.renderHostResults(host)).join('');
        } else {
            hostsHtml = '<p>No hosts found or scan still in progress.</p>';
        }
        
        reportContainer.innerHTML = `
            <div class="scan-results">
                <h3>🔍 Scan Results for ${scanId}</h3>
                <div class="result-summary">
                    <p><strong>Status:</strong> <span class="status-${scan.status || 'unknown'}">${scan.status || 'Unknown'}</span></p>
                    <p><strong>Scan Type:</strong> ${scan.scan_type || 'Unknown'}</p>
                    <p><strong>Targets:</strong> ${scan.targets || 'N/A'}</p>
                    <p><strong>Progress:</strong> ${scan.progress || 0}%</p>
                    <p><strong>Hosts Found:</strong> ${hosts.length}</p>
                    <p><strong>Start Time:</strong> ${scan.start_time || 'N/A'}</p>
                    ${scan.end_time ? `<p><strong>End Time:</strong> ${scan.end_time}</p>` : ''}
                </div>
                
                <div class="hosts-results">
                    ${hostsHtml}
                </div>
                
                <div class="result-actions">
                    <button onclick="app.scanner.exportResults('${scanId}', 'json')" class="btn btn-secondary">📄 Export JSON</button>
                    <button onclick="app.scanner.exportResults('${scanId}', 'csv')" class="btn btn-secondary">📊 Export CSV</button>
                    <button onclick="app.scanner.exportResults('${scanId}', 'html')" class="btn btn-secondary">🌐 Export HTML</button>
                    <button onclick="app.scanner.viewDetailedResults('${scanId}')" class="btn btn-primary">🔍 View Details</button>
                </div>
            </div>
        `;
        reportContainer.style.display = 'block';
    }

    renderHostResults(host) {
        if (!host) return '';
        
        const ports = host.ports || [];
        const vulnerabilities = host.vulnerabilities || [];
        
        let portsHtml = '';
        if (ports.length > 0) {
            portsHtml = `
                <table class="ports-table">
                    <thead>
                        <tr>
                            <th>🔌 Port</th>
                            <th>🌐 Protocol</th>
                            <th>📊 State</th>
                            <th>🔧 Service</th>
                            <th>📋 Version</th>
                            <th>🏷️ Banner</th>
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
        
        let vulnsHtml = '';
        if (vulnerabilities.length > 0) {
            vulnsHtml = `
                <h4>⚠️ Vulnerabilities Found:</h4>
                <ul>
                    ${vulnerabilities.map(vuln => `
                        <li><strong>${vuln.title || 'Unknown'}</strong> - ${vuln.description || 'No description'} (${vuln.severity || 'Unknown'})</li>
                    `).join('')}
                </ul>
            `;
        }
        
        return `
            <div class="host-result">
                <h4>🖥️ Host: ${host.ip_address || 'Unknown'}</h4>
                <div class="host-info">
                    <p><strong>Status:</strong> <span class="status-${host.status || 'unknown'}">${host.status || 'Unknown'}</span></p>
                    ${host.hostname ? `<p><strong>Hostname:</strong> ${host.hostname}</p>` : ''}
                    ${host.os_info ? `<p><strong>OS:</strong> ${host.os_info.name || 'Unknown'}</p>` : ''}
                    <p><strong>Open Ports:</strong> ${host.open_ports_count || 0}</p>
                </div>
                
                <div class="ports-section">
                    <h5>🔌 Port Scan Results:</h5>
                    ${portsHtml}
                </div>
                
                ${vulnsHtml}
            </div>
        `;
    }

    async exportResults(scanId, format) {
        if (!scanId) {
            window.handleError(new Error('No scan ID provided for export'));
            return;
        }
        
        try {
            const response = await fetch(`/api/scan/export/${scanId}?format=${format}`);
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
                    window.showSuccess(`Results exported as ${format.toUpperCase()}`);
                }
            } else {
                throw new Error(data.message || 'Failed to export results');
            }
        } catch (error) {
            console.error('Error exporting results:', error);
            window.handleError(error);
        }
    }

    async viewDetailedResults(scanId) {
        if (!scanId) {
            window.handleError(new Error('No scan ID provided for detailed view'));
            return;
        }
        
        try {
            const response = await fetch(`/api/scan/results/${scanId}`);
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.showDetailedResults(data.results);
            } else {
                throw new Error(data.message || 'Failed to load detailed results');
            }
        } catch (error) {
            console.error('Error loading detailed results:', error);
            window.handleError(error);
        }
    }

    showDetailedResults(results) {
        // Create a modal or expand the results section with detailed information
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close">&times;</span>
                <h2>🔍 Detailed Scan Results</h2>
                <pre>${JSON.stringify(results, null, 2)}</pre>
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

    async refreshScanHistory() {
        try {
            const response = await fetch('/api/history/scans');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    this.displayScanHistory(data.scans);
                }
            }
        } catch (error) {
            console.warn('Could not refresh scan history:', error);
        }
    }

    displayScanHistory(scans) {
        const tbody = document.getElementById('scans-list');
        if (!tbody) return;

        if (scans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="text-center">No scans found</td></tr>';
            return;
        }

        tbody.innerHTML = scans.map(scan => `
            <tr>
                <td>${scan.start_time ? new Date(scan.start_time).toLocaleString() : 'N/A'}</td>
                <td>${scan.scan_type || 'Unknown'}</td>
                <td><span class="status-${scan.status || 'unknown'}">${scan.status || 'Unknown'}</span></td>
                <td>${scan.targets || 'N/A'}</td>
                <td>${scan.hosts_count || 0}</td>
                <td>${scan.progress || 0}%</td>
                <td>
                    <button onclick="app.scanner.viewScan('${scan.scan_id}')" class="btn btn-sm btn-primary">👁️ View</button>
                    <button onclick="app.scanner.exportResults('${scan.scan_id}', 'json')" class="btn btn-sm btn-secondary">📄 JSON</button>
                    <button onclick="app.scanner.deleteScan('${scan.scan_id}')" class="btn btn-sm btn-danger">🗑️ Delete</button>
                </td>
            </tr>
        `).join('');
    }

    async viewScan(scanId) {
        await this.loadResults(scanId);
    }

    async deleteScan(scanId) {
        if (!confirm('Are you sure you want to delete this scan?')) {
            return;
        }

        try {
            const response = await fetch(`/api/scan/delete/${scanId}`, {
                method: 'DELETE'
            });

            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    if (window.showSuccess) {
                        window.showSuccess('Scan deleted successfully');
                    }
                    this.refreshScanHistory();
                }
            }
        } catch (error) {
            console.error('Error deleting scan:', error);
            window.handleError(error);
        }
    }

    async cleanupCompletedScans() {
        if (!confirm('Are you sure you want to cleanup all completed scans?')) {
            return;
        }

        try {
            const response = await fetch('/api/scan/cleanup', {
                method: 'POST'
            });

            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    if (window.showSuccess) {
                        window.showSuccess('Cleanup completed successfully');
                    }
                    this.refreshScanHistory();
                }
            }
        } catch (error) {
            console.error('Error during cleanup:', error);
            window.handleError(error);
        }
    }

    async showStatistics() {
        try {
            const response = await fetch('/api/scan/statistics');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    this.displayStatistics(data.statistics);
                }
            }
        } catch (error) {
            console.error('Error loading statistics:', error);
            window.handleError(error);
        }
    }

    displayStatistics(statistics) {
        const modal = document.createElement('div');
        modal.className = 'modal';
        modal.style.display = 'block';
        modal.innerHTML = `
            <div class="modal-content">
                <span class="close">&times;</span>
                <h2>📊 Scan Statistics</h2>
                <div class="statistics-content">
                    <div class="stat-item">
                        <strong>Total Scans:</strong> ${statistics.total_scans}
                    </div>
                    <div class="stat-item">
                        <strong>Completed:</strong> ${statistics.completed_scans}
                    </div>
                    <div class="stat-item">
                        <strong>Failed:</strong> ${statistics.failed_scans}
                    </div>
                    <div class="stat-item">
                        <strong>Running:</strong> ${statistics.running_scans}
                    </div>
                    <div class="stat-item">
                        <strong>Success Rate:</strong> ${statistics.success_rate.toFixed(1)}%
                    </div>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        const closeBtn = modal.querySelector('.close');
        if (closeBtn) {
            closeBtn.onclick = () => modal.remove();
        }

        window.onclick = (event) => {
            if (event.target === modal) {
                modal.remove();
            }
        };
    }

    async exportAllScans() {
        try {
            const response = await fetch('/api/scan/export-all');
            if (response.ok) {
                const data = await response.json();
                if (data.status === 'success') {
                    const blob = new Blob([JSON.stringify(data.data, null, 2)], { type: 'application/json' });
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = `all_scans_${new Date().toISOString().split('T')[0]}.json`;
                    a.click();
                    window.URL.revokeObjectURL(url);
                    
                    if (window.showSuccess) {
                        window.showSuccess('All scans exported successfully');
                    }
                }
            }
        } catch (error) {
            console.error('Error exporting all scans:', error);
            window.handleError(error);
        }
    }

    initializeStatusCheck() {
        // Check if there are any running scans on page load
        this.checkForRunningScans();
        // Load initial scan history
        this.refreshScanHistory();
    }

    async checkForRunningScans() {
        try {
            const response = await fetch('/api/scan/active');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            
            if (data.status === 'success' && data.active_scans && data.active_scans.length > 0) {
                const runningScan = data.active_scans[0];
                this.currentScanId = runningScan.scan_id;
                this.startStatusCheck(runningScan.scan_id);
                this.showStatusPanel();
                this.setFormEnabled(false);
            }
        } catch (error) {
            console.warn('Could not check for running scans:', error);
        }
    }
}