// Main Application Class
class MainApplication {
    constructor() {
        this.scanner = null;
        this.reports = null;
        this.theme = 'light';
        this.init();
    }

    init() {
        this.setupTheme();
        this.setupGlobalErrorHandling();
        this.setupSuccessNotifications();
        this.setupNotificationSystem();
        this.setupUtilityFunctions();
        this.setupKeyboardShortcuts();
        this.initializeComponents();
    }

    setupTheme() {
        // Load saved theme
        const savedTheme = localStorage.getItem('theme') || 'light';
        this.setTheme(savedTheme);
        
        // Setup theme toggle
        const themeToggle = document.getElementById('theme-switcher');
        if (themeToggle) {
            themeToggle.checked = savedTheme === 'dark';
            themeToggle.addEventListener('change', (e) => {
                const newTheme = e.target.checked ? 'dark' : 'light';
                this.setTheme(newTheme);
            });
        }
    }

    setTheme(theme) {
        this.theme = theme;
        // Remove existing theme classes
        document.body.classList.remove('theme-light', 'theme-dark');
        // Add new theme class
        document.body.classList.add(`theme-${theme}`);
        localStorage.setItem('theme', theme);
        
        // Update theme toggle if it exists
        const themeToggle = document.getElementById('theme-switcher');
        if (themeToggle) {
            themeToggle.checked = theme === 'dark';
        }
    }

    setupGlobalErrorHandling() {
        window.handleError = (error) => {
            console.error('Application error:', error);
            
            const errorMessage = document.getElementById('error-message');
            if (errorMessage) {
                errorMessage.textContent = error.message || 'An unexpected error occurred';
                errorMessage.style.display = 'block';
                
                // Auto-hide after 5 seconds
                setTimeout(() => {
                    errorMessage.style.display = 'none';
                }, 5000);
            }
            
            // Show notification if available
            if (window.showNotification) {
                window.showNotification(error.message || 'An error occurred', 'error');
            }
        };
    }

    setupSuccessNotifications() {
        window.showSuccess = (message) => {
            console.log('Success:', message);
            
            // Show notification if available
            if (window.showNotification) {
                window.showNotification(message, 'success');
            } else {
                // Fallback to alert
                alert(message);
            }
        };
    }

    setupNotificationSystem() {
        window.showNotification = (message, type = 'info') => {
            // Create notification element
            const notification = document.createElement('div');
            notification.className = `notification notification-${type}`;
            notification.innerHTML = `
                <div class="notification-content">
                    <span class="notification-message">${message}</span>
                    <button class="notification-close">&times;</button>
                </div>
            `;
            
            // Add to page
            document.body.appendChild(notification);
            
            // Show notification
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                window.hideNotification(notification);
            }, 5000);
            
            // Close button functionality
            const closeBtn = notification.querySelector('.notification-close');
            if (closeBtn) {
                closeBtn.addEventListener('click', () => {
                    window.hideNotification(notification);
                });
            }
        };

        window.hideNotification = (notification) => {
            if (notification) {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (notification.parentNode) {
                        notification.parentNode.removeChild(notification);
                    }
                }, 300);
            }
        };
    }

    setupUtilityFunctions() {
        window.utils = {
            // Format bytes to human readable format
            formatBytes: function(bytes, decimals = 2) {
                if (bytes === 0) return '0 Bytes';
                
                const k = 1024;
                const dm = decimals < 0 ? 0 : decimals;
                const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
                
                const i = Math.floor(Math.log(bytes) / Math.log(k));
                
                return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
            },
            
            // Format duration in seconds to human readable format
            formatDuration: function(seconds) {
                if (seconds < 60) return `${seconds}s`;
                if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
                const hours = Math.floor(seconds / 3600);
                const minutes = Math.floor((seconds % 3600) / 60);
                return `${hours}h ${minutes}m`;
            },
            
            // Debounce function
            debounce: function(func, wait) {
                let timeout;
                return function executedFunction(...args) {
                    const later = () => {
                        clearTimeout(timeout);
                        func(...args);
                    };
                    clearTimeout(timeout);
                    timeout = setTimeout(later, wait);
                };
            },
            
            // Throttle function
            throttle: function(func, limit) {
                let inThrottle;
                return function() {
                    const args = arguments;
                    const context = this;
                    if (!inThrottle) {
                        func.apply(context, args);
                        inThrottle = true;
                        setTimeout(() => inThrottle = false, limit);
                    }
                };
            },
            
            // Safe DOM query selector
            safeQuerySelector: function(selector, parent = document) {
                try {
                    return parent.querySelector(selector);
                } catch (error) {
                    console.warn(`Invalid selector: ${selector}`, error);
                    return null;
                }
            },
            
            // Safe DOM query selector all
            safeQuerySelectorAll: function(selector, parent = document) {
                try {
                    return parent.querySelectorAll(selector);
                } catch (error) {
                    console.warn(`Invalid selector: ${selector}`, error);
                    return [];
                }
            }
        };
    }

    setupKeyboardShortcuts() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + Enter to start scan
            if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                const scanForm = document.getElementById('scan-form');
                if (scanForm) {
                    scanForm.dispatchEvent(new Event('submit'));
                }
            }
            
            // Escape to close modals
            if (e.key === 'Escape') {
                const modals = document.querySelectorAll('.modal');
                modals.forEach(modal => {
                    if (modal.style.display === 'block') {
                        modal.remove();
                    }
                });
            }
        });
    }

    initializeComponents() {
        try {
            // Initialize scanner
            if (typeof Scanner !== 'undefined') {
                this.scanner = new Scanner();
                this.scanner.initializeStatusCheck();
            } else {
                console.warn('Scanner class not found');
            }
            
            // Initialize reports
            if (typeof Reports !== 'undefined') {
                this.reports = new Reports();
            } else {
                console.warn('Reports class not found');
            }
            
            console.log('Application initialized successfully');
        } catch (error) {
            console.error('Error initializing components:', error);
            window.handleError(error);
        }
    }
}

// Initialize application when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    try {
        window.app = new MainApplication();
    } catch (error) {
        console.error('Failed to initialize application:', error);
        // Show error message to user
        const errorMessage = document.getElementById('error-message');
        if (errorMessage) {
            errorMessage.textContent = 'Failed to initialize application. Please refresh the page.';
            errorMessage.style.display = 'block';
        }
    }
});