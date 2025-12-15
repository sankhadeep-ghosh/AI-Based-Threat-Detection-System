/**
 * Dashboard JavaScript - Modern IDS Dashboard
 * Handles WebSocket communication, real-time updates, and Chart.js visualizations
 */

// Global state
let socket = null;
let charts = {};
let alertCache = new Set();
let isConnected = false;
let lastStatsTimestamp = 0;
let statsUpdateInterval = null;

// Severity color mapping
const severityColors = {
    'critical': '#dc3545',
    'high': '#fd7e14',
    'medium': '#ffc107',
    'low': '#28a745'
};

// Initialize dashboard when page loads
document.addEventListener('DOMContentLoaded', function() {
    initCharts();
    connectWebSocket();
    loadInitialData();
    setupAutoRefresh();
});

/**
 * Initialize Chart.js visualizations with modern styling
 */
function initCharts() {
    // Chart default options for dark theme
    Chart.defaults.color = '#9ca3af';
    Chart.defaults.borderColor = '#2a3142';

    // Severity distribution chart
    const severityCtx = document.getElementById('severity-chart').getContext('2d');
    charts.severity = new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#dc3545',
                    '#fd7e14',
                    '#ffc107',
                    '#28a745'
                ],
                borderColor: '#1a1f2e',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 15,
                        font: { size: 12 }
                    }
                }
            }
        }
    });

    // Alert type distribution chart
    const typeCtx = document.getElementById('type-chart').getContext('2d');
    charts.type = new Chart(typeCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Count',
                data: [],
                backgroundColor: '#667eea',
                borderColor: '#667eea',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            indexAxis: 'y',
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { precision: 0 }
                }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

/**
 * Establish WebSocket connection to server
 */
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}`;
    
    socket = io(wsUrl, {
        transports: ['websocket', 'polling'],  // WebSocket first for real-time
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 10,
        upgrade: true
    });

    socket.on('connect', function() {
        console.log('✓ Connected to IDS server');
        isConnected = true;
        updateConnectionStatus(true);
        socket.emit('request_alerts', { limit: 50 });
    });

    socket.on('disconnect', function() {
        console.log('✗ Disconnected from IDS server');
        isConnected = false;
        updateConnectionStatus(false);
    });

    socket.on('new_alert', function(data) {
        if (data && data.alert) {
            console.log('✓ New alert received:', data.alert.alert_type);
            addAlertToUI(data.alert);
            updateMetrics();
            // Show notification
            showNotification(`${data.alert.alert_type} detected from ${data.alert.source_ip}`, 'alert');
        }
    });

    socket.on('alerts_update', function(data) {
        if (data && data.alerts) {
            console.log('✓ Alerts list updated:', data.alerts.length);
            updateAlertsList(data.alerts);
        }
    });

    socket.on('stats_update', function(data) {
        if (data && data.stats) {
            console.log('✓ Real-time stats update:', data.stats);
            updateCharts(data.stats);
            updateMetrics(data.stats);
            updatePacketStats(data.stats);
            lastStatsTimestamp = Date.now();
        }
    });

    socket.on('error', function(data) {
        console.error('Server error:', data);
        showNotification('Server Error: ' + (data.message || 'Unknown error'), 'error');
    });

    socket.on('connected', function(data) {
        console.log('✓ Server connected message:', data.data);
    });
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    const statusBadge = document.getElementById('status-badge');
    
    if (connected) {
        statusEl.innerHTML = '<i class="fas fa-circle"></i><span>Connected</span>';
        statusEl.className = 'connection-status connected';
        statusEl.style.backgroundColor = 'rgba(40, 167, 69, 0.2)';
        statusEl.style.color = '#28a745';
        statusEl.style.borderColor = '#28a745';
        
        statusBadge.innerHTML = '<i class="fas fa-check-circle"></i> Online';
        statusBadge.className = 'badge bg-success';
    } else {
        statusEl.innerHTML = '<i class="fas fa-circle"></i><span>Disconnected</span>';
        statusEl.className = 'connection-status disconnected';
        statusEl.style.backgroundColor = 'rgba(220, 53, 69, 0.2)';
        statusEl.style.color = '#dc3545';
        statusEl.style.borderColor = '#dc3545';
        
        statusBadge.innerHTML = '<i class="fas fa-exclamation-circle"></i> Offline';
        statusBadge.className = 'badge bg-danger';
    }
}

/**
 * Load initial data on page load
 */
async function loadInitialData() {
    try {
        // Load alert stats
        const statsResponse = await fetch('/api/stats');
        const stats = await statsResponse.json();
        updateCharts(stats);
        updateMetrics(stats);
        updatePacketStats(stats);

        // Load recent alerts
        const alertsResponse = await fetch('/api/alerts?limit=30');
        const data = await alertsResponse.json();
        const alerts = data.alerts || [];
        updateAlertsList(alerts);
    } catch (error) {
        console.error('Error loading initial data:', error);
        showNotification('Failed to load initial data', 'error');
    }
}

/**
 * Update charts with new data
 */
function updateCharts(stats) {
    if (!stats) return;

    const dbStats = stats.database || stats;
    
    if (dbStats.by_severity) {
        const severityData = {
            critical: dbStats.by_severity.CRITICAL || dbStats.by_severity.critical || 0,
            high: dbStats.by_severity.HIGH || dbStats.by_severity.high || 0,
            medium: dbStats.by_severity.MEDIUM || dbStats.by_severity.medium || 0,
            low: dbStats.by_severity.LOW || dbStats.by_severity.low || 0
        };

        charts.severity.data.datasets[0].data = [
            severityData.critical,
            severityData.high,
            severityData.medium,
            severityData.low
        ];
        charts.severity.update();
    }

    if (dbStats.by_type) {
        const typeLabels = Object.keys(dbStats.by_type).slice(0, 8);
        const typeData = Object.values(dbStats.by_type).slice(0, 8);

        charts.type.data.labels = typeLabels;
        charts.type.data.datasets[0].data = typeData;
        charts.type.update();
    }
}

/**
 * Update metric displays for alerts
 */
function updateMetrics(stats) {
    if (!stats) return;

    const dbStats = stats.database || stats;

    if (dbStats.by_severity) {
        const critical = dbStats.by_severity.CRITICAL || dbStats.by_severity.critical || 0;
        const high = dbStats.by_severity.HIGH || dbStats.by_severity.high || 0;
        const total = dbStats.total_alerts || 0;

        const totalAlertsEl = document.getElementById('total-alerts');
        const criticalEl = document.getElementById('critical-count');
        const highEl = document.getElementById('high-count');

        // Update with animation effect if values changed
        if (totalAlertsEl.textContent !== total.toString()) {
            totalAlertsEl.textContent = total;
            totalAlertsEl.style.animation = 'none';
            setTimeout(() => {
                totalAlertsEl.style.animation = 'pulse 0.6s ease-out';
            }, 10);
        }

        if (criticalEl.textContent !== critical.toString()) {
            criticalEl.textContent = critical;
            criticalEl.style.animation = 'none';
            setTimeout(() => {
                criticalEl.style.animation = 'pulse 0.6s ease-out';
            }, 10);
        }

        if (highEl.textContent !== high.toString()) {
            highEl.textContent = high;
            highEl.style.animation = 'none';
            setTimeout(() => {
                highEl.style.animation = 'pulse 0.6s ease-out';
            }, 10);
        }
    }

    if (stats.engine && stats.engine.capture) {
        const packetRate = stats.engine.capture.capture_rate || 0;
        const packetRateEl = document.getElementById('packet-rate');
        packetRateEl.textContent = packetRate.toFixed(1);
    }
}

/**
 * Update packet statistics with real-time values
 */
function updatePacketStats(stats) {
    if (!stats) {
        console.warn('updatePacketStats: stats is null/undefined');
        return;
    }

    const engineStats = stats.engine || {};
    const captureStats = engineStats.capture || {};

    console.log('Packet Stats Update:', {
        engineStats: engineStats,
        captureStats: captureStats,
        packets_captured: captureStats.packets_captured
    });

    // Total packets captured
    const totalPackets = captureStats.packets_captured || 0;
    const totalPacketsEl = document.getElementById('total-packets');
    if (totalPacketsEl) {
        const oldValue = totalPacketsEl.textContent;
        if (oldValue !== totalPackets.toString()) {
            console.log(`Updated total packets: ${oldValue} → ${totalPackets}`);
            totalPacketsEl.textContent = totalPackets;
            totalPacketsEl.style.animation = 'none';
            setTimeout(() => {
                totalPacketsEl.style.animation = 'pulse 0.6s ease-out';
            }, 10);
        }
    } else {
        console.warn('total-packets element not found');
    }

    // Malicious packets (equals total alerts)
    const maliciousPackets = (stats.database && stats.database.total_alerts) || 0;
    const maliciousEl = document.getElementById('malicious-packets');
    if (maliciousEl) {
        const oldValue = maliciousEl.textContent;
        if (oldValue !== maliciousPackets.toString()) {
            console.log(`Updated malicious packets: ${oldValue} → ${maliciousPackets}`);
            maliciousEl.textContent = maliciousPackets;
            maliciousEl.style.animation = 'none';
            setTimeout(() => {
                maliciousEl.style.animation = 'pulse 0.6s ease-out';
            }, 10);
        }
    } else {
        console.warn('malicious-packets element not found');
    }
}

/**
 * Update alerts list in UI
 */
function updateAlertsList(alerts) {
    const container = document.getElementById('alerts-container');
    
    if (!alerts || alerts.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-inbox"></i>
                <p>No alerts found. Your network looks secure!</p>
            </div>
        `;
        return;
    }

    alertCache.clear();
    container.innerHTML = '';

    alerts.forEach(alert => {
        addAlertToUI(alert);
    });
}

/**
 * Add single alert to UI
 */
function addAlertToUI(alert) {
    if (!alert) return;

    const alertId = `${alert.rule_id || 'unknown'}-${alert.timestamp}`;
    if (alertCache.has(alertId)) return;
    alertCache.add(alertId);

    const container = document.getElementById('alerts-container');
    
    // Clear empty state if first alert
    if (container.querySelector('.empty-state')) {
        container.innerHTML = '';
    }

    const timestamp = new Date(alert.timestamp).toLocaleString();
    const sourcePort = alert.source_port || '*';
    const destPort = alert.dest_port || '*';
    const severity = (alert.severity || 'unknown').toLowerCase();
    
        const alertCard = document.createElement('div');
    alertCard.className = `alert-card severity-${severity}`;
    
    alertCard.innerHTML = `
        <div>
            <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 4px;">
                <h6 style="margin: 0; font-weight: 600; font-size: 0.75rem;">${alert.name || 'Unknown Alert'}</h6>
                <span class="badge bg-${getSeverityClass(severity)}" style="white-space: nowrap; font-size: 0.6rem; padding: 2px 6px;">
                    ${severity.toUpperCase()}
                </span>
            </div>
            <p style="margin: 2px 0; color: #9ca3af; font-size: 0.7rem;">${alert.message || 'No description'}</p>
            <small style="font-family: 'Courier New', monospace; display: block; margin-top: 4px; font-size: 0.65rem;">
                <strong>Source:</strong> ${alert.source_ip}:${sourcePort} → 
                <strong>Dest:</strong> ${alert.dest_ip}:${destPort}
            </small>
            <small style="color: #666; margin-top: 2px; display: block; font-size: 0.65rem;">${timestamp}</small>
        </div>
    `;    container.insertBefore(alertCard, container.firstChild);
    
    // Limit displayed alerts to 50
    const maxAlerts = 30;
    while (container.children.length > maxAlerts) {
        container.removeChild(container.lastChild);
    }
}

/**
 * Get Bootstrap class for severity
 */
function getSeverityClass(severity) {
    const mapping = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'success'
    };
    return mapping[severity] || 'secondary';
}

/**
 * Refresh alerts manually
 */
async function refreshAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=50');
        const data = await response.json();
        const alerts = data.alerts || [];
        updateAlertsList(alerts);
        showNotification('✓ Alerts refreshed', 'success');
    } catch (error) {
        console.error('Error refreshing alerts:', error);
        showNotification('Failed to refresh alerts', 'error');
    }
}

/**
 * Setup auto-refresh for stats - both WebSocket (real-time) and polling (fallback)
 */
function setupAutoRefresh() {
    // Real-time updates via WebSocket broadcasts (server pushes stats every 5 seconds)
    // Dashboard will receive stats_update events automatically
    
    // Fallback: Also poll REST API every 2 seconds for extra real-time feel
    // This ensures updates even if WebSocket broadcasts are missed
    setInterval(async () => {
        try {
            const response = await fetch('/api/stats');
            const stats = await response.json();
            updateCharts(stats);
            updateMetrics(stats);
            updatePacketStats(stats);
        } catch (error) {
            // Silently fail - WebSocket will provide updates
        }
    }, 2000); // 2 second poll rate for smooth updates
}

/**
 * Show notification to user
 */
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    const bgClass = type === 'error' ? 'bg-danger' : `bg-${type}`;
    
    notification.className = `alert ${bgClass} alert-dismissible fade show`;
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        border: none;
        border-radius: 8px;
    `;
    
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 5000);
}

