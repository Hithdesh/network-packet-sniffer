// ==========================================================================
// SOC Intrusion Detection System Dashboard Script
// Handles WebSockets, UI Tabs, Chart.js updates, and REST API communications.
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
    // ----------------------------------------------------------------------
    // UI Elements Selector Constants
    // ----------------------------------------------------------------------
    const sidebarItems = document.querySelectorAll(".sidebar-nav li");
    const tabContents = document.querySelectorAll(".tab-content");
    const interfaceSelector = document.getElementById("interface-selector");
    const btnToggleCapture = document.getElementById("btn-toggle-capture");
    const globalStatusDot = document.getElementById("global-status-dot");
    const globalStatusText = document.getElementById("global-status-text");

    // Metric Values
    const valTotalPackets = document.getElementById("val-total-packets");
    const valTotalAlerts = document.getElementById("val-total-alerts");
    const valTcpCount = document.getElementById("val-tcp-count");
    const valUdpCount = document.getElementById("val-udp-count");
    const valIcmpCount = document.getElementById("val-icmp-count");
    const badgeLiveAlertsCount = document.getElementById("badge-live-alerts-count");
    const valPacketRatePs = document.getElementById("val-packet-rate-ps");

    // Feeds Containers
    const liveAlertsFeed = document.getElementById("live-alerts-feed-container");
    const livePacketTbody = document.getElementById("live-packet-tbody");

    // Historical Logs Tab Tables
    const historicalAlertsTbody = document.getElementById("historical-alerts-tbody");
    const historicalPacketsTbody = document.getElementById("historical-packets-tbody");
    const btnRefreshAlerts = document.getElementById("btn-refresh-alerts");
    const btnRefreshPackets = document.getElementById("btn-refresh-packets");

    // Diagnostic labels
    const diagAdmin = document.getElementById("diag-admin");
    const diagNpcap = document.getElementById("diag-npcap");
    const privilegeWarningModal = document.getElementById("privilege-warning-modal");

    // ----------------------------------------------------------------------
    // State Variables
    // ----------------------------------------------------------------------
    let socket = null;
    let isCaptureActive = false;
    let newAlertsCount = 0;
    
    // Packet Rate calculation window variables
    let secondPacketsCount = 0;
    let rateIntervalId = null;

    // Charts references
    let chartProtocol = null;
    let chartPacketRate = null;
    let chartTopSources = null;
    let chartTopDestinations = null;
    let chartAlertsTrend = null;

    // Internal stats mapping
    let stats = {
        totalPackets: 0,
        totalAlerts: 0,
        protocols: { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, ARP: 0, Other: 0 },
        topSources: {},
        topDestinations: {},
        rateTimeline: [], // sliding window of packet counts [seconds]
        alertsTimeline: []
    };

    // ----------------------------------------------------------------------
    // Chart.js Configuration & Initialization
    // ----------------------------------------------------------------------
    function initCharts() {
        const ctxProto = document.getElementById("chart-protocol").getContext("2d");
        const ctxRate = document.getElementById("chart-packet-rate").getContext("2d");
        const ctxSrc = document.getElementById("chart-top-sources").getContext("2d");
        const ctxDst = document.getElementById("chart-top-destinations").getContext("2d");
        const ctxTrend = document.getElementById("chart-alerts-trend").getContext("2d");

        const chartColors = ['#00b4d8', '#ffd166', '#06d6a0', '#ef476f', '#e040fb', '#94a3b8'];

        // 1. Protocol Doughnut
        chartProtocol = new Chart(ctxProto, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0, 0, 0],
                    backgroundColor: chartColors,
                    borderWidth: 1,
                    borderColor: '#0b1226'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } }
                }
            }
        });

        // 2. Packet Rate Line Chart (Rolling 60 seconds / data points)
        const rateLabels = Array.from({length: 12}, (_, i) => `${(12-i)*5}s ago`);
        chartPacketRate = new Chart(ctxRate, {
            type: 'line',
            data: {
                labels: rateLabels,
                datasets: [{
                    label: 'Packets',
                    data: Array(12).fill(0),
                    borderColor: '#00b4d8',
                    backgroundColor: 'rgba(0, 180, 216, 0.15)',
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' }, beginAtZero: true }
                },
                plugins: { legend: { display: false } }
            }
        });

        // 3. Top Source IPs Horizontal Bar
        chartTopSources = new Chart(ctxSrc, {
            type: 'bar',
            data: {
                labels: ['N/A', 'N/A', 'N/A', 'N/A', 'N/A'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(0, 180, 216, 0.7)',
                    borderWidth: 0
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' }, beginAtZero: true },
                    y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // 4. Top Destination IPs Horizontal Bar
        chartTopDestinations = new Chart(ctxDst, {
            type: 'bar',
            data: {
                labels: ['N/A', 'N/A', 'N/A', 'N/A', 'N/A'],
                datasets: [{
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: 'rgba(156, 39, 176, 0.7)',
                    borderWidth: 0
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' }, beginAtZero: true },
                    y: { grid: { display: false }, ticks: { color: '#94a3b8' } }
                },
                plugins: { legend: { display: false } }
            }
        });

        // 5. Alerts Trend Line Chart
        chartAlertsTrend = new Chart(ctxTrend, {
            type: 'line',
            data: {
                labels: Array.from({length: 10}, (_, i) => `T-${10-i}`),
                datasets: [{
                    label: 'Alerts Triggered',
                    data: Array(10).fill(0),
                    borderColor: '#ef476f',
                    backgroundColor: 'rgba(239, 71, 111, 0.1)',
                    fill: true,
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' } },
                    y: { grid: { color: 'rgba(255, 255, 255, 0.03)' }, ticks: { color: '#94a3b8' }, beginAtZero: true, stepSize: 1 }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // ----------------------------------------------------------------------
    // UI Navigation logic
    // ----------------------------------------------------------------------
    sidebarItems.forEach(item => {
        item.addEventListener("click", () => {
            // Remove active classes
            sidebarItems.forEach(el => el.classList.remove("active"));
            tabContents.forEach(content => content.classList.remove("active"));

            // Add active status to clicked tab
            item.classList.add("active");
            const target = item.getAttribute("data-target");
            const targetContent = document.getElementById(target);
            targetContent.classList.add("active");

            // Auto-load tab data on activation
            if (target === "alerts-section") {
                fetchAlertLogs();
            } else if (target === "packets-section") {
                fetchPacketLogs();
            } else if (target === "dashboard-section") {
                // reset dashboard tab alert notification badges
                newAlertsCount = 0;
                badgeLiveAlertsCount.textContent = "0 New";
                badgeLiveAlertsCount.style.display = "none";
            }
        });
    });

    // ----------------------------------------------------------------------
    // API Requests
    // ----------------------------------------------------------------------
    
    // Fetch available Interfaces
    function fetchInterfaces() {
        fetch('/api/interfaces')
            .then(res => res.json())
            .then(data => {
                // Clear selector
                interfaceSelector.innerHTML = '<option value="" disabled selected>Select Interface...</option>';
                data.forEach(iface => {
                    const option = document.createElement("option");
                    option.value = iface.guid;
                    option.textContent = `${iface.description} (${iface.ip})`;
                    interfaceSelector.appendChild(option);
                });
            })
            .catch(err => console.error("Error loading interfaces:", err));
    }

    // Fetch System Diagnostic Info
    function fetchSystemDiagnostic() {
        fetch('/api/status')
            .then(res => res.json())
            .then(data => {
                // Update diagnostic tags
                if (data.admin_privileges) {
                    diagAdmin.textContent = "Granted";
                    diagAdmin.className = "value badge badge-green";
                } else {
                    diagAdmin.textContent = "Required";
                    diagAdmin.className = "value badge badge-red";
                }

                if (data.npcap_installed) {
                    diagNpcap.textContent = "Active";
                    diagNpcap.className = "value badge badge-green";
                } else {
                    diagNpcap.textContent = "Missing";
                    diagNpcap.className = "value badge badge-yellow";
                }

                // If not admin and not npcap, warn via Modal
                if (!data.admin_privileges && !data.npcap_installed) {
                    privilegeWarningModal.classList.add("active");
                }

                // Sync status buttons on refresh
                if (data.is_sniffing || data.is_simulation) {
                    setCaptureStateActive(data.active_interface);
                } else {
                    setCaptureStateIdle();
                }
            })
            .catch(err => console.error("Error loading diagnostics:", err));
    }

    // Pull historical stats and pre-populate local model
    function fetchDashboardStats() {
        fetch('/api/stats')
            .then(res => res.json())
            .then(data => {
                stats.totalPackets = data.total_packets;
                stats.totalAlerts = data.total_alerts;
                stats.protocols.TCP = data.tcp_count;
                stats.protocols.UDP = data.udp_count;
                stats.protocols.ICMP = data.icmp_count;
                
                // Fetch other protocols count
                const other = Math.max(0, data.total_packets - (data.tcp_count + data.udp_count + data.icmp_count));
                stats.protocols.Other = other;

                // Sync counts to HTML UI
                valTotalPackets.textContent = stats.totalPackets.toLocaleString();
                valTotalAlerts.textContent = stats.totalAlerts.toLocaleString();
                valTcpCount.textContent = stats.protocols.TCP.toLocaleString();
                valUdpCount.textContent = stats.protocols.UDP.toLocaleString();
                valIcmpCount.textContent = stats.protocols.ICMP.toLocaleString();

                updateProtocolChart();
            })
            .catch(err => console.error("Error loading stats:", err));

        // Pull historical packet records to extract Top Talkers
        fetch('/api/packets?limit=200')
            .then(res => res.json())
            .then(packets => {
                stats.topSources = {};
                stats.topDestinations = {};
                packets.forEach(pkt => {
                    if (pkt.src_ip) stats.topSources[pkt.src_ip] = (stats.topSources[pkt.src_ip] || 0) + 1;
                    if (pkt.dst_ip) stats.topDestinations[pkt.dst_ip] = (stats.topDestinations[pkt.dst_ip] || 0) + 1;
                });
                updateTopTalkersCharts();
            })
            .catch(err => console.error("Error fetching historical packets for top talkers:", err));
    }

    // Load recent database packets in Live Panel on start
    function preloadLiveFeeds() {
        // Load Packets
        fetch('/api/packets?limit=25')
            .then(res => res.json())
            .then(data => {
                if (data.length > 0) {
                    livePacketTbody.innerHTML = '';
                    data.forEach(pkt => appendPacketToTable(pkt, false));
                }
            })
            .catch(err => console.error("Error loading live packets history:", err));

        // Load Alerts
        fetch('/api/alerts?limit=15')
            .then(res => res.json())
            .then(data => {
                if (data.length > 0) {
                    // Clear placeholder
                    const placeholder = liveAlertsFeed.querySelector(".no-data-placeholder");
                    if (placeholder) placeholder.remove();
                    
                    data.forEach(alt => appendAlertToFeed(alt, false));
                }
            })
            .catch(err => console.error("Error loading live alerts history:", err));
    }

    // Refresh historical alerts list
    function fetchAlertLogs() {
        historicalAlertsTbody.innerHTML = '<tr><td colspan="6" class="text-center">Loading incident records...</td></tr>';
        fetch('/api/alerts?limit=100')
            .then(res => res.json())
            .then(data => {
                historicalAlertsTbody.innerHTML = '';
                if (data.length === 0) {
                    historicalAlertsTbody.innerHTML = '<tr><td colspan="6" class="text-center">No alerts logged in database.</td></tr>';
                    return;
                }
                data.forEach(row => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${row.id}</td>
                        <td>${row.timestamp}</td>
                        <td><span class="badge badge-red">${row.alert_type}</span></td>
                        <td>${row.source_ip}</td>
                        <td><span class="badge ${getSeverityBadgeClass(row.severity)}">${row.severity}</span></td>
                        <td style="max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${row.description}">${row.description}</td>
                    `;
                    historicalAlertsTbody.appendChild(tr);
                });
            })
            .catch(err => {
                historicalAlertsTbody.innerHTML = '<tr><td colspan="6" class="text-center text-red">Failed to load alerts data from database.</td></tr>';
                console.error(err);
            });
    }

    // Refresh historical packets list
    function fetchPacketLogs() {
        historicalPacketsTbody.innerHTML = '<tr><td colspan="8" class="text-center">Loading packet records...</td></tr>';
        fetch('/api/packets?limit=100')
            .then(res => res.json())
            .then(data => {
                historicalPacketsTbody.innerHTML = '';
                if (data.length === 0) {
                    historicalPacketsTbody.innerHTML = '<tr><td colspan="8" class="text-center">No packets saved in database.</td></tr>';
                    return;
                }
                data.forEach(row => {
                    const tr = document.createElement("tr");
                    tr.innerHTML = `
                        <td>${row.id}</td>
                        <td>${row.timestamp}</td>
                        <td><span class="proto-tag ${getProtoTagClass(row.protocol)}">${row.protocol}</span></td>
                        <td>${row.src_ip}</td>
                        <td>${row.src_port || 'N/A'}</td>
                        <td>${row.dst_ip}</td>
                        <td>${row.dst_port || 'N/A'}</td>
                        <td>${row.length} Bytes</td>
                    `;
                    historicalPacketsTbody.appendChild(tr);
                });
            })
            .catch(err => {
                historicalPacketsTbody.innerHTML = '<tr><td colspan="8" class="text-center text-red">Failed to load packets data from database.</td></tr>';
                console.error(err);
            });
    }

    // ----------------------------------------------------------------------
    // HTML Row and Card Insertion Helpers
    // ----------------------------------------------------------------------
    function getSeverityBadgeClass(severity) {
        switch (severity.toLowerCase()) {
            case 'high': return 'badge-red';
            case 'medium': return 'badge-yellow';
            case 'low': return 'badge-blue';
            default: return 'badge-grey';
        }
    }

    function getProtoTagClass(protocol) {
        switch (protocol.toLowerCase()) {
            case 'tcp': return 'proto-tcp';
            case 'udp': return 'proto-udp';
            case 'icmp': return 'proto-icmp';
            case 'dns': return 'proto-dns';
            case 'arp': return 'proto-arp';
            default: return 'proto-other';
        }
    }

    function appendPacketToTable(pkt, isLive = true) {
        // Remove placeholder if present
        const placeholder = livePacketTbody.querySelector(".placeholder-row");
        if (placeholder) placeholder.remove();

        const tr = document.createElement("tr");
        const flagText = pkt.flags ? `<code>[${pkt.flags}]</code>` : '-';
        tr.innerHTML = `
            <td>${pkt.timestamp.split(' ')[1]}</td>
            <td><span class="proto-tag ${getProtoTagClass(pkt.protocol)}">${pkt.protocol}</span></td>
            <td>${pkt.src_ip}${pkt.src_port ? ':' + pkt.src_port : ''}</td>
            <td>${pkt.dst_ip}${pkt.dst_port ? ':' + pkt.dst_port : ''}</td>
            <td>${pkt.length}</td>
            <td>${flagText}</td>
        `;

        if (isLive) {
            // Prepend new row
            livePacketTbody.insertBefore(tr, livePacketTbody.firstChild);
            // Cap to 50 rows in the DOM
            if (livePacketTbody.children.length > 50) {
                livePacketTbody.lastChild.remove();
            }
        } else {
            // Append historic preload
            livePacketTbody.appendChild(tr);
        }
    }

    function appendAlertToFeed(alt, isLive = true) {
        // Remove placeholder if present
        const placeholder = liveAlertsFeed.querySelector(".no-data-placeholder");
        if (placeholder) placeholder.remove();

        const card = document.createElement("div");
        card.className = `alert-feed-card severity-${alt.severity.toLowerCase()}`;
        
        card.innerHTML = `
            <div class="alert-card-meta">
                <span class="alert-card-type color-${alt.severity.toLowerCase()}">${alt.alert_type}</span>
                <span class="alert-card-time">${alt.timestamp.split(' ')[1]}</span>
            </div>
            <p class="alert-card-desc">${alt.description}</p>
            <div class="alert-card-source">
                <i class="fa-solid fa-circle-radiation"></i>
                <span>Source IP: <strong>${alt.source_ip}</strong></span>
            </div>
        `;

        if (isLive) {
            // Prepend alert card
            liveAlertsFeed.insertBefore(card, liveAlertsFeed.firstChild);
            // Cap alert items in viewport
            if (liveAlertsFeed.children.length > 25) {
                liveAlertsFeed.lastChild.remove();
            }
        } else {
            // Append historic preload
            liveAlertsFeed.appendChild(card);
        }
    }

    // ----------------------------------------------------------------------
    // Chart Update Helpers
    // ----------------------------------------------------------------------
    function updateProtocolChart() {
        if (!chartProtocol) return;
        chartProtocol.data.datasets[0].data = [
            stats.protocols.TCP,
            stats.protocols.UDP,
            stats.protocols.ICMP,
            stats.protocols.DNS,
            stats.protocols.ARP,
            stats.protocols.Other
        ];
        chartProtocol.update('none');
    }

    function updateTopTalkersCharts() {
        if (!chartTopSources || !chartTopDestinations) return;

        // Sort Sources
        const sortedSrc = Object.entries(stats.topSources)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        const srcLabels = sortedSrc.map(x => x[0]);
        const srcData = sortedSrc.map(x => x[1]);

        chartTopSources.data.labels = srcLabels.length > 0 ? srcLabels : Array(5).fill('N/A');
        chartTopSources.data.datasets[0].data = srcData.length > 0 ? srcData : Array(5).fill(0);
        chartTopSources.update('none');

        // Sort Destinations
        const sortedDst = Object.entries(stats.topDestinations)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 5);
        
        const dstLabels = sortedDst.map(x => x[0]);
        const dstData = sortedDst.map(x => x[1]);

        chartTopDestinations.data.labels = dstLabels.length > 0 ? dstLabels : Array(5).fill('N/A');
        chartTopDestinations.data.datasets[0].data = dstData.length > 0 ? dstData : Array(5).fill(0);
        chartTopDestinations.update('none');
    }

    // Real-Time moving rate monitor timeline (5-second segments loop)
    let packetsInLastInterval = 0;
    let alertsInLastInterval = 0;

    function runMetricsTimelineAggregator() {
        rateIntervalId = setInterval(() => {
            // Update Packets timeline
            if (chartPacketRate) {
                chartPacketRate.data.datasets[0].data.shift();
                chartPacketRate.data.datasets[0].data.push(packetsInLastInterval);
                chartPacketRate.update();
                packetsInLastInterval = 0;
            }

            // Update Alerts timeline
            if (chartAlertsTrend) {
                chartAlertsTrend.data.datasets[0].data.shift();
                chartAlertsTrend.data.datasets[0].data.push(alertsInLastInterval);
                chartAlertsTrend.update();
                alertsInLastInterval = 0;
            }
        }, 5000);
    }

    // ----------------------------------------------------------------------
    // Capture Controls
    // ----------------------------------------------------------------------
    btnToggleCapture.addEventListener("click", () => {
        if (!isCaptureActive) {
            // Start Sniffing
            const selectedIface = interfaceSelector.value;
            if (!selectedIface) {
                alert("Please select a physical network interface or choose Simulation Mode before starting capture.");
                return;
            }

            fetch('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: selectedIface })
            })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    setCaptureStateActive(selectedIface);
                    initWebSocket();
                } else {
                    alert(`Failed to start capture: ${data.message}`);
                }
            })
            .catch(err => {
                console.error("Start capture error:", err);
                alert("An error occurred trying to connect to the backend sniffer.");
            });
        } else {
            // Stop Sniffing
            fetch('/api/stop', { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                if (data.success) {
                    setCaptureStateIdle();
                    disconnectWebSocket();
                } else {
                    alert(`Failed to stop capture: ${data.message}`);
                }
            })
            .catch(err => console.error("Stop capture error:", err));
        }
    });

    function setCaptureStateActive(interfaceGuid) {
        isCaptureActive = true;
        btnToggleCapture.innerHTML = '<i class="fa-solid fa-stop"></i> Stop Capture';
        btnToggleCapture.className = "btn-control stop";
        interfaceSelector.disabled = true;

        globalStatusDot.className = "pulse-dot active";
        globalStatusText.textContent = `Capturing [${interfaceGuid === 'simulation' ? 'SIM' : 'LIVE'}]`;

        // Start metrics timer logging
        packetsInLastInterval = 0;
        alertsInLastInterval = 0;
        if (!rateIntervalId) runMetricsTimelineAggregator();
    }

    function setCaptureStateIdle() {
        isCaptureActive = false;
        btnToggleCapture.innerHTML = '<i class="fa-solid fa-play"></i> Start Capture';
        btnToggleCapture.className = "btn-control start";
        interfaceSelector.disabled = false;

        globalStatusDot.className = "pulse-dot idle";
        globalStatusText.textContent = "System Idle";

        // Stop rate tracking
        if (rateIntervalId) {
            clearInterval(rateIntervalId);
            rateIntervalId = null;
        }
        valPacketRatePs.textContent = "0 Pkts/S";
    }

    // ----------------------------------------------------------------------
    // WebSockets Handler (Flask-SocketIO connection)
    // ----------------------------------------------------------------------
    function initWebSocket() {
        if (socket) return;

        // Connect back to server URL
        socket = io("http://127.0.0.1:5000");

        socket.on("connect", () => {
            console.log("WebSocket connected to IDS daemon.");
        });

        socket.on("disconnect", () => {
            console.warn("WebSocket disconnected from IDS daemon.");
        });

        // Live Packet Stream Ingestion
        socket.on("live_packet", (pkt) => {
            // 1. Process statistics counters
            stats.totalPackets++;
            packetsInLastInterval++;
            secondPacketsCount++;

            // Count protocols specifically
            if (pkt.protocol in stats.protocols) {
                stats.protocols[pkt.protocol]++;
            } else {
                stats.protocols.Other++;
            }

            // Sync counters to cards
            valTotalPackets.textContent = stats.totalPackets.toLocaleString();
            valTcpCount.textContent = stats.protocols.TCP.toLocaleString();
            valUdpCount.textContent = stats.protocols.UDP.toLocaleString();
            valIcmpCount.textContent = stats.protocols.ICMP.toLocaleString();

            // Track talkers
            if (pkt.src_ip) stats.topSources[pkt.src_ip] = (stats.topSources[pkt.src_ip] || 0) + 1;
            if (pkt.dst_ip) stats.topDestinations[pkt.dst_ip] = (stats.topDestinations[pkt.dst_ip] || 0) + 1;

            // 2. Append row to HTML table
            appendPacketToTable(pkt, true);

            // 3. Update dynamic charts
            updateProtocolChart();
            updateTopTalkersCharts();
        });

        // Live Security Alerts Stream Ingestion
        socket.on("live_alert", (alt) => {
            // Increment statistics
            stats.totalAlerts++;
            alertsInLastInterval++;
            valTotalAlerts.textContent = stats.totalAlerts.toLocaleString();

            // Insert alert into feed panel
            appendAlertToFeed(alt, true);

            // If user is currently looking at another tab, add a notification count badge on Dashboard link
            const dashboardTab = document.querySelector('li[data-target="dashboard-section"]');
            if (!dashboardTab.classList.contains("active")) {
                newAlertsCount++;
                badgeLiveAlertsCount.textContent = `${newAlertsCount} New`;
                badgeLiveAlertsCount.style.display = "inline-block";
            }
        });
    }

    function disconnectWebSocket() {
        if (socket) {
            socket.disconnect();
            socket = null;
        }
    }

    // Packet rate displays updater (calculates averages per second)
    setInterval(() => {
        if (isCaptureActive) {
            valPacketRatePs.textContent = `${secondPacketsCount} Pkts/S`;
            secondPacketsCount = 0;
        }
    }, 1000);

    // ----------------------------------------------------------------------
    // Initialization Sequence
    // ----------------------------------------------------------------------
    initCharts();
    fetchInterfaces();
    fetchSystemDiagnostic();
    fetchDashboardStats();
    preloadLiveFeeds();

    // Bind log page refresh buttons
    btnRefreshAlerts.addEventListener("click", fetchAlertLogs);
    btnRefreshPackets.addEventListener("click", fetchPacketLogs);
});
