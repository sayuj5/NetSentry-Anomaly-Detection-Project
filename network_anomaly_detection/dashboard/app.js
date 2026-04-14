// ===== GLOBAL DETECTION STATE =====

let simulationActive = false;
let realCaptureActive = false;
let detectionStats = {
    anomalies: 0,
    normal: 0,
    totalPackets: 0,
    attackHistory: []  // Complete history of all attacks
};

const ATTACK_DEFINITIONS = {
    'SYN_FLOOD': { count: 5, score: 0.92, reason: 'High rate SYN packets' },
    'ICMP_FLOOD': { count: 3, score: 0.87, reason: 'ICMP flood attack' },
    'HTTP_DDoS': { count: 4, score: 0.85, reason: 'HTTP request flood' },
    'PORT_SCAN': { count: 4, score: 0.85, reason: 'Sequential port probing' },
    'UDP_SCAN': { count: 3, score: 0.80, reason: 'UDP service probing' },
    'SSH_BRUTE_FORCE': { count: 6, score: 0.88, reason: 'Failed SSH attempts' },
    'FTP_BRUTE_FORCE': { count: 4, score: 0.86, reason: 'FTP login failures' },
    'SQL_INJECTION': { count: 4, score: 0.91, reason: 'SQL injection payload' }
};

// Real-time API endpoint
const API_BASE = 'http://localhost:5000/api';

// ===== DETECTION FUNCTIONS =====

function updateDetectionStats() {
    const total = detectionStats.anomalies + detectionStats.normal;
    const rate = total > 0 ? (detectionStats.anomalies / total * 100).toFixed(1) : 0;
    
    document.getElementById('anomaly-count').textContent = detectionStats.anomalies;
    document.getElementById('normal-count').textContent = detectionStats.normal;
    document.getElementById('detection-rate').textContent = rate + '%';
}

function addDetectionLog(attackType, score, reason, srcIp = null) {
    const log = document.getElementById('detection-log');
    const timestamp = new Date().toLocaleTimeString();
    const srcDisplay = srcIp || generateRandomIp();
    const dstDisplay = '10.193.242.167';  // Your Windows IP
    
    let colorClass = 'term-red';
    
    const logEntry = `<p><span class="term-red">[${timestamp}]</span> <span style="color: #ff3131; font-weight: bold;">${attackType}</span> from <span class="term-cyan">${srcDisplay} → ${dstDisplay}</span> <span class="term-green">Score: ${score}</span></p>`;
    log.innerHTML += logEntry;
    log.scrollTop = log.scrollHeight;
    
    // Add to history
    detectionStats.attackHistory.push({
        time: timestamp,
        type: attackType,
        srcIp: srcDisplay,
        dstIp: dstDisplay,
        score: score,
        reason: reason
    });
}

function startAttackSimulation() {
    simulationActive = true;
    document.getElementById('detection-status').innerHTML = '<span class="status-dot red pulse"></span> Detecting Attacks (SIMULATION)';
    addDetectionLog('SYSTEM', 0.00, 'Simulation mode started', '127.0.0.1');
    // Simulate normal traffic in background
    startNormalTrafficSimulation();
}

function stopAttackSimulation() {
    simulationActive = false;
    document.getElementById('detection-status').innerHTML = '<span class="status-dot green"></span> Ready';
    addDetectionLog('SYSTEM', 0.00, 'Simulation mode stopped', '127.0.0.1');
}

// ===== REAL KALI ATTACK CAPTURE =====

let pollInterval = null;

async function startRealCapture() {
    if (realCaptureActive) {
        alert('Real capture already running!');
        return;
    }
    
    try {
        const response = await fetch(`${API_BASE}/start_capture`, { method: 'POST' });
        if (response.ok) {
            realCaptureActive = true;
            document.getElementById('detection-status').innerHTML = '<span class="status-dot red pulse"></span> CAPTURING REAL TRAFFIC';
            addDetectionLog('SYSTEM', 0.00, 'Real packet capture STARTED - Waiting for Kali attacks...', '127.0.0.1');
            
            // Start polling for detections
            pollInterval = setInterval(pollDetections, 500);
        }
    } catch (error) {
        alert('ERROR: Cannot connect to backend. Make sure real_time_detector.py is running on port 5000');
    }
}

async function stopRealCapture() {
    if (!realCaptureActive) return;
    
    try {
        await fetch(`${API_BASE}/stop_capture`, { method: 'POST' });
        realCaptureActive = false;
        clearInterval(pollInterval);
        document.getElementById('detection-status').innerHTML = '<span class="status-dot green"></span> Ready';
        addDetectionLog('SYSTEM', 0.00, 'Real packet capture STOPPED', '127.0.0.1');
    } catch (error) {
        console.error('Error stopping capture:', error);
    }
}

async function pollDetections() {
    try {
        const response = await fetch(`${API_BASE}/detections`);
        if (response.ok) {
            const data = await response.json();
            
            // Update stats
            detectionStats.totalPackets = data.stats.total_packets;
            detectionStats.anomalies = data.stats.anomalies;
            detectionStats.normal = data.stats.normal;
            
            // Add new detections to log
            if (data.detections && data.detections.length > 0) {
                data.detections.forEach(detection => {
                    if (detection.type === 'REAL_PACKET_ANOMALY') {
                        addDetectionLog(
                            `[REAL] ${detection.protocol.toUpperCase()} ${detection.service}`,
                            detection.anomaly_score,
                            `From ${detection.src_ip}:${detection.src_port}`,
                            detection.src_ip
                        );
                    }
                });
            }
            
            updateDetectionStats();
        }
    } catch (error) {
        // Backend API not available
        if (realCaptureActive && pollInterval) {
            // Keep trying silently
        }
    }
}

function clearDetectionLog() {
    document.getElementById('detection-log').innerHTML = '<span class="muted">Log cleared. Ready for new detections...</span>';
    detectionStats = {
        anomalies: 0,
        normal: 0,
        totalPackets: 0,
        attackHistory: []
    };
    updateDetectionStats();
}

function generateRandomIp() {
    const options = ['192.168.1.5', '10.0.0.54', '172.16.254.100', '192.168.1.105'];
    return options[Math.floor(Math.random() * options.length)];
}

// ===== ATTACK SIMULATORS =====

function simulateAttack(attackType) {
    if (!simulationActive) {
        alert('⚠️ Click "Start Simulation" first!');
        return;
    }
    
    const attackConfig = ATTACK_DEFINITIONS[attackType];
    if (!attackConfig) return;
    
    const srcIp = generateRandomIp();
    const dstIp = '10.193.242.167';
    
    // Simulate sequential detections
    for (let i = 0; i < attackConfig.count; i++) {
        setTimeout(() => {
            detectionStats.anomalies += 1;
            detectionStats.totalPackets += 1;
            addDetectionLog(attackType, attackConfig.score, attackConfig.reason, srcIp);
            updateDetectionStats();
        }, i * 200);
    }
}

function launchDDosAttack() {
    simulateAttack('SYN_FLOOD');
}

function launchICMPAttack() {
    simulateAttack('ICMP_FLOOD');
}

function launchHTTPAttack() {
    simulateAttack('HTTP_DDoS');
}

function launchPortScan() {
    simulateAttack('PORT_SCAN');
}

function launchUDPScan() {
    simulateAttack('UDP_SCAN');
}

function launchSSHBruteForce() {
    simulateAttack('SSH_BRUTE_FORCE');
}

function launchFTPBruteForce() {
    simulateAttack('FTP_BRUTE_FORCE');
}

function launchSQLInjection() {
    simulateAttack('SQL_INJECTION');
}

// ===== BACKGROUND TRAFFIC SIMULATION =====

function startNormalTrafficSimulation() {
    const normalTrafficInterval = setInterval(() => {
        if (!simulationActive) {
            clearInterval(normalTrafficInterval);
            return;
        }
        
        if (Math.random() > 0.6) {  // 40% chance of normal traffic
            detectionStats.normal += 1;
            detectionStats.totalPackets += 1;
            updateDetectionStats();
        }
    }, 3000);
}

// ===== NAVIGATION =====

// Handle Navigation Tab Switching
function switchTab(event, viewId) {
    if (event) event.preventDefault();
    
    // Hide all views
    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });
    // Remove active class from nav items
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });
    
    // Show selected view
    document.getElementById(viewId).classList.add('active');
    // Set clicked nav item to active
    if (event) event.currentTarget.classList.add('active');
}

// Handle Model Matrix Inner Tabs
function openModelTab(event, tabId) {
    document.querySelectorAll('.tab-content').forEach(content => {
        content.classList.remove('active');
    });
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    
    document.getElementById(tabId).classList.add('active');
    event.currentTarget.classList.add('active');
}

// ===== THEME =====

// Theme Toggle logic
function toggleTheme() {
    const body = document.body;
    const isLightMode = document.getElementById('theme-checkbox').checked;
    
    if (isLightMode) {
        body.classList.add('light-mode');
        localStorage.setItem('theme', 'light');
    } else {
        body.classList.remove('light-mode');
        localStorage.setItem('theme', 'dark');
    }
}

// Initialize Theme on Load
document.addEventListener('DOMContentLoaded', () => {
    const savedTheme = localStorage.getItem('theme');
    const themeCheckbox = document.getElementById('theme-checkbox');
    
    if (savedTheme === 'light') {
        document.body.classList.add('light-mode');
        if (themeCheckbox) themeCheckbox.checked = true;
    }
});

// ===== TERMINAL CAPTURE =====

// Terminal Live Capture Simulation
let captureInterval;
function toggleCapture() {
    const isChecked = document.getElementById('live-capture-toggle').checked;
    const terminal = document.getElementById('terminal-output');
    
    if(isChecked) {
        terminal.innerHTML = '<span class="term-cyan">[SYSTEM]</span> Intercepting live traffic via Scapy / PyShark...<br>';
        captureInterval = setInterval(() => {
            const ips = ['192.168.1.105', '10.0.0.54', '172.16.254.1', '192.168.1.12'];
            const ports = ['443', '80', '22', '8080'];
            const protocols = ['TCP', 'UDP', 'ICMP'];
            
            const randomIp = ips[Math.floor(Math.random() * ips.length)];
            const randomPort = ports[Math.floor(Math.random() * ports.length)];
            const proto = protocols[Math.floor(Math.random() * protocols.length)];
            
            // Randomly insert an anomaly
            if(Math.random() > 0.8) {
                terminal.innerHTML += `<p><span class="term-red">[ANOMALY]</span> DdoS signature pattern from <span class="term-cyan">${randomIp}:${randomPort}</span> [${proto}] - <span class="term-red">BLOCKED</span></p>`;
            } else {
                terminal.innerHTML += `<p><span class="term-green">[NORMAL]</span> Packet fragment received from <span class="term-cyan">${randomIp}:${randomPort}</span> [${proto}] - ALLOWED</p>`;
            }
            
            // Auto scroll to bottom
            terminal.scrollTop = terminal.scrollHeight;
            
        }, 1500);
    } else {
        clearInterval(captureInterval);
        terminal.innerHTML += '<br><span class="term-cyan">[SYSTEM]</span> Live capture halted.<br>';
    }
}

// ===== ADVERSARIAL TRAINING =====

// Adversarial Training Dummy Function
function runAdversarial() {
    const btn = document.querySelector('.adv-mitigation .btn');
    const originalText = btn.innerText;
    btn.innerText = "TRAINING IN PROGRESS...";
    btn.style.boxShadow = "0 0 20px var(--red)";
    btn.style.backgroundColor = "var(--red)";
    btn.style.color = "white";
    btn.style.borderColor = "var(--red)";
    
    setTimeout(() => {
        btn.innerText = "DRILL COMPLETE - RESILIENCE UPDATED";
        btn.style.boxShadow = "0 0 20px var(--green)";
        btn.style.backgroundColor = "var(--green)";
        btn.style.borderColor = "var(--green)";
        
        document.querySelector('.gauge-fill').style.width = '94%';
        document.querySelector('.gauge-text').innerText = 'Resilience: 94%';
        
        setTimeout(() => {
            btn.innerText = originalText;
            btn.style.backgroundColor = "";
            btn.style.borderColor = "";
            btn.style.boxShadow = "";
        }, 2000);
    }, 3000);
}
