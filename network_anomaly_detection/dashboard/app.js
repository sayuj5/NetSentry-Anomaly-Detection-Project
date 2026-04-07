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
