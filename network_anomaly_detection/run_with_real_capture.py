"""
Launch Script for Network Anomaly Detection with Real Kali Capture
Runs both the real-time detector (Flask backend) and dashboard web server
"""

import subprocess
import time
import os
import webbrowser
import sys

def start_real_time_detector():
    """Start the real-time detector backend"""
    print("\n" + "="*70)
    print("🛡️  STARTING REAL-TIME DETECTOR (Flask Backend on Port 5000)")
    print("="*70)
    print("\n⚠️  NOTE: Admin/Root privileges required for packet capture!")
    print("   On Windows: Run Command Prompt as Administrator")
    print("   On Linux: Use 'sudo python run_project.py'\n")
    
    process = subprocess.Popen(
        [sys.executable, 'real_time_detector.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    return process

def start_dashboard_server():
    """Start the dashboard web server"""
    print("\n" + "="*70)
    print("🌐 STARTING DASHBOARD SERVER (Port 8000)")
    print("="*70 + "\n")
    
    os.chdir('dashboard')
    process = subprocess.Popen(
        [sys.executable, '-m', 'http.server', '8000'],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1
    )
    os.chdir('..')
    return process

if __name__ == '__main__':
    print("\n" + "█"*70)
    print("█  NetSentry: Real-Time Network Anomaly Detection with Kali Support")
    print("█"*70)
    
    # Start both services
    print("\n[*] Launching services...")
    
    detector_process = start_real_time_detector()
    time.sleep(2)
    
    dashboard_process = start_dashboard_server()
    time.sleep(2)
    
    print("\n" + "="*70)
    print("✅ ALL SERVICES STARTED")
    print("="*70)
    print("\n📊 Dashboard URL:          http://localhost:8000")
    print("🔌 Backend API:            http://localhost:5000")
    print("\n📖 HOW TO USE:")
    print("   1. Open dashboard at http://localhost:8000")
    print("   2. Click 'Capture Real Traffic' button")
    print("   3. From Kali Linux, run attacks against your Windows IP: 10.193.242.167")
    print("\n🎯 EXAMPLE KALI COMMANDS:")
    print("   nmap -sV 10.193.242.167")
    print("   sudo hping3 -S --flood -p 80 10.193.242.167")
    print("   sudo hping3 -1 --flood 10.193.242.167")
    print("   nmap -sU 10.193.242.167")
    print("\n📡 Dashboard will show real detections in real-time!")
    print("\n" + "="*70)
    print("Press Ctrl+C to stop all services\n")
    
    try:
        # Keep running
        detector_process.wait()
        dashboard_process.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        detector_process.terminate()
        dashboard_process.terminate()
        print("✅ Services stopped")
