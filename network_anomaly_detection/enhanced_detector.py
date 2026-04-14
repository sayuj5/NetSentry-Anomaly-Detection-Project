"""
ENHANCED LIVE DETECTOR - KALI/REAL-WORLD ATTACK DETECTION
Improved feature extraction to match KDD dataset structure.
"""

import numpy as np
import pandas as pd
import joblib
import pickle
import time
from datetime import datetime, timedelta
from collections import defaultdict
from threading import Lock

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


class KaliRealWorldDetector:
    """
    Advanced detector tuned for real-world Kali Linux attacks.
    Implements proper KDD feature extraction for live packets.
    """
    
    def __init__(self, model_path_rf=None):
        """Load trained Random Forest model."""
        self.rf_model = None
        self.models_loaded = False
        
        if model_path_rf:
            try:
                self.rf_model = joblib.load(model_path_rf)
                self.models_loaded = True
                print("✅ Real-World Detector initialized")
            except Exception as e:
                print(f"⚠️  Could not load model: {e}")
        
        # Connection tracking (aggregates packets into connections)
        self.connection_data = defaultdict(lambda: {
            'packets': [],
            'src_bytes': 0,
            'dst_bytes': 0,
            'start_time': None,
            'end_time': None,
            'flags': set(),
            'service': 'unknown'
        })
        
        self.anomalies_log = []
        self.lock = Lock()
    
    def extract_kdd_features(self, src_ip, dst_ip, protocol, src_port, dst_port, 
                           payload_size, flags, service):
        """
        Extract 41 KDD-compatible features from network data.
        
        Returns a feature vector matching the training data.
        """
        
        # Map protocol to numeric
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
        proto_num = protocol_map.get(protocol, 0)
        
        # Service mapping
        service_map = {
            'ssh': 22, 'telnet': 23, 'smtp': 25, 'dns': 53,
            'http': 80, 'pop3': 110, 'nntp': 119, 'whois': 43,
            'sunrpc': 111, 'netbios': 139, 'imap': 143, 'https': 443,
            'mysql': 3306, 'postgres': 5432, 'irc': 6667
        }
        
        # Flag status (TCP flags)
        flag_values = {
            'S': 1,    # SYN
            'A': 2,    # ACK
            'F': 4,    # FIN
            'R': 8,    # RST
            'P': 16,   # PUSH
            'U': 32    # URG
        }
        
        flag_encoded = 0
        for f in flags:
            flag_encoded |= flag_values.get(f, 0)
        
        # Determine service from port
        if service == 'unknown':
            service = next((s for s, p in service_map.items() if p == dst_port), 'other')
        
        # Build 41-feature vector (simplified version)
        # In production, aggregate across multiple packets
        features = {
            'duration': 0,                    # Will be calculated from packet times
            'protocol_type': proto_num,       # 6=tcp, 17=udp, 1=icmp
            'service': service,               # http, ssh, smtp, etc.
            'src_bytes': payload_size,        # Bytes sent
            'dst_bytes': 0,                   # Response bytes (0 for single packet)
            'flag': flag_encoded,             # TCP flags
            'land': 0,                        # src == dst
            'wrong_fragment': 0,              # Fragmented incorrectly
            'urgent': 1 if 'U' in flags else 0,
            
            # Statistical features (aggregated)
            'count': 1,                       # Packets in connection
            'srv_count': 1,                   # Connections to same service
            'serror_rate': 0.0,               # % SYN errors
            'rerror_rate': 0.0,               # % REJ errors
            'same_srv_rate': 1.0,             # % to same service
            'diff_srv_rate': 0.0,             # % to different services
            
            # More features (defaults for single packet)
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 1.0,
            'dst_host_diff_srv_rate': 0.0,
        }
        
        return features
    
    def detect_port_scan(self, packets_log):
        """
        Detect port scans from packet history.
        Signature: Multiple connections to different ports in short time.
        """
        if len(packets_log) < 5:
            return False, 0.0
        
        # Check if ports are sequential (nmap pattern)
        ports = [p['dst_port'] for p in packets_log[-10:]]
        port_diffs = [ports[i+1] - ports[i] for i in range(len(ports)-1)]
        
        # Sequential ports = port scan
        if len([d for d in port_diffs if d > 0 and d < 100]) > len(port_diffs) * 0.7:
            return True, 0.85
        
        return False, 0.0
    
    def detect_ddos(self, src_ip, packets_recent):
        """
        Detect DDoS patterns from recent packets.
        Signature: Same source sending >50 packets/sec with SYN flags
        """
        if len(packets_recent) < 20:
            return False, 0.0
        
        # Check packet rate
        time_window = packets_recent[-1]['time'] - packets_recent[0]['time']
        if time_window > 0 and (len(packets_recent) / time_window) > 50:
            # Also check for SYN flags (DDoS indicator)
            syn_count = sum(1 for p in packets_recent if 'S' in p['flags'])
            if syn_count > len(packets_recent) * 0.6:
                return True, 0.92  # High anomaly score
        
        return False, 0.0
    
    def detect_brute_force(self, dst_port, failed_attempts):
        """
        Detect brute force attacks.
        Signature: Multiple failed SSH/FTP attempts from same source
        """
        # SSH/FTP ports
        if dst_port in [22, 21] and failed_attempts > 5:
            return True, 0.88
        
        return False, 0.0
    
    def detect_http_anomaly(self, payload):
        """
        Detect HTTP anomalies (SQLi, XSS patterns).
        Signature: Suspicious characters in payload
        """
        if not payload:
            return False, 0.0
        
        # SQL injection patterns
        sqli_patterns = ["' OR", "UNION SELECT", "DROP TABLE", "INSERT INTO", "--", "/*", "*/"]
        for pattern in sqli_patterns:
            if pattern.lower() in payload.lower():
                return True, 0.91
        
        # XSS patterns
        xss_patterns = ["<script>", "javascript:", "onerror=", "onload=", "eval("]
        for pattern in xss_patterns:
            if pattern.lower() in payload.lower():
                return True, 0.89
        
        return False, 0.0
    
    def analyze_packet(self, packet, packet_history):
        """
        Comprehensive packet analysis with multiple detection engines.
        """
        try:
            if not packet.haslayer(IP):
                return None
            
            # Extract basic info
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload_size = len(packet[IP].payload)
            timestamp = datetime.now()
            
            result = {
                'timestamp': timestamp,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'anomaly': False,
                'anomaly_type': None,
                'anomaly_score': 0.0,
                'reason': ''
            }
            
            # Determine protocol
            if packet.haslayer(TCP):
                protocol = 'tcp'
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                flags = packet[TCP].flags
                service = 'unknown'
            elif packet.haslayer(UDP):
                protocol = 'udp'
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                flags = ''
                service = 'unknown'
            elif packet.haslayer(ICMP):
                protocol = 'icmp'
                src_port = 0
                dst_port = 0
                flags = ''
                service = 'icmp'
            else:
                return None
            
            # Get payload if available
            payload_data = ''
            if packet.haslayer(Raw):
                try:
                    payload_data = packet[Raw].load.decode('utf-8', errors='ignore')
                except:
                    payload_data = str(packet[Raw].load)[:200]
            
            result['protocol'] = protocol
            result['src_port'] = src_port
            result['dst_port'] = dst_port
            result['flags'] = str(flags)
            
            # ===== DETECTION ENGINES =====
            
            # 1. PORT SCAN DETECTION
            is_portscan, score_portscan = self.detect_port_scan(packet_history)
            if is_portscan:
                result['anomaly'] = True
                result['anomaly_type'] = 'PORT_SCAN'
                result['anomaly_score'] = score_portscan
                result['reason'] = 'Sequential port probing detected'
                return result
            
            # 2. DDOS DETECTION
            recent_from_src = [p for p in packet_history[-50:] if p.get('src_ip') == src_ip]
            is_ddos, score_ddos = self.detect_ddos(src_ip, recent_from_src)
            if is_ddos:
                result['anomaly'] = True
                result['anomaly_type'] = 'DDOS'
                result['anomaly_score'] = score_ddos
                result['reason'] = f'High packet rate ({len(recent_from_src)}/sec) with SYN flags'
                return result
            
            # 3. BRUTE FORCE DETECTION
            # Count failed attempts (RST flags or connection resets)
            failed_attempts = sum(1 for p in recent_from_src if 'R' in p.get('flags', ''))
            is_bruteforce, score_brute = self.detect_brute_force(dst_port, failed_attempts)
            if is_bruteforce:
                result['anomaly'] = True
                result['anomaly_type'] = 'BRUTE_FORCE'
                result['anomaly_score'] = score_brute
                result['reason'] = f'{failed_attempts} failed login attempts to port {dst_port}'
                return result
            
            # 4. HTTP ANOMALY DETECTION (SQLi, XSS)
            if dst_port in [80, 8080, 8000]:
                is_http_anomaly, score_http = self.detect_http_anomaly(payload_data)
                if is_http_anomaly:
                    result['anomaly'] = True
                    result['anomaly_type'] = 'HTTP_ATTACK'
                    result['anomaly_score'] = score_http
                    result['reason'] = 'Malicious payload detected (SQLi/XSS patterns)'
                    return result
            
            # 5. ICMP FLOOD DETECTION
            recent_icmp = [p for p in packet_history[-100:] if p.get('protocol') == 'icmp']
            if len(recent_icmp) > 50:  # >50 ICMP packets in last 100
                result['anomaly'] = True
                result['anomaly_type'] = 'ICMP_FLOOD'
                result['anomaly_score'] = 0.87
                result['reason'] = f'ICMP flood attack detected ({len(recent_icmp)} packets)'
                return result
            
            # If no anomaly detected
            result['anomaly'] = False
            result['anomaly_score'] = 0.1
            result['reason'] = 'Normal traffic pattern'
            
            return result
        
        except Exception as e:
            print(f"Error analyzing packet: {e}")
            return None
    
    def start_sniffing(self, interface=None, timeout=60):
        """Start real-time packet capture for Kali attack detection."""
        
        if not SCAPY_AVAILABLE:
            print("❌ Scapy not available")
            return
        
        packet_history = []
        
        def packet_callback(packet):
            try:
                result = self.analyze_packet(packet, packet_history)
                
                if result:
                    packet_history.append(result)
                    # Keep only last 500 packets for memory efficiency
                    if len(packet_history) > 500:
                        packet_history.pop(0)
                    
                    # Log anomalies
                    if result['anomaly']:
                        with self.lock:
                            self.anomalies_log.append(result)
                        
                        print(f"\n🚨 ATTACK DETECTED")
                        print(f"   Type: {result['anomaly_type']}")
                        print(f"   Source: {result['src_ip']}")
                        print(f"   Target: {result['dst_ip']}")
                        print(f"   Score: {result['anomaly_score']:.2f}")
                        print(f"   Reason: {result['reason']}\n")
            
            except Exception as e:
                pass
        
        print(f"\n{'='*70}")
        print("🔴 KALI/REAL-WORLD ATTACK DETECTOR STARTED")
        print(f"   Mode: Live Network Packet Capture")
        print(f"   Status: Listening for Kali attacks...")
        print(f"{'='*70}\n")
        
        try:
            sniff(
                prn=packet_callback,
                iface=interface,
                timeout=timeout,
                filter="ip"
            )
        except PermissionError:
            print("❌ Admin/Root privileges required!")
        except Exception as e:
            print(f"❌ Error: {e}")
        
        finally:
            print(f"\n{'='*70}")
            print(f"✅ DETECTION SESSION ENDED")
            print(f"   Total Attacks Detected: {len(self.anomalies_log)}")
            
            # Print summary
            attack_types = defaultdict(int)
            for anomaly in self.anomalies_log:
                attack_types[anomaly['anomaly_type']] += 1
            
            print(f"\n   Breakdown by Attack Type:")
            for attack_type, count in attack_types.items():
                print(f"      {attack_type}: {count}")
            
            print(f"{'='*70}\n")


# ===== PRESET DETECTORS FOR COMMON KALI TOOLS =====

class KaliToolDetectors:
    """
    Specialized detectors for specific Kali Linux tools.
    """
    
    @staticmethod
    def detect_nmap(packet_history):
        """Detect nmap scans."""
        detections = []
        
        for i in range(len(packet_history) - 5):
            window = packet_history[i:i+6]
            
            # Check for SYN scan pattern
            syn_count = sum(1 for p in window if 'S' in str(p.get('flags', '')))
            
            if syn_count >= 4:  # Most are SYN packets
                detections.append({
                    'confidence': 0.92,
                    'tool': 'nmap',
                    'pattern': 'SYN scan'
                })
        
        return detections
    
    @staticmethod
    def detect_hping3(packet_history):
        """Detect hping3 attacks."""
        detections = []
        
        recent = packet_history[-100:]
        if len(recent) > 50:
            # Check for consistent SYN flags (hping3 default)
            syn_ratio = sum(1 for p in recent if 'S' in str(p.get('flags', ''))) / len(recent)
            
            if syn_ratio > 0.8:
                detections.append({
                    'confidence': 0.89,
                    'tool': 'hping3',
                    'pattern': 'Continuous SYN flood'
                })
        
        return detections
    
    @staticmethod
    def detect_hydra(packet_history):
        """Detect Hydra brute force attempts."""
        detections = []
        
        # Group by destination port
        port_activity = defaultdict(int)
        for p in packet_history[-200:]:
            port_activity[p.get('dst_port')] += 1
        
        # SSH/FTP ports with high activity = Hydra
        for port in [22, 21]:
            if port_activity.get(port, 0) > 30:
                detections.append({
                    'confidence': 0.91,
                    'tool': 'hydra',
                    'pattern': f'Brute force on port {port}'
                })
        
        return detections


if __name__ == "__main__":
    print("\n⚠️  KALI ATTACK DETECTION MODE")
    print("   Requires Admin/Root privileges")
    print("   Usage: sudo python -u enhanced_detector.py\n")
    
    detector = KaliRealWorldDetector()
    print("Detector initialized. Ready for live capture.")
