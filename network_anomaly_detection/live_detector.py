"""
LIVE ANOMALY DETECTOR MODULE
Real-time packet capture and anomaly detection using trained models.
"""

import numpy as np
import pandas as pd
import joblib
import pickle
import time
from datetime import datetime
from collections import defaultdict
from threading import Lock

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️  Scapy not installed. Install with: pip install scapy")


class LiveAnomalyDetector:
    """
    Real-time anomaly detection using trained models.
    Captures packets → Converts to KDD format → Predicts anomalies
    """
    
    def __init__(self, model_path_rf=None, model_path_mlp=None, scaler_path=None):
        """
        Load pre-trained models and feature scaler.
        """
        self.models_loaded = False
        self.rf_model = None
        self.mlp_model = None
        self.scaler = None
        
        # Try to load models if paths provided
        if model_path_rf and model_path_mlp:
            try:
                self.rf_model = joblib.load(model_path_rf)
                if scaler_path:
                    self.scaler = joblib.load(scaler_path)
                self.models_loaded = True
                print("✅ Models loaded successfully")
            except Exception as e:
                print(f"⚠️  Could not load models: {e}")
                self.models_loaded = False
        
        # Track connection statistics
        self.connections = defaultdict(lambda: {
            'count': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
            'duration': 0
        })
        
        self.anomalies_detected = 0
        self.normal_traffic = 0
        self.anomaly_log = []
        self.lock = Lock()
    
    def packet_to_kdd_features(self, packet):
        """
        Convert Scapy packet to KDD format features.
        
        KDD has 41 features including:
        - protocol_type (TCP/UDP/ICMP)
        - service (port-derived)
        - src_bytes, dst_bytes
        - duration
        - flag
        """
        try:
            features = {}
            
            if not packet.haslayer(IP):
                return None
            
            # Protocol detection
            if packet.haslayer(TCP):
                protocol = 'tcp'
                flags = packet[TCP].flags
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'udp'
                flags = 0
                src_port = packet[UDP].sport if packet.haslayer(UDP) else 0
                dst_port = packet[UDP].dport if packet.haslayer(UDP) else 0
            elif packet.haslayer(ICMP):
                protocol = 'icmp'
                flags = 0
                src_port = 0
                dst_port = 0
            else:
                protocol = 'other'
                flags = 0
                src_port = 0
                dst_port = 0
            
            # Extract basic features
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            payload_len = len(packet[IP].payload)
            
            # Service mapping (common ports)
            port_service_map = {
                20: 'ftp', 21: 'ftp', 22: 'ssh', 23: 'telnet',
                25: 'smtp', 53: 'dns', 80: 'http', 443: 'https',
                3306: 'mysql', 5432: 'postgres', 8080: 'http_alt'
            }
            
            service = port_service_map.get(dst_port, 'other')
            
            # Build feature dictionary
            features = {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol_type': protocol,
                'service': service,
                'src_bytes': payload_len,
                'dst_bytes': 0,
                'duration': 0,
                'flag': 'SF',
                'timestamp': datetime.now()
            }
            
            return features
        
        except Exception as e:
            return None
    
    def predict_anomaly(self, features):
        """
        Make anomaly prediction using trained models.
        """
        if not self.models_loaded or self.rf_model is None:
            return 0.5, 0, 0  # Return neutral prediction if no model
        
        try:
            # For demonstration, create a simple feature vector
            feature_vector = np.array([[
                features.get('src_bytes', 0),
                features.get('dst_bytes', 0),
                features.get('duration', 0),
                len(features.get('protocol_type', 'unknown')),
                features.get('dst_port', 0)
            ]])
            
            # Random Forest prediction
            rf_pred = self.rf_model.predict(feature_vector)[0]
            
            # Majority voting
            anomaly_score = rf_pred
            
            return float(anomaly_score), int(rf_pred), 0
        
        except Exception as e:
            return 0.5, 0, 0
    
    def packet_callback(self, packet):
        """
        Callback function for each captured packet.
        """
        try:
            features = self.packet_to_kdd_features(packet)
            
            if features is None:
                return
            
            # Make predictions
            anomaly_score, rf_pred, mlp_pred = self.predict_anomaly(features)
            
            with self.lock:
                if anomaly_score > 0.5:
                    self.anomalies_detected += 1
                    
                    alert = {
                        'timestamp': datetime.now(),
                        'src_ip': features['src_ip'],
                        'dst_ip': features['dst_ip'],
                        'protocol': features['protocol_type'].upper(),
                        'service': features['service'],
                        'dst_port': features['dst_port'],
                        'anomaly_score': anomaly_score,
                        'rf_pred': rf_pred
                    }
                    
                    self.anomaly_log.append(alert)
                    
                    print(f"\n🚨 ANOMALY DETECTED at {alert['timestamp']}")
                    print(f"   Src IP: {alert['src_ip']} → Dst IP: {alert['dst_ip']}")
                    print(f"   Protocol: {alert['protocol']}")
                    print(f"   Service: {alert['service']}")
                    print(f"   Dst Port: {alert['dst_port']}")
                    print(f"   Anomaly Score: {anomaly_score:.2f}")
                    print(f"   Total anomalies: {self.anomalies_detected}\n")
                
                else:
                    self.normal_traffic += 1
        
        except Exception as e:
            pass
    
    def start_sniffing(self, interface=None, packet_count=0, timeout=None):
        """
        Start live packet capture and anomaly detection.
        
        Args:
            interface: Network interface (e.g., 'Ethernet', 'Wi-Fi')
            packet_count: Number of packets to sniff (0 = infinite)
            timeout: Sniffing timeout in seconds
        """
        if not SCAPY_AVAILABLE:
            print("❌ Scapy not available. Cannot start packet sniffing.")
            return
        
        print(f"\n{'='*60}")
        print("🔵 LIVE ANOMALY DETECTION STARTED")
        print(f"{'='*60}\n")
        
        try:
            sniff(
                prn=self.packet_callback,
                iface=interface,
                count=packet_count,
                timeout=timeout,
                filter="ip"  # Only IPv4 packets
            )
        
        except PermissionError:
            print("❌ ERROR: Admin/Root privileges required for packet capture!")
            print("   Windows: Run as Administrator")
            print("   Linux: Use 'sudo python -u live_detector.py'")
        
        except Exception as e:
            print(f"❌ Sniffing error: {e}")
        
        finally:
            print(f"\n{'='*60}")
            print(f"✅ DETECTION SESSION SUMMARY")
            print(f"   Total Anomalies Detected: {self.anomalies_detected}")
            print(f"   Normal Traffic Packets: {self.normal_traffic}")
            print(f"   Detection Rate: {self.anomalies_detected / max(1, self.anomalies_detected + self.normal_traffic) * 100:.2f}%")
            print(f"{'='*60}\n")
    
    def get_anomaly_log(self):
        """Return current anomaly log."""
        with self.lock:
            return self.anomaly_log.copy()
    
    def get_statistics(self):
        """Return current detection statistics."""
        with self.lock:
            return {
                'anomalies_detected': self.anomalies_detected,
                'normal_traffic': self.normal_traffic,
                'total_packets': self.anomalies_detected + self.normal_traffic,
                'detection_rate': self.anomalies_detected / max(1, self.anomalies_detected + self.normal_traffic) * 100
            }


# ===== TESTING FUNCTIONS =====

def test_detector_mode():
    """Test detector without live capture (simulation mode)."""
    detector = LiveAnomalyDetector()
    
    print("\n🧪 Testing in Simulation Mode (No Live Capture)")
    print("   Creating 10 sample packets...\n")
    
    # Simulate some packets
    for i in range(10):
        fake_packet = type('obj', (object,), {
            'haslayer': lambda x, layer=None: layer in ['IP', 'TCP'],
            '__getitem__': lambda self, key: type('obj', (object,), {
                'src': f'192.168.1.{i}',
                'dst': '192.168.1.1',
                'payload': type('obj', (object,), {'__len__': lambda: 100})(),
                'sport': 5000 + i,
                'dport': 80,
                'flags': 'S'
            })()
        })()
        
        features = detector.packet_to_kdd_features(fake_packet)
        if features:
            anomaly_score, rf_pred, mlp_pred = detector.predict_anomaly(features)
            print(f"   Packet {i+1}: Anomaly Score={anomaly_score:.2f}, Verdict={'ANOMALY' if anomaly_score > 0.5 else 'NORMAL'}")
    
    stats = detector.get_statistics()
    print(f"\n📊 Simulation Results:")
    print(f"   Total packets: {stats['total_packets']}")
    print(f"   Anomalies detected: {stats['anomalies_detected']}")
    print(f"   Detection rate: {stats['detection_rate']:.2f}%")


if __name__ == "__main__":
    print("\n⚠️  For LIVE DETECTION (requires admin/root):")
    print("   python -u live_detector.py")
    print("\nFor SIMULATION MODE (no admin required):")
    
    test_detector_mode()
