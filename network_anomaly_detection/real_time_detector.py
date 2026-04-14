"""
Real-Time Network Anomaly Detector
Captures actual network packets and detects anomalies using trained ML models
"""

import pickle
import numpy as np
import json
from datetime import datetime
from collections import defaultdict
import threading
import time

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list
except ImportError:
    print("ERROR: Scapy not installed. Run: pip install scapy")
    exit(1)

import tensorflow as tf
from flask import Flask, jsonify
from flask_cors import CORS

# ===== LOAD TRAINED MODELS =====

print("[*] Loading trained models...")
try:
    with open('trained_rf_model.pkl', 'rb') as f:
        rf_model = pickle.load(f)
    print("✅ Random Forest model loaded")
except:
    print("❌ Random Forest model not found")
    rf_model = None

try:
    mlp_model = tf.keras.models.load_model('trained_mlp_model.h5')
    print("✅ Keras MLP model loaded")
except:
    print("❌ Keras MLP model not found")
    mlp_model = None

try:
    with open('trained_iforest_model.pkl', 'rb') as f:
        iforest_model = pickle.load(f)
    print("✅ Isolation Forest model loaded")
except:
    print("❌ Isolation Forest model not found")
    iforest_model = None

try:
    with open('feature_names.pkl', 'rb') as f:
        feature_names = pickle.load(f)
    print(f"✅ Feature names loaded ({len(feature_names)} features)")
except:
    print("❌ Feature names not found")
    feature_names = None

# ===== FEATURE ENGINEERING =====

class PacketFeatureExtractor:
    """Convert network packets to KDD-like features"""
    
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'syn_count': 0,
            'fin_count': 0,
            'rst_count': 0,
            'psh_count': 0,
            'ack_count': 0,
            'urg_count': 0,
            'icmp_count': 0,
            'udp_count': 0,
            'tcp_count': 0,
            'protocols': defaultdict(int),
            'destination_ports': defaultdict(int),
            'source_ports': defaultdict(int),
            'timestamps': []
        })
        
    def extract_features(self, packet):
        """Extract features from a single packet"""
        features = {
            'duration': 0,
            'protocol_type': 'unknown',
            'service': 'unknown',
            'flag': 'SF',
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'count': 1,
            'srv_count': 1,
            'serror_rate': 0.0,
            'srv_serror_rate': 0.0,
            'rerror_rate': 0.0,
            'srv_rerror_rate': 0.0,
            'same_srv_rate': 0.0,
            'diff_srv_rate': 0.0,
            'srv_diff_host_rate': 0.0,
            'dst_host_count': 1,
            'dst_host_srv_count': 1,
            'dst_host_same_srv_rate': 0.0,
            'dst_host_diff_srv_rate': 0.0,
            'dst_host_same_src_port_rate': 0.0,
            'dst_host_srv_diff_host_rate': 0.0,
            'dst_host_serror_rate': 0.0,
            'dst_host_srv_serror_rate': 0.0,
            'dst_host_rerror_rate': 0.0,
            'dst_host_srv_rerror_rate': 0.0
        }
        
        try:
            if IP in packet:
                ip_layer = packet[IP]
                features['src_ip'] = ip_layer.src
                features['dst_ip'] = ip_layer.dst
                features['duration'] = 0
                
                if TCP in packet:
                    tcp_layer = packet[TCP]
                    features['protocol_type'] = 'tcp'
                    features['src_port'] = tcp_layer.sport
                    features['dst_port'] = tcp_layer.dport
                    features['service'] = self._port_to_service(tcp_layer.dport)
                    features['src_bytes'] = len(packet)
                    
                    # Detect flags
                    if tcp_layer.flags.S:
                        features['flag'] = 'S0'
                    elif tcp_layer.flags.F:
                        features['flag'] = 'F'
                    elif tcp_layer.flags.R:
                        features['flag'] = 'R'
                    
                elif UDP in packet:
                    udp_layer = packet[UDP]
                    features['protocol_type'] = 'udp'
                    features['src_port'] = udp_layer.sport
                    features['dst_port'] = udp_layer.dport
                    features['service'] = self._port_to_service(udp_layer.dport)
                    features['src_bytes'] = len(packet)
                    
                elif ICMP in packet:
                    features['protocol_type'] = 'icmp'
                    features['service'] = 'icmp'
                    features['src_bytes'] = len(packet)
                    features['flag'] = 'SH'
                    
        except Exception as e:
            pass
            
        return features
    
    @staticmethod
    def _port_to_service(port):
        """Map port number to service"""
        port_map = {
            20: 'ftp_data', 21: 'ftp', 23: 'telnet', 25: 'smtp',
            53: 'domain', 80: 'http', 110: 'pop_3', 143: 'imap4',
            443: 'https', 3306: 'mysql', 3389: 'ms_term_serv',
            5432: 'postgres', 8080: 'http_alt', 8443: 'https_alt',
            22: 'ssh'
        }
        return port_map.get(port, 'other')

# ===== FLASK APP FOR DASHBOARD =====

app = Flask(__name__)
CORS(app)

detection_log = []
detection_stats = {
    'total_packets': 0,
    'anomalies_detected': 0,
    'normal_packets': 0,
    'capture_active': False
}

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Return all detections"""
    return jsonify({
        'detections': detection_log[-100:],  # Last 100 detections
        'stats': detection_stats
    })

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Return detection statistics"""
    total = detection_stats['total_packets']
    if total > 0:
        anomaly_rate = (detection_stats['anomalies_detected'] / total) * 100
    else:
        anomaly_rate = 0
    
    return jsonify({
        'total_packets': detection_stats['total_packets'],
        'anomalies': detection_stats['anomalies_detected'],
        'normal': detection_stats['normal_packets'],
        'anomaly_rate': round(anomaly_rate, 1),
        'capture_active': detection_stats['capture_active']
    })

@app.route('/api/start_capture', methods=['POST'])
def start_capture():
    """Start packet capture"""
    global capture_thread, capture_thread_running
    
    if capture_thread_running:
        return jsonify({'status': 'error', 'message': 'Capture already running'})
    
    detection_stats['capture_active'] = True
    detection_log.clear()
    capture_thread_running = True
    
    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()
    
    return jsonify({'status': 'started', 'message': 'Packet capture started. Waiting for packets...'})

@app.route('/api/stop_capture', methods=['POST'])
def stop_capture():
    """Stop packet capture"""
    global capture_thread_running
    detection_stats['capture_active'] = False
    capture_thread_running = False
    return jsonify({'status': 'stopped', 'message': 'Packet capture stopped'})

@app.route('/api/clear_log', methods=['POST'])
def clear_log():
    """Clear detection log"""
    global detection_log, detection_stats
    detection_log = []
    detection_stats = {
        'total_packets': 0,
        'anomalies_detected': 0,
        'normal_packets': 0,
        'capture_active': detection_stats['capture_active']
    }
    return jsonify({'status': 'cleared'})

# ===== PACKET CAPTURE =====

extractor = PacketFeatureExtractor()
capture_thread = None

def packet_callback(packet):
    """Process each captured packet"""
    if not detection_stats['capture_active']:
        return
    
    try:
        features_dict = extractor.extract_features(packet)
        
        if 'src_ip' not in features_dict:
            return
        
        # Prepare features for ML model
        if feature_names:
            features_array = []
            for fname in feature_names:
                if fname in features_dict:
                    val = features_dict[fname]
                    if isinstance(val, str):
                        features_array.append(0)  # Default for string features
                    else:
                        features_array.append(float(val))
                else:
                    features_array.append(0)
            
            features_array = np.array([features_array])
            
            # Predict with Random Forest (most reliable)
            if rf_model:
                prediction = rf_model.predict(features_array)[0]
                anomaly_score = rf_model.predict_proba(features_array)[0][1]
                
                detection_stats['total_packets'] += 1
                
                timestamp = datetime.now().strftime("%H:%M:%S")
                
                if prediction == 1:  # Anomaly detected
                    detection_stats['anomalies_detected'] += 1
                    
                    detection = {
                        'timestamp': timestamp,
                        'type': 'REAL_PACKET_ANOMALY',
                        'src_ip': features_dict.get('src_ip', 'unknown'),
                        'dst_ip': features_dict.get('dst_ip', 'unknown'),
                        'src_port': features_dict.get('src_port', 0),
                        'dst_port': features_dict.get('dst_port', 0),
                        'protocol': features_dict.get('protocol_type', 'unknown'),
                        'service': features_dict.get('service', 'unknown'),
                        'anomaly_score': round(anomaly_score, 3),
                        'model': 'Random Forest'
                    }
                    
                    detection_log.append(detection)
                    print(f"🚨 ANOMALY: {detection['src_ip']} → {detection['dst_ip']} | {detection['protocol'].upper()} | Score: {detection['anomaly_score']}")
                else:
                    detection_stats['normal_packets'] += 1
                    
    except Exception as e:
        pass

def capture_packets():
    """Start sniffing network packets"""
    global capture_thread_running
    print("\n[*] Starting packet capture on default interface...")
    
    try:
        # Sniff packets indefinitely
        sniff(
            prn=packet_callback,
            store=False,
            iface=None,  # Use default interface
            filter=None,  # Capture all packets
            quiet=True
        )
    except PermissionError:
        print("\n⚠️  PERMISSION DENIED: Packet capture requires Admin/Root privileges!")
        print("━" * 60)
        print("On Windows:")
        print("  1. Close this window")
        print("  2. Right-click Command Prompt → 'Run as administrator'")
        print("  3. Navigate to project folder and run again")
        print("\nOn Linux:")
        print("  sudo python run_with_real_capture.py")
        print("━" * 60)
        detection_stats['capture_active'] = False
        capture_thread_running = False
    except Exception as e:
        print(f"❌ Capture error: {e}")
        detection_stats['capture_active'] = False
        capture_thread_running = False

capture_thread_running = False

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🛡️  REAL-TIME NETWORK ANOMALY DETECTOR")
    print("="*60)
    print(f"✅ Models Loaded: RF={'Yes' if rf_model else 'No'}, MLP={'Yes' if mlp_model else 'No'}, IF={'Yes' if iforest_model else 'No'}")
    print(f"✅ API Server: http://localhost:5000")
    print("\n📢 DASHBOARD: Open http://localhost:8000")
    print("📡 Click 'Capture Real Traffic' to start packet sniffing")
    print("⚠️  Note: Packet capture needs Admin/Root privileges")
    print("="*60 + "\n")
    
    # Start Flask app (doesn't require admin)
    try:
        app.run(debug=False, host='127.0.0.1', port=5000, threaded=True, use_reloader=False)
    except Exception as e:
        print(f"Error starting Flask app: {e}")
        print("Make sure port 5000 is not already in use")
