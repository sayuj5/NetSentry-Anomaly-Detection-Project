"""
COMPREHENSIVE TEST SUITE
Runs all attack scenarios and measures detection effectiveness.
"""

import time
import threading
from datetime import datetime
from attack_simulator import (
    simulate_ddos_flood,
    simulate_port_scan,
    simulate_ssh_brute_force,
    simulate_http_ddos,
    simulate_sql_injection_attempts,
    simulate_ftp_brute_force,
    simulate_icmp_flood,
    simulate_udp_port_scan
)
from live_detector import LiveAnomalyDetector


class TestSuite:
    """
    Master test suite for all attack types and detection scenarios.
    """
    
    def __init__(self, detector=None):
        """
        Initialize test suite with optional detector instance.
        """
        self.detector = detector or LiveAnomalyDetector()
        self.test_results = []
        self.total_start_time = None
    
    def run_test_scenario(self, scenario_name, scenario_func, duration=30):
        """
        Run a single attack scenario and measure detections.
        """
        print(f"\n{'='*70}")
        print(f"SCENARIO: {scenario_name}")
        print(f"{'='*70}\n")
        
        initial_count = self.detector.anomalies_detected
        test_start = time.time()
        
        try:
            # Run attack
            scenario_func()
        except Exception as e:
            print(f"❌ Error during attack: {str(e)[:100]}")
        
        test_duration = time.time() - test_start
        detected = self.detector.anomalies_detected - initial_count
        
        result = {
            'scenario': scenario_name,
            'duration': test_duration,
            'anomalies_detected': detected,
            'timestamp': datetime.now()
        }
        
        self.test_results.append(result)
        
        print(f"\n📊 Results for {scenario_name}:")
        print(f"   Duration: {test_duration:.2f}s")
        print(f"   Anomalies Detected: {detected}")
        print(f"   Detection Rate: {(detected > 0 and '✅ DETECTED') or '❌ MISSED'}")
        print()
        
        return result
    
    def run_all_scenarios(self, sniff_timeout=300):
        """
        Run all attack scenarios sequentially with live detection.
        
        Args:
            sniff_timeout: Total timeout for packet sniffing (seconds)
        """
        print(f"\n{'='*70}")
        print("🚀 STARTING COMPREHENSIVE ATTACK TEST SUITE")
        print(f"   Start Time: {datetime.now()}")
        print(f"   Sniffer Timeout: {sniff_timeout}s")
        print(f"{'='*70}\n")
        
        self.total_start_time = time.time()
        
        # Define all test scenarios
        scenarios = [
            ("SYN Flood (DDoS Attack)", lambda: simulate_ddos_flood('192.168.1.1', 15, 100)),
            ("ICMP Flood (Ping Flood)", lambda: simulate_icmp_flood('192.168.1.1', 15, 100)),
            ("Port Scan (TCP)", lambda: simulate_port_scan('192.168.1.1', [22, 80, 443, 3306])),
            ("UDP Port Scan", lambda: simulate_udp_port_scan('192.168.1.1', [53, 123, 161])),
            ("SSH Brute Force", lambda: simulate_ssh_brute_force('192.168.1.1', 22, 30)),
            ("FTP Brute Force", lambda: simulate_ftp_brute_force('192.168.1.1', 21, 20)),
            ("SQL Injection Attack", lambda: simulate_sql_injection_attempts('http://localhost:8080/api', 20)),
            ("HTTP DDoS (Layer 7)", lambda: simulate_http_ddos('http://localhost:8080', 15, 5))
        ]
        
        # Run each scenario
        for name, func in scenarios:
            if time.time() - self.total_start_time > sniff_timeout:
                print(f"\n⏱️  Sniffing timeout reached. Ending test suite.")
                break
            
            time.sleep(3)  # Pause between scenarios
            self.run_test_scenario(name, func)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print comprehensive test results summary."""
        total_duration = time.time() - self.total_start_time
        total_detected = sum(r['anomalies_detected'] for r in self.test_results)
        
        print(f"\n{'='*70}")
        print("📋 TEST SUITE SUMMARY")
        print(f"{'='*70}\n")
        
        print(f"Total Duration: {total_duration:.2f}s")
        print(f"Total Scenarios: {len(self.test_results)}")
        print(f"Total Anomalies Detected: {total_detected}")
        print(f"Overall Detection Rate: {(total_detected > 0 and '✅ SUCCESS') or '❌ NO DETECTIONS'}\n")
        
        print("Scenario-by-Scenario Results:")
        print("-" * 70)
        for result in self.test_results:
            status = "✅ DETECTED" if result['anomalies_detected'] > 0 else "❌ MISSED"
            print(f"  {result['scenario']:<40} {status:<15} ({result['duration']:.1f}s)")
        
        print(f"\n{'='*70}")
        
        # Get final statistics
        stats = self.detector.get_statistics()
        print("\nFinal Detection Statistics:")
        print(f"  Normal Traffic Packets: {stats['normal_traffic']}")
        print(f"  Anomalies Detected: {stats['anomalies_detected']}")
        print(f"  Total Packets Analyzed: {stats['total_packets']}")
        print(f"  Overall Detection Rate: {stats['detection_rate']:.2f}%")
        
        print(f"\n{'='*70}\n")
    
    def export_results(self, filename='test_results.txt'):
        """Export test results to a file."""
        with open(filename, 'w') as f:
            f.write(f"NetSentry Anomaly Detection Test Suite Results\n")
            f.write(f"{'='*70}\n")
            f.write(f"Test Date: {datetime.now()}\n\n")
            
            for result in self.test_results:
                f.write(f"Scenario: {result['scenario']}\n")
                f.write(f"  Duration: {result['duration']:.2f}s\n")
                f.write(f"  Anomalies Detected: {result['anomalies_detected']}\n")
                f.write(f"  Status: {'DETECTED' if result['anomalies_detected'] > 0 else 'MISSED'}\n\n")
            
            stats = self.detector.get_statistics()
            f.write(f"Final Statistics:\n")
            f.write(f"  Total Anomalies: {stats['anomalies_detected']}\n")
            f.write(f"  Normal Traffic: {stats['normal_traffic']}\n")
            f.write(f"  Detection Rate: {stats['detection_rate']:.2f}%\n")
        
        print(f"✅ Results exported to {filename}")


def main():
    """
    Main entry point for running the test suite.
    """
    print("\n" + "="*70)
    print("NetSentry - Anomaly Detection Test Suite Launcher")
    print("="*70)
    
    print("\nOptions:")
    print("  1. Run with LIVE DETECTION (requires admin/root privileges)")
    print("  2. Run in SIMULATION MODE (no admin required)")
    print("  3. View attack simulator options only")
    
    choice = input("\nEnter choice (1-3): ").strip()
    
    if choice == '1':
        print("\n⚠️  This requires ADMIN/ROOT privileges for packet capturing.")
        print("   Windows: Run Command Prompt/PowerShell as Administrator")
        print("   Linux/Mac: Run with 'sudo python test_suite.py'\n")
        
        confirm = input("Continue with live detection? (y/n): ").strip().lower()
        
        if confirm == 'y':
            detector = LiveAnomalyDetector()
            
            # Start sniffer in background thread
            sniff_thread = threading.Thread(
                target=detector.start_sniffing,
                kwargs={'timeout': 300},
                daemon=True
            )
            sniff_thread.start()
            
            time.sleep(2)  # Let sniffer start
            
            # Run test suite
            suite = TestSuite(detector)
            suite.run_all_scenarios(sniff_timeout=300)
            
            sniff_thread.join(timeout=5)
        else:
            print("Cancelled.")
    
    elif choice == '2':
        print("\n✅ Running in SIMULATION MODE\n")
        
        suite = TestSuite()
        
        # Run scenarios without live capture
        scenarios = [
            ("SYN Flood (DDoS Attack)", lambda: simulate_ddos_flood('192.168.1.1', 2, 20)),
            ("Port Scan (TCP)", lambda: simulate_port_scan('192.168.1.1', [22, 80, 443])),
            ("SSH Brute Force", lambda: simulate_ssh_brute_force('192.168.1.1', 22, 10)),
        ]
        
        for name, func in scenarios:
            time.sleep(1)
            suite.run_test_scenario(name, func)
        
        suite.print_summary()
        suite.export_results()
    
    elif choice == '3':
        print("\nAvailable Attack Simulators:")
        print("  - simulate_ddos_flood(target_ip, duration, packet_rate)")
        print("  - simulate_icmp_flood(target_ip, duration, packet_rate)")
        print("  - simulate_port_scan(target_ip, ports)")
        print("  - simulate_udp_port_scan(target_ip, ports)")
        print("  - simulate_ssh_brute_force(target_ip, port, attempts)")
        print("  - simulate_ftp_brute_force(target_ip, port, attempts)")
        print("  - simulate_http_ddos(target_url, duration, threads)")
        print("  - simulate_sql_injection_attempts(target_url, attempts)")
    
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
