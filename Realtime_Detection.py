import pandas as pd
import joblib
from scapy.all import IP, TCP, UDP
import time
import random
import sys
import warnings
from collections import defaultdict

# Suppress scikit-learn warnings
warnings.filterwarnings("ignore", category=UserWarning) 

# --- Configuration ---
MODEL_FILENAME = 'intrusionnet_sentinel_model.pkl'
SCALER_FILENAME = 'sentinel_scaler.pkl'
FEATURES_FILENAME = 'sentinel_features.pkl'

# SIMULATION MODE: Set to True to bypass network driver issues (Npcap/WinPcap) 
# and use synthetic packet generation for testing the ML pipeline logic.
SIMULATION_MODE = True 

ALERT_COOLDOWN_SECONDS = 2
NUMERICAL_FEATURES = ['duration', 'src_bytes', 'dst_bytes']
CATEGORICAL_FEATURES = ['protocol_type', 'service']

class SentinelDetector:
    """
    Handles packet processing, feature extraction, and ML prediction.
    Runs in simulation mode to ensure core ML logic works despite environment issues.
    """
    def __init__(self):
        self.model = None
        self.scaler = None
        self.expected_features = []
        
        # State tracking for flow-based feature calculation
        self.flow_stats = defaultdict(lambda: {
            'start_time': time.time(), 
            'packet_count': 0, 
            'total_src_bytes': 0, 
            'total_dst_bytes': 0
        })
        self.last_alert_time = defaultdict(float)
        
        self._load_assets()

    def _load_assets(self):
        """Loads the saved ML model, scaler, and feature list."""
        try:
            self.model = joblib.load(MODEL_FILENAME)
            self.scaler = joblib.load(SCALER_FILENAME)
            self.expected_features = joblib.load(FEATURES_FILENAME)
            print(f"✅ Sentinel assets loaded.")
        except FileNotFoundError as e:
            print(f"❌ ERROR: Missing asset file {e.filename}. Run 'Train_Sentinel_Model.py' first.")
            sys.exit(1)

    def _get_flow_key(self, packet):
        """Extracts the 5-tuple flow key from a packet."""
        if not packet.haslayer(IP): return None, None
        ip = packet[IP]
        
        if packet.haslayer(TCP):
            proto = 'tcp'
            sport, dport = packet[TCP].sport, packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = 'udp'
            sport, dport = packet[UDP].sport, packet[UDP].dport
        else:
            proto = 'icmp'
            sport, dport = 0, 0
            
        # 5-tuple: (Source IP, Destination IP, Protocol, Source Port, Destination Port)
        return (ip.src, ip.dst, proto, sport, dport), ip.src

    def _update_flow_stats(self, flow_key, src_ip, packet_size):
        """Updates the running statistical features for a flow."""
        stats = self.flow_stats[flow_key]
        current_time = time.time()
        
        if stats['packet_count'] == 0: stats['start_time'] = current_time 
        stats['packet_count'] += 1
        
        if src_ip == flow_key[0]: stats['total_src_bytes'] += packet_size
        else: stats['total_dst_bytes'] += packet_size
            
        duration = current_time - stats['start_time']
        
        # Mapping service
        port, proto = flow_key[4], flow_key[2]
        service = 'http' if port == 80 else 'ftp' if port == 21 else 'other'
        
        return {
            'duration': duration,
            'protocol_type': proto,
            'src_bytes': stats['total_src_bytes'],
            'dst_bytes': stats['total_dst_bytes'],
            'service': service,
            'logged_in': 0 
        }

    def _predict_and_alert(self, features, flow_key):
        """Transforms features, performs prediction, and prints alert."""
        
        # 1. Create DataFrame and apply One-Hot Encoding
        df = pd.DataFrame([features])
        df = pd.get_dummies(df, columns=CATEGORICAL_FEATURES, drop_first=True)
        
        # 2. Align columns with training data (The fix for the 'iloc' error)
        aligned_data = {}
        for col in self.expected_features:
            if col in df.columns:
                # Column exists, take the value (iloc[0] is safe since df is a single row)
                aligned_data[col] = df[col].iloc[0]
            else:
                # Column is missing (e.g., 'protocol_type_icmp' not in this flow), set to 0
                aligned_data[col] = 0
                
        final_input = pd.DataFrame([aligned_data])
        
        # 3. Scale numerical features and Predict
        final_input[NUMERICAL_FEATURES] = self.scaler.transform(final_input[NUMERICAL_FEATURES])
        prediction = self.model.predict(final_input)[0]
        
        if prediction == 1: 
            if time.time() - self.last_alert_time[flow_key] > ALERT_COOLDOWN_SECONDS:
                # Get confidence score
                try:
                    conf = self.model.predict_proba(final_input)[0][1]
                except:
                    conf = 1.0 # Default if model doesn't support probability

                print(f"\n🚨 ALERT | {flow_key[0]} -> {flow_key[1]} | {flow_key[2].upper()} | Attack Confidence: {conf:.2f}")
                self.last_alert_time[flow_key] = time.time()
        elif SIMULATION_MODE:
             # Overwrite the line to show constant activity without clutter
             print(f"✅ Normal Traffic | {flow_key[0]} -> {flow_key[1]}      ", end='\r')

    def process_packet(self, packet):
        """The core packet processing function."""
        if packet.haslayer(IP):
            flow_key, src_ip = self._get_flow_key(packet)
            if flow_key:
                # Packet length is required for src_bytes/dst_bytes
                features = self._update_flow_stats(flow_key, src_ip, len(packet))
                self._predict_and_alert(features, flow_key)

    def start_simulation(self):
        """Generates synthetic packets and runs the detector."""
        print(f"\n📡 IntrusionNet Sentinel: SIMULATION MODE ACTIVE")
        print("Generating synthetic network traffic to test detection logic...")
        print("Press Ctrl+C to stop.\n")
        
        while True:
            try:
                if random.random() > 0.85: 
                    # Simulated "Attack" Packet (Large payload for anomaly)
                    pkt = IP(src="192.168.1.50", dst="10.0.0.1")/TCP(dport=80)/("X"*2000)
                else:
                    # Simulated "Normal" Packet (DNS or general traffic)
                    pkt = IP(src="192.168.1.105", dst="8.8.8.8")/UDP(dport=53)/("query")
                
                self.process_packet(pkt)
                time.sleep(0.5) 
                
            except KeyboardInterrupt:
                print("\n🛑 Simulation stopped.")
                break

    def start(self):
        """Entry point for the application."""
        if SIMULATION_MODE:
            self.start_simulation()
        else:
            # Live Sniffer requires Npcap/WinPcap and elevated privileges
            from scapy.all import sniff, conf
            print("Starting Live Sniffer (Requires Npcap and Administrator privileges)...")
            sniff(prn=self.process_packet, store=0, L2socket=conf.L3socket) 

if __name__ == '__main__':
    detector = SentinelDetector()
    detector.start()
