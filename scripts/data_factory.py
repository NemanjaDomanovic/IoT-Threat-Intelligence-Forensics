import pandas as pd
import numpy as np
import json
import os
from datetime import datetime, timedelta

class IoTDataFactory:
    """
    Generator of synthetic IoT network traffic data for forensic analysis.
    Simulates Mirai botnet patterns (C2 beaconing and DDoS flooding).
    """
    
    def __init__(self, output_dir=None):
        if output_dir is None:
            script_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(script_dir)
            self.output_dir = os.path.join(project_root, "data")
        else:
            self.output_dir = os.path.abspath(output_dir)

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            print(f"[*] TARGET DATA LOCATION: {os.path.abspath(self.output_dir)}")

    def _generate_json_source(self, timestamp, ttl=64, port=80):
        """Simulates Malcolm/Zeek JSON format in the _source column."""
        data = {
            "@timestamp": timestamp.strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
            "ip": {"ttl": int(ttl)},
            "destination": {"port": int(port)},
            "network": {"ttl": int(ttl)}
        }
        return json.dumps(data).replace('"', "'") 

    def generate_heartbeat_data(self, filename="heartbeat_analysis.csv", n=2000):
        """Generates C2 communication data: 50% Normal (random), 50% Botnet (fixed)."""
        print(f"[*] Generating Heartbeat data ({n} rows)...")
        
        #Target timeline 2018 (to match ForensicsEngine filter)
        base_time = datetime(2018, 5, 20, 10, 0, 0)
        
        #Regular traffic (Gamma distribution for high jitter)
        normal_iat = np.random.gamma(shape=2.0, scale=5.0, size=n//2)
        
        #Botnet traffic (Normal distribution for machine-precision cadence)
        bot_iat = np.random.normal(loc=1.0, scale=0.0001, size=n//2)
        
        all_iats = np.concatenate([normal_iat, bot_iat])
        current_time = base_time
        rows = []
        
        for iat in all_iats:
            current_time += timedelta(seconds=float(iat))
            rows.append({
                "_source": self._generate_json_source(current_time)
            })
            
        df = pd.DataFrame(rows)
        output_path = os.path.join(self.output_dir, filename)
        df.to_csv(output_path, index=False)
        print(f"[✓] Successfully saved to: {output_path}")

    def generate_ddos_data(self, filename="ddos_traffic.csv", n=5000):
        """Generating DDoS traffic with fixed TTL signatures."""
        print(f"[*] Generating DDoS traffic data ({n} rows)...")
        
        base_time = datetime(2018, 5, 20, 11, 0, 0)
        rows = []
        
        for i in range(n):
            #Mirai-style attack simulation
            is_attack = i > n // 2
            ttl = 64 if is_attack else np.random.randint(40, 128)
            port = np.random.choice([23, 80, 443, 8080]) if is_attack else np.random.randint(1024, 65535)
            
            timestamp = base_time + timedelta(milliseconds=i * 10)
            rows.append({
                "_source": self._generate_json_source(timestamp, ttl, port)
            })
            
        df = pd.DataFrame(rows)
        output_path = os.path.join(self.output_dir, filename)
        df.to_csv(output_path, index=False)
        print(f"[✓] Successfully saved to: {output_path}")

if __name__ == "__main__":
    factory = IoTDataFactory()
    factory.generate_heartbeat_data()
    factory.generate_ddos_data()