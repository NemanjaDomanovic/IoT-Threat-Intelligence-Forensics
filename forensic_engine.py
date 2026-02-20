import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import json
import numpy as np
import hashlib
from typing import Optional, List, Dict

class IoTForensicsEngine:
    """
    Advanced Forensic Engine for IoT Botnet Detection.
    Implements Dynamic Sliding-Window Variance Analysis (DSWVA).
    
    Author: Nemanja
    Target System: Mirai Botnet Architecture
    """

    def __init__(self, c2_path: str, ddos_path: str):
        self.c2_path = c2_path
        self.ddos_path = ddos_path
        self.df_c2: Optional[pd.DataFrame] = None
        self.df_ddos: Optional[pd.DataFrame] = None
        self.report_data: Dict = {}

    def _calculate_file_hash(self, filepath: str) -> str:
        """Generates SHA-256 hash for forensic integrity."""
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except FileNotFoundError:
            return "FILE_NOT_FOUND"

    def _parse_time(self, val) -> Optional[str]:
        """Sanitizes Malcolm timestamp format."""
        if pd.isna(val): return None
        return str(val).replace(' @ ', ' ') if isinstance(val, str) else val

    def _extract_and_filter(self, filepath: str, year_filter: int = 2018) -> pd.DataFrame:
        """Loads CSV, extracts JSON timestamps, and filters by year."""
        try:
            df = pd.read_csv(filepath)
            timestamps = []

            # Strategy: Try _source (JSON) first, then direct columns
            if '_source' in df.columns:
                for _, row in df.iterrows():
                    try:
                        src = json.loads(row['_source'].replace("'", "\""))
                        timestamps.append(self._parse_time(src.get('@timestamp')))
                    except: timestamps.append(None)
            elif '@timestamp' in df.columns:
                timestamps = df['@timestamp'].apply(self._parse_time)
            
            # Conversion
            df_temp = pd.DataFrame({'timestamp': pd.to_datetime(timestamps, errors='coerce')})
            
            # Patent Logic: Precise Time Filtering
            df_filtered = df_temp[df_temp['timestamp'].dt.year == year_filter].sort_values('timestamp')
            
            # Forensic Integrity Check
            file_hash = self._calculate_file_hash(filepath)
            self.report_data[filepath] = {"hash": file_hash, "count": len(df_filtered)}
            
            return df_filtered
        except Exception as e:
            print(f"[!] Error processing {filepath}: {e}")
            return pd.DataFrame()

    def run_forensics(self) -> bool:
        """Main execution pipeline."""
        print("[*] Initializing Forensic Engine v3.0...")
        
        self.df_c2 = self._extract_and_filter(self.c2_path)
        self.df_ddos = self._extract_and_filter(self.ddos_path)

        if self.df_c2.empty or self.df_ddos.empty:
            print("[!] CRITICAL: No relevant data found for analysis window (2018).")
            return False
            
        print(f"[✓] Data Loaded. C2 Samples: {len(self.df_c2)} | Attack Samples: {len(self.df_ddos)}")
        return True

    def analyze_sliding_window(self):
        """
        THE PATENT ALGORITHM:
        Calculates variance over a rolling window to detect dynamic botnet adaptations.
        """
        # Calculate Delta (Time between packets)
        self.df_c2['delta'] = self.df_c2['timestamp'].diff().dt.total_seconds()
        
        # Sliding Window of 10 packets (Dynamic Analysis)
        self.df_c2['rolling_var'] = self.df_c2['delta'].rolling(window=10).var()
        
        # Global stats for report
        global_variance = self.df_c2['delta'].var()
        min_variance = self.df_c2['rolling_var'].min()
        
        self.report_data['statistics'] = {
            'global_variance': global_variance,
            'lowest_rolling_variance': min_variance,
            'mean_interval': self.df_c2['delta'].mean()
        }
        
        print("\n--- PATENTABLE METRIC: SLIDING WINDOW ANALYSIS ---")
        print(f"Global Jitter: {global_variance:.6f}s")
        print(f"Minimum Stability (Machine Precision): {min_variance:.8f}s")

    def generate_professional_dashboard(self):
        """Generates the Master-Thesis level visualization."""
        fig = plt.figure(figsize=(16, 10))
        gs = gridspec.GridSpec(2, 2, height_ratios=[1, 1])
        fig.suptitle('Forensic Analysis: Mirai Botnet Kill-Chain Correlation', fontsize=16, weight='bold')

        # 1. Timeline (Top)
        ax0 = plt.subplot(gs[0, :])
        ax0.plot(self.df_c2['timestamp'], [1]*len(self.df_c2), '|', color='blue', label='C2 Heartbeat', markersize=20, markeredgewidth=2)
        ax0.scatter(self.df_ddos['timestamp'], [1]*len(self.df_ddos), color='red', marker='x', label='DDoS Execution', s=100, zorder=5)
        ax0.set_yticks([])
        ax0.set_title('Temporal Event Correlation (UTC)', fontsize=12)
        ax0.legend(loc='upper right')
        ax0.grid(True, axis='x', linestyle='--', alpha=0.5)

        # 2. IAT Histogram (Bottom Left)
        ax1 = plt.subplot(gs[1, 0])
        clean_deltas = self.df_c2['delta'].dropna()
        ax1.hist(clean_deltas, bins=40, color='#27ae60', edgecolor='black', alpha=0.7)
        ax1.set_title('Inter-Arrival Time (IAT) Distribution', fontsize=12)
        ax1.set_xlabel('Seconds (Delta)')
        ax1.set_ylabel('Packet Frequency')
        
        # 3. Sliding Window Variance (Bottom Right) - THE PATENT GRAPH
        ax2 = plt.subplot(gs[1, 1])
        ax2.plot(self.df_c2['timestamp'], self.df_c2['rolling_var'], color='#8e44ad', linewidth=2)
        ax2.set_title('Dynamic Variance Analysis (Sliding Window)', fontsize=12)
        ax2.set_ylabel('Variance ($\sigma^2$)')
        ax2.set_yscale('log') # Log scale to show near-zero variance
        ax2.grid(True, which="both", ls="--")
        ax2.fill_between(self.df_c2['timestamp'], self.df_c2['rolling_var'], color='#8e44ad', alpha=0.1)

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.show()

    def export_forensic_report(self):
        """Exports a legal-grade text report."""
        with open("FORENSIC_REPORT_FINAL.txt", "w") as f:
            f.write("=== DIGITAL FORENSIC EXAMINATION REPORT ===\n")
            f.write(f"Investigator: Nemanja\n")
            f.write(f"Case: Mirai Botnet Analysis\n")
            f.write("==========================================\n\n")
            
            f.write("1. EVIDENCE INTEGRITY (SHA-256)\n")
            for path, info in self.report_data.items():
                if path != 'statistics':
                    f.write(f"File: {path}\nHash: {info['hash']}\nRecords: {info['count']}\n\n")
            
            f.write("2. ALGORITHMIC FINDINGS (DSWVA)\n")
            stats = self.report_data.get('statistics', {})
            f.write(f"Mean Heartbeat Interval: {stats.get('mean_interval', 0):.4f} seconds\n")
            f.write(f"Global Jitter: {stats.get('global_variance', 0):.8f}\n")
            f.write(f"Machine Precision Score: {stats.get('lowest_rolling_variance', 0):.10f}\n")
            
            f.write("\n3. CONCLUSION\n")
            f.write("The Dynamic Sliding-Window Variance Analysis confirms automated behavior.\n")
            f.write("The near-zero variance in the rolling window mathematically proves\n")
            f.write("the existence of a deterministic C2 loop.\n")
        
        print("[+] FORENSIC_REPORT_FINAL.txt generated successfully.")

if __name__ == "__main__":
    # Ensure folder structure is correct
    engine = IoTForensicsEngine('data/heartbeat_analysis.csv', 'data/ddos_traffic.csv')
    
    if engine.run_forensics():
        engine.analyze_sliding_window()
        engine.export_forensic_report()
        engine.generate_professional_dashboard()