IoT Botnet Forensics: Dynamic Sliding-Window Variance Analysis (DSWVA)

![Build Status](https://img.shields.io/badge/build-passing-brightgreen?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)
![Domain](https://img.shields.io/badge/Domain-Network%20Forensics-red?style=flat-square)

Abstract

This project implements a proprietary forensic analysis engine designed to detect automated Command-and-Control (C2) channels within IoT botnets (specifically Mirai architectures). Unlike traditional signature-based Intrusion Detection Systems (IDS) which fail against encrypted or polymorphic payloads, this engine utilizes behavioral statistical analysis.

The core innovation is the Dynamic Sliding-Window Variance Analysis (DSWVA) algorithm, which isolates deterministic machine signatures (beaconing) from stochastic background noise (jitter), achieving a machine precision score of `0.0000` in controlled environments.

Key Innovation: DSWVA Algorithm

Traditional variance analysis ($\sigma^2$) often yields false negatives due to high global network jitter caused by latency and packet loss. This engine implements a rolling window approach to detect micro-bursts of automation:

1.  Ingestion: Parses raw telemetry from Malcolm/Zeek JSON exports.
2.  Sanitization: Filters traffic by temporal attack windows (e.g., Mirai 2018 Campaign) to remove analysis artifacts.
3.  Calculation: Computes variance over a sliding window ($N=10$) of Inter-Arrival Times (IAT).
4.  Detection: Flags windows where variance drops below a critical threshold ($\epsilon < 10^{-6}$), confirming automated script execution regardless of payload encryption.

Project Architecture

```text
/IoT-Botnet-Forensics
│
├── data/                   # Input Telemetry (Sanitized CSVs)
│   ├── heartbeat_analysis.csv
│   └── ddos_traffic.csv
│
├── evidence/               # Generated Forensic Artifacts
│   ├── evid_06_advanced_analysis.png
│   └── FORENSIC_REPORT_FINAL.txt
│
├── forensics_engine.py     # Core Analysis Class (DSWVA Implementation)
├── requirements.txt        # Dependencies
└── README.md               # Documentation


Setup & Usage
Prerequisites
Python 3.8+
Pandas, Matplotlib, NumPy (see requirements.txt)

Installation
git clone [https://github.com/YOUR_USERNAME/IoT-Botnet-Forensics.git](https://github.com/YOUR_USERNAME/IoT-Botnet-Forensics.git)
cd IoT-Botnet-Forensics
pip install -r requirements.txt

Execution
Run the main forensic engine:
python3 forensics_engine.py

Output & Results
The engine generates two key artifacts:
Forensic Dashboard: A visualization correlating the C2 timeline with the DDoS attack vector.
Integrity Report: A SHA-256 hashed text file containing the mathematical proof of automation.
Sample Findings (Dec 2018 Dataset):
Global Jitter: 1137.50 ms (Indicates high network noise)
DSWVA Precision Score: 0.0000000000 (Confirms deterministic automation