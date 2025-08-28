# APATCP: A Novel SDN-Enabled Framework for Adaptive Detection of Advanced TCP Flooding Attacks in IoT Networks

## 🔍 Overview

**APATCP** is a novel multi-controller SDN-based framework built for detecting and mitigating sophisticated **TCP flooding DDoS attacks** in resource-constrained **IoT networks**. Using **P4-programmable switches**, **machine learning**, and decentralized SDN controllers, APATCP achieves high accuracy and low latency in real-time traffic anomaly detection and mitigation.


## 📌 Key Features

- ✅ **P4-based traffic analytics** with 24 real-time features
- ✅ **Modular detection pipeline**: ACID, DTAM, DTAC, and FlowGuard-AP
- ✅ **Multi-controller coordination** with secure MQTT-based channels
- ✅ **Adaptive ensemble classifier (AWEC)** using 6 ML models
- ✅ **Tested against 8 TCP-based DDoS scenarios**
- ✅ 99.3% Accuracy | <0.4% FPR | <100ms latency

## 🧠 Key Contributions

- **ACID Framework**: An intelligent, scalable SD-IoT architecture that performs adaptive mitigation through decentralized collaboration.
- **Five Algorithmic Modules**:
  1. **DTAM** – Dynamic Traffic Anomaly Mitigation
  2. **P4-FE** – P4-Based Stateful Feature Extraction
  3. **FlowGuard-AP** – Flow-based Adaptive Protection
  4. **INAD** – Intelligent Network Anomaly Detector (Ensemble Classifier)
  5. **ACID System** – Full orchestration for SD-IoT with real-time optimization and cryptographic communication

  ## 🧱 Architecture
🧩 Modules:
- **ACID** – Collaborative intrusion detection
- **DTAM** – Dynamic anomaly mitigation
- **DTAC** – Real-time threat classification
- **FlowGuard-AP** – Adaptive response engine

## 📂 Project Structure
APATCP/
│
├── controller/
│   ├── apatcp_controller_agent.py     # Main SDN controller logic (ACID, FlowGuard, DTAM integration)
│   ├── awec_model.pkl                 # Pretrained Adaptive Weighted Ensemble Classifier (DTAC)
│   └── config/
│       ├── controller_config.json     # Controller ID, mode (ACI/GCI), MQTT topics
│       ├── model_config.json          # ML model parameters & selected features
│       ├── mitigation_policy.json     # Per-scenario mitigation strategies
│
├── topology/
│   ├── apatcp_topo.py                 # Mininet-WiFi simulation with P4 switches and IoT domains
│
├── p4src/
│   ├── apatcp_module.p4               # Main P4 program (features, counters, detection logic)
│   └── headers.p4                     # TCP/IP header formats and parsers
│
├── attack_simulator/
│   ├── attack_launcher.py             # Launches SYN, ACK, HTTP floods, Slowloris, etc.
│   └── attack_profiles.json           # Definitions of attack scenarios and timing
│
├── runtime_config/
│   ├── p4runtime_controller.py        # P4Runtime interface with BMv2 switches
│   ├── forwarding_rules.json          # Static flow entries for IoT communication
│   ├── mitigation_rules.json          # Dynamic rules for rate limiting, flow drop, and flag filtering
│
├── logs/
│   ├── controller.log                 # Detection events, anomaly scores, response logs
│   ├── switch_digest.log              # Logs from P4 digest/alerts
│
└── README.md                          # Full overview of architecture, usage, and results

## ⚙️ Installation
```bash
git clone https://github.com/AyaHassanAli/APATCP.git
cd APATCP
pip install -r requirements.txt


## 🛠 Requirements

- Python ≥ 3.8
- scikit-learn
- numpy
- pandas
- paho-mqtt
- cryptography

## 🚀 Quickstart
Run demo with synthetic data:
python code/run_detection.py --dataset data/sample.csv

Or test on public dataset (CICIoT2024, ToN_IoT):
python code/train_model.py --dataset data/CICIoT2024.csv

##🧠 Datasets Used

[CICIoT2024](https://www.unb.ca/cic/datasets/iot2024.html)

[Edge-IIoTset](https://www.kaggle.com/datasets/iot2023/edge-iiot-dataset)

[ToN_IoT](https://research.unsw.edu.au/projects/toniot-datasets)


## 📈 Performance Metrics
| Attack Scenario   | Accuracy | F1-Score | Latency | CPU Usage |
| ----------------- | -------- | -------- | ------- | --------- |
| SYN Flood         | 99.3%    | 99.5%    | 25 ms   | < 15%     |
| ACK Flood         | 98.9%    | 99.1%    | 30 ms   | < 20%     |
| HTTP Flood        | 97.2%    | 97.4%    | 70 ms   | < 30%     |
| LRDoS (Slowloris) | 95.6%    | 96.0%    | 60 ms   | < 18%     |

