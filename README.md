# ACID: A Novel SDN-Enabled Framework for Adaptive Detection of Advanced TCP Flooding Attacks in IoT Networks

## 📄 Overview

This repository contains the implementation of five core algorithms proposed in the paper:  
**"ACID: A Novel SDN-Enabled Framework for Adaptive Detection of Advanced TCP Flooding Attacks in IoT Networks"**.  
The framework presents a decentralized, real-time, and intelligent defense mechanism for detecting and mitigating DDoS attacks within Software-Defined IoT (SD-IoT) environments using P4 programmable data planes.

## 🧠 Key Contributions

- **ACID Framework**: An intelligent, scalable SD-IoT architecture that performs adaptive mitigation through decentralized collaboration.
- **Five Algorithmic Modules**:
  1. **DTAM** – Dynamic Traffic Anomaly Mitigation
  2. **P4-FE** – P4-Based Stateful Feature Extraction
  3. **FlowGuard-AP** – Flow-based Adaptive Protection
  4. **INAD** – Intelligent Network Anomaly Detector (Ensemble Classifier)
  5. **ACID System** – Full orchestration for SD-IoT with real-time optimization and cryptographic communication

## ⚙️ Algorithms

### 1. `DTAM` - Dynamic Traffic Anomaly Mitigation
Monitors multi-node P4 switch traffic in real-time, performs adaptive thresholding, and triggers mitigation when anomalies exceed defined baselines.

### 2. `P4-FE` - P4-Based Stateful Feature Extraction Engine
Implements per-flow metrics (SYN/ACK counters, inter-arrival times, flag patterns) using registers in P4 switches to identify malicious traffic.

### 3. `INAD` - Intelligent Network Anomaly Detector
A Python-based ensemble model that uses decision trees, random forest, gradient boosting, k-NN, SVM, and Naive Bayes for multi-class DDoS detection.

### 4. `FlowGuard-AP`
Analyzes real-time traffic against known attack patterns and modifies flow tables dynamically to isolate or quarantine malicious sources.

### 5. `ACID System`
An integrated controller-based defense system that:
- Encrypts alert communication (RTAC/SDSC) via MQTT
- Detects DDoS via real-time P4 traffic features
- Shares threat intelligence across controllers (ACI/GCI mode)
- Adapts mitigation strategies based on evolving attack vectors

## 🧪 Evaluation Highlights

- Achieved up to **99.69% detection accuracy** and **F1-score of 0.9929** using the INAD module.
- Demonstrated **low false alarm rate** (FAR < 1%) across multiple scenarios.
- Verified responsiveness and adaptability of ACID in simulated and real-world DDoS attacks like SYN flood, HTTP flood, and SynonymousIP attacks.

## 📁 Repository Structure

├── dtam.py # Dynamic Traffic Anomaly Mitigation
├── p4_feature_engine.py # P4-FE Stateful Feature Extraction
├── inad_classifier.py # INAD Ensemble Detection Module
├── flowguard_ap.py # FlowGuard-AP Mitigation Logic
├── acid_main.py # Main ACID System Implementation
├── utils/ 
└── README.md 

## 🔐 Cryptographic Security

The ACID system employs AES-based encryption using the `cryptography` library to secure MQTT communications between SD-IoT controllers.

## 🛠 Requirements

- Python ≥ 3.8
- scikit-learn
- numpy
- pandas
- paho-mqtt
- cryptography
