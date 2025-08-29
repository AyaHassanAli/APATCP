"""
Dynamic Traffic Anomaly Mitigation (DTAM) Algorithm Implementation
A Python implementation of the DTAM algorithm for dynamic threshold-based traffic analysis and mitigation using P4-enabled switches.
"""

import time
import random
import logging
from typing import Dict, List, Any
from dataclasses import dataclass, field

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("DTAM")

@dataclass
class DATSConfig:
    """Configuration for Dynamic Anomaly Thresholding System."""
    baseline_traffic: Dict[str, float]
    thresholds: Dict[str, float]

@dataclass
class Packet:
    """Simplified representation of a network packet."""
    size: int
    src_ip: str
    dst_ip: str
    protocol: str
    flags: List[str]

@dataclass
class MitigationPolicy:
    """Defines a mitigation policy."""
    name: str
    action: str  
    parameters: Dict[str, Any]

@dataclass
class AnomalyScore:
    score: float
    attack_type: str


class DATS:
    """Dynamic Anomaly Thresholding System."""
    
    def __init__(self, config: DATSConfig):
        self.config = config
        self.feature_data: List[Dict[str, Any]] = []

    def populate(self, packet: Packet):
        """Extract features and store in DATS."""
        features = {
            "size": packet.size,
            "src_ip": packet.src_ip,
            "dst_ip": packet.dst_ip,
            "protocol": packet.protocol,
            "flags": packet.flags
        }
        self.feature_data.append(features)

    def analyze_traffic(self) -> AnomalyScore:
        """Analyze traffic and return anomaly score."""
        avg_packet_size = sum(p["size"] for p in self.feature_data) / len(self.feature_data)
        baseline_size = self.config.baseline_traffic.get("avg_packet_size", 500)
        deviation = abs(avg_packet_size - baseline_size) / baseline_size
        
        score = deviation * 100
        attack_type = "SYN Flood" if score > 40 else "Normal"
        return AnomalyScore(score=score, attack_type=attack_type)

    def update_baseline(self):
        """Update baseline based on recent traffic patterns."""
        if not self.feature_data:
            return
        avg_packet_size = sum(p["size"] for p in self.feature_data) / len(self.feature_data)
        self.config.baseline_traffic["avg_packet_size"] = avg_packet_size
        self.feature_data.clear()


class DTAMSystem:
    def __init__(self, dats_config: DATSConfig, policies: List[MitigationPolicy]):
        self.dats = DATS(dats_config)
        self.policies = policies

    def initialize_dtam(self):
        logger.info("DTAM Initialized with baseline traffic and mitigation policies.")

    def monitor_traffic(self, mns_traffic: List[Packet]):
        for packet in mns_traffic:
            self.dats.populate(packet)

    def adapt_thresholds(self, anomaly_score: AnomalyScore):
        if anomaly_score.score > self.dats.config.thresholds.get("anomaly", 30):
            logger.info(f"Adapting thresholds due to score: {anomaly_score.score:.2f}")
            self.dats.config.thresholds["anomaly"] += 5  # Example logic

    def apply_mitigation(self, anomaly_score: AnomalyScore):
        if anomaly_score.score > self.dats.config.thresholds.get("anomaly", 30):
            policy = self.select_policy(anomaly_score)
            logger.warning(f"Mitigation triggered: {policy.name} - Action: {policy.action}")

    def select_policy(self, anomaly_score: AnomalyScore) -> MitigationPolicy:
        if anomaly_score.attack_type == "SYN Flood":
            return next((p for p in self.policies if p.name == "SYN Policy"), self.policies[0])
        return self.policies[0]

    def update_baseline(self):
        self.dats.update_baseline()
        logger.info("Traffic baseline updated.")

    def run(self, system_runtime: int = 10):
        self.initialize_dtam()
        start_time = time.time()

        while time.time() - start_time < system_runtime:
            traffic_data = self.generate_mock_traffic()
            self.monitor_traffic(traffic_data)

            anomaly_score = self.dats.analyze_traffic()
            logger.info(f"Anomaly Score: {anomaly_score.score:.2f} ({anomaly_score.attack_type})")

            self.adapt_thresholds(anomaly_score)
            self.apply_mitigation(anomaly_score)
            self.update_baseline()

            time.sleep(1)

    def generate_mock_traffic(self) -> List[Packet]:
        return [
            Packet(
                size=random.randint(400, 1600),
                src_ip=f"192.168.0.{random.randint(1, 255)}",
                dst_ip=f"10.0.0.{random.randint(1, 255)}",
                protocol="TCP",
                flags=["SYN"] if random.random() < 0.3 else ["ACK"]
            ) for _ in range(100)
        ]

if __name__ == "__main__":
    baseline = {"avg_packet_size": 600}
    thresholds = {"anomaly": 30}
    dats_config = DATSConfig(baseline_traffic=baseline, thresholds=thresholds)

    policies = [
        MitigationPolicy(name="Default Policy", action="monitor", parameters={}),
        MitigationPolicy(name="SYN Policy", action="rate_limit", parameters={"limit": "100pps"})
    ]

    dtam = DTAMSystem(dats_config, policies)
    dtam.run(system_runtime=20)