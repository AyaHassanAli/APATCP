
import time
import logging
from typing import List, Dict, Any, Tuple
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("FlowGuard-AP")

class TrafficEntry:
    """Represents a unit of real-time IoT traffic."""
    def __init__(self, source_ip: str, dst_ip: str, mac: str, headers: Dict[str, Any], state: Dict[str, Any]):
        self.source_ip = source_ip
        self.dst_ip = dst_ip
        self.mac = mac
        self.headers = headers  
        self.state = state      

class AttackPattern:
    """Defines a known malicious pattern."""
    def __init__(self, pattern_id: str, rule_conditions: Dict[str, Any], mitigation_actions: List[str]):
        self.pattern_id = pattern_id
        self.rule_conditions = rule_conditions
        self.mitigation_actions = mitigation_actions

class MaliciousTrafficEntry:
    """Represents detected malicious flow and related mitigation strategy."""
    def __init__(self, entry: TrafficEntry, attack_pattern: AttackPattern):
        self.entry = entry
        self.pattern = attack_pattern
        self.attack_rules = attack_pattern.mitigation_actions



Threat_Database: List[AttackPattern] = []
Mitigation_Table: Dict[str, MaliciousTrafficEntry] = {}
P4_IoT_FT: Dict[str, Any] = {}  # Simulated flow table
P4_IoT_CT: List[str] = ["controller_1", "controller_2"]  # Simulated controller list
Quarantine_Zone = "10.10.10.0/24"



def initialize_flowguard_ap(attack_patterns: List[AttackPattern]):
    global Threat_Database
    Threat_Database = attack_patterns
    logger.info("FlowGuard-AP initialized with threat database and controllers.")



def traffic_analysis_stage(P4_IoT_NT: List[TrafficEntry]) -> List[MaliciousTrafficEntry]:
    malicious_flows = []
    for traffic in P4_IoT_NT:
        for pattern in Threat_Database:
            if all(traffic.headers.get(k) == v for k, v in pattern.rule_conditions.items()):
                logger.warning(f"Match found: {traffic.source_ip} -> {traffic.dst_ip} matches {pattern.pattern_id}")
                malicious = MaliciousTrafficEntry(traffic, pattern)
                malicious_flows.append(malicious)
    return malicious_flows



def mitigation_stage(
    malicious_entries: List[MaliciousTrafficEntry],
    flow_table: Dict[str, Any],
    controllers: List[str],
    quarantine_zone: str
) ->  Tuple[Dict[str, Any], List[str]]:
    alerts = []

    for entry in malicious_entries:
        src_ip = entry.entry.source_ip
        mac = entry.entry.mac

        logger.info(f"Isolating device {mac} and redirecting traffic to quarantine zone {quarantine_zone}")
        flow_table[src_ip] = {"action": "redirect", "destination": quarantine_zone}

        alert_msg = f"ALERT: Malicious flow from {src_ip} detected. Pattern: {entry.pattern.pattern_id}"
        alerts.append(alert_msg)
        logger.info(alert_msg)

        for action in entry.attack_rules:
            logger.info(f"Applying mitigation action: {action} for {src_ip}")
            flow_table[src_ip] = {"action": action, "priority": "high"}

        Mitigation_Table[src_ip] = entry

    return flow_table, alerts



def adaptive_mitigation_stage(
    traffic_list: List[TrafficEntry],
    flow_table: Dict[str, Any],
    controllers: List[str],
    threshold: float
):
    for traffic in traffic_list:
        src_ip = traffic.source_ip
        if src_ip in Mitigation_Table:
            entry = Mitigation_Table[src_ip]
            traffic_rate = traffic.state.get("packet_rate", 0)

            if traffic_rate > threshold * 1.5:
                logger.info(f"Adaptive mitigation: Upgrading action for {src_ip} due to high rate")
                flow_table[src_ip] = {"action": "drop", "priority": "critical"}
            elif traffic_rate < threshold * 0.5:
                logger.info(f"Adaptive mitigation: Downgrading action for {src_ip} due to low rate")
                flow_table[src_ip] = {"action": "monitor", "priority": "low"}



def simulate_traffic(num_entries: int = 50) -> List[TrafficEntry]:
    import random
    entries = []
    for _ in range(num_entries):
        headers = {"protocol": "TCP", "dst_port": 80 if random.random() < 0.5 else 53}
        state = {"packet_rate": random.uniform(10, 150)}
        entry = TrafficEntry(
            source_ip=f"192.168.1.{random.randint(1, 254)}",
            dst_ip=f"10.0.0.{random.randint(1, 254)}",
            mac=f"AA:BB:CC:DD:EE:{random.randint(10, 99)}",
            headers=headers,
            state=state
        )
        entries.append(entry)
    return entries

def main_loop(threshold_value: float = 100.0, runtime: int = 20):
    start = time.time()
    while time.time() - start < runtime:
        traffic = simulate_traffic()

        malicious = traffic_analysis_stage(traffic)

        updated_ft, alerts = mitigation_stage(malicious, P4_IoT_FT, P4_IoT_CT, Quarantine_Zone)

        adaptive_mitigation_stage(traffic, updated_ft, P4_IoT_CT, threshold_value)

        logger.info(f"Flow table updated. Entries: {len(updated_ft)} | Alerts: {len(alerts)}")
        time.sleep(1)



def build_example_attack_patterns() -> List[AttackPattern]:
    return [
        AttackPattern(
            pattern_id="HTTP_FLOOD",
            rule_conditions={"protocol": "TCP", "dst_port": 80},
            mitigation_actions=["rate_limit", "redirect"]
        ),
        AttackPattern(
            pattern_id="DNS_AMP",
            rule_conditions={"protocol": "UDP", "dst_port": 53},
            mitigation_actions=["drop", "isolate"]
        )
    ]



if __name__ == "__main__":
    example_patterns = build_example_attack_patterns()
    initialize_flowguard_ap(example_patterns)
    main_loop(threshold_value=100.0, runtime=20)