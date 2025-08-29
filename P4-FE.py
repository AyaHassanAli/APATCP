"""
P4-Based Stateful Feature Extraction Engine (P4-FE) Implementation
A Python implementation simulating the P4-based feature extraction logic for real-time DDoS detection.
"""

import time
import random
import logging
from typing import Dict, List, Tuple
from collections import deque, defaultdict


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("P4-FE")



TCP_FLAGS_SET = {"SYN", "ACK", "RST", "PSH", "FIN"}
WINDOW_SIZE = 10  
SYN_THRESHOLD = 20



SYN_Counter: Dict[str, int] = defaultdict(int)
ACK_Counter: Dict[str, int] = defaultdict(int)
Pkt_Timestamp: Dict[str, float] = defaultdict(lambda: time.time())
InterArrival: Dict[str, float] = defaultdict(float)
Pkt_Size_Buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
Flag_Mix_Counter: Dict[str, int] = defaultdict(int)



class Packet:
    def __init__(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                 protocol: str, size: int, tcp_flags: List[str]):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.size = size
        self.tcp_flags = tcp_flags
        self.timestamp = time.time()

    def flow_id(self) -> str:
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}-{self.protocol}"



def initialize_p4_fe():
    """Initialize feature extraction data structures."""
    logger.info("P4-FE Initialized. Ready to monitor packet stream.")

def update_rolling_avg(current_avg: float, new_value: float, alpha: float = 0.8) -> float:
    """Exponentially weighted moving average."""
    return alpha * current_avg + (1 - alpha) * new_value

def get_flag_pattern(flags: List[str]) -> str:
    """Generate a pattern string from TCP flags."""
    return "-".join(sorted(flags))

def session_exists(flow_id: str) -> bool:
    """Stub for checking if a TCP session exists (simulated)."""
    return False

def trigger_alert(flow_id: str, reason: str):
    logger.warning(f"ALERT: Flow {flow_id} triggered {reason} detection.")

def execute_feature_extraction_stage(packet_stream: List[Packet]):
    """Main feature extraction stage for each packet in stream."""
    for packet in packet_stream:
        flow_id = packet.flow_id()
        flags = packet.tcp_flags

        if "SYN" in flags:
            SYN_Counter[flow_id] += 1
            logger.debug(f"SYN Count[{flow_id}] = {SYN_Counter[flow_id]}")
            if SYN_Counter[flow_id] > SYN_THRESHOLD:
                trigger_alert(flow_id, "SYN_Flood")

        if "ACK" in flags and not session_exists(flow_id):
            ACK_Counter[flow_id] += 1

        current_time = packet.timestamp
        inter_time = current_time - Pkt_Timestamp[flow_id]
        InterArrival[flow_id] = update_rolling_avg(InterArrival[flow_id], inter_time)
        Pkt_Timestamp[flow_id] = current_time

        Pkt_Size_Buffer[flow_id].append(packet.size)

        pattern = get_flag_pattern(flags)
        Flag_Mix_Counter[pattern] += 1

        logger.debug(f"Updated metrics for {flow_id}: InterArrival={InterArrival[flow_id]:.3f}, Pattern={pattern}")


def simulate_packet_stream(num_packets: int = 100) -> List[Packet]:
    stream = []
    for _ in range(num_packets):
        packet = Packet(
            src_ip=f"192.168.1.{random.randint(1, 254)}",
            dst_ip=f"10.0.0.{random.randint(1, 254)}",
            src_port=random.randint(1000, 5000),
            dst_port=80,
            protocol="TCP",
            size=random.randint(40, 1500),
            tcp_flags=random.sample(list(TCP_FLAGS_SET), k=random.randint(1, 2))  # FIXED LINE
        )
        stream.append(packet)
    return stream


def run_p4_feature_extraction_engine(duration: int = 10):
    initialize_p4_fe()
    start_time = time.time()
    while time.time() - start_time < duration:
        packets = simulate_packet_stream()
        execute_feature_extraction_stage(packets)
        update_data_plane_registers()
        time.sleep(1)

def update_data_plane_registers():
    """Simulate register updates to P4 switch."""
    logger.info("Registers updated with latest metrics...")



if __name__ == "__main__":
    run_p4_feature_extraction_engine(duration=20)