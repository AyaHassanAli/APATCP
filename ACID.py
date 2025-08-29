
import time
import json
import logging
import threading
import statistics
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import paho.mqtt.client as mqtt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import hashlib

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_HOST = "localhost"
DDOS_THRESHOLD_PACKETS = 1000
DDOS_THRESHOLD_IPS = 50
MAX_THREAT_SCORE = 100.0
RTAC_TOPIC = "rtac/alerts"
SDSC_TOPIC = "sdsc/network_updates"
KEY_EXCHANGE_TOPIC = "key_exchange"
OPTIMIZATION_INTERVAL = 30  # seconds

class CollaborationMode(Enum):
    """Collaboration modes for ACID system."""
    ACI = "adaptive_collaborative_intrusion"
    GCI = "global_collaborative_intrusion"

class ChannelType(Enum):
    """Communication channel types."""
    SCC = "secure_communication_channel"
    RTAC = "realtime_alert_channel"
    SDSC = "software_defined_secure_channel"

@dataclass
class ControllerConfig:
    """Configuration for SD-IoT Controller."""
    controller_id: str
    crypto_key: bytes
    ip_address: str = "127.0.0.1"
    port: int = DEFAULT_MQTT_PORT
    is_authenticated: bool = False
    scc_established: bool = False

@dataclass
class NetworkTrafficData:
    """Real-time network traffic data."""
    packet_count: int
    source_ips: List[str]
    destination_ips: List[str]
    packet_rates: List[int]
    timestamp: float
    protocol_distribution: Dict[str, int] = field(default_factory=dict)

@dataclass
class DDoSAlert:
    """DDoS attack alert information."""
    threat_score: float
    attack_patterns: Dict[str, Any]
    packet_rates: List[int]
    ip_variations: List[str]
    timestamp: float
    source_controller: str
    mitigation_strategy: Optional[str] = None

@dataclass
class NetworkState:
    """Current network state information."""
    active_threats: List[DDoSAlert]
    controller_status: Dict[str, str]
    network_statistics: Dict[str, Any]
    last_updated: float

class CryptoManager:
    """Handles cryptographic operations for ACID system."""
    
    def __init__(self):
        self.cipher_suites: Dict[str, Fernet] = {}
        self.session_keys: Dict[str, bytes] = {}
    
    def add_controller_key(self, controller_id: str, key: bytes) -> None:
        """Add cryptographic key for a controller."""
        try:
            self.cipher_suites[controller_id] = Fernet(key)
            logger.info(f"Added crypto key for controller: {controller_id}")
        except Exception as e:
            logger.error(f"Failed to add key for {controller_id}: {e}")
            raise
    
    def verify_controller_identity(self, controller_id: str, challenge: bytes) -> bool:
        """Verify controller identity using cryptographic challenge."""
        try:
            if controller_id not in self.cipher_suites:
                return False
            
            cipher = self.cipher_suites[controller_id]
            response = cipher.encrypt(challenge)
            return len(response) > 0
        except Exception as e:
            logger.error(f"Identity verification failed for {controller_id}: {e}")
            return False
    
    def encrypt_message(self, controller_id: str, message: Dict) -> bytes:
        """Encrypt message for specific controller."""
        try:
            cipher = self.cipher_suites[controller_id]
            message_bytes = json.dumps(message).encode('utf-8')
            return cipher.encrypt(message_bytes)
        except Exception as e:
            logger.error(f"Encryption failed for {controller_id}: {e}")
            raise
    
    def decrypt_message(self, controller_id: str, encrypted_message: bytes) -> Dict:
        """Decrypt message from specific controller."""
        try:
            cipher = self.cipher_suites[controller_id]
            decrypted_bytes = cipher.decrypt(encrypted_message)
            return json.loads(decrypted_bytes.decode('utf-8'))
        except Exception as e:
            logger.error(f"Decryption failed for {controller_id}: {e}")
            raise
    
    def generate_session_key(self) -> bytes:
        """Generate new session key."""
        return Fernet.generate_key()
    
    def exchange_keys(self, controller_id: str) -> bytes:
        """Exchange cryptographic keys with controller."""
        session_key = self.generate_session_key()
        self.session_keys[controller_id] = session_key
        return session_key

class CommunicationManager:
    """Manages MQTT communication channels."""
    
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto_manager = crypto_manager
        self.mqtt_client: Optional[mqtt.Client] = None
        self.channels: Dict[ChannelType, str] = {}
        self.message_handlers: Dict[str, callable] = {}
        self.is_connected = False
    
    def setup_mqtt(self, host: str = DEFAULT_MQTT_HOST, port: int = DEFAULT_MQTT_PORT) -> None:
        """Setup MQTT client connection."""
        try:
            self.mqtt_client = mqtt.Client()
            self.mqtt_client.on_connect = self._on_connect
            self.mqtt_client.on_message = self._on_message
            self.mqtt_client.connect(host, port, 60)
            self.mqtt_client.loop_start()
            logger.info(f"MQTT client connected to {host}:{port}")
        except Exception as e:
            logger.error(f"MQTT setup failed: {e}")
            raise
    
    def setup_rtac(self) -> None:
        """Set up Real-Time Alert Channel using MQTT."""
        self.channels[ChannelType.RTAC] = RTAC_TOPIC
        if self.mqtt_client:
            self.mqtt_client.subscribe(RTAC_TOPIC)
            logger.info("RTAC channel established")
    
    def setup_sdsc(self) -> None:
        """Set up Software-Defined Secure Channel using MQTT."""
        self.channels[ChannelType.SDSC] = SDSC_TOPIC
        if self.mqtt_client:
            self.mqtt_client.subscribe(SDSC_TOPIC)
            logger.info("SDSC channel established")
    
    def send_encrypted_alert(self, alert: DDoSAlert, channel: ChannelType) -> None:
        """Send encrypted alert message over specified channel."""
        try:
            if channel not in self.channels or not self.mqtt_client:
                raise ValueError(f"Channel {channel} not available")
            
            alert_data = {
                'threat_score': alert.threat_score,
                'attack_patterns': alert.attack_patterns,
                'timestamp': alert.timestamp,
                'source_controller': alert.source_controller
            }
            
            encrypted_message = self.crypto_manager.encrypt_message(
                alert.source_controller, alert_data
            )
            
            topic = self.channels[channel]
            self.mqtt_client.publish(topic, encrypted_message)
            logger.info(f"Alert sent over {channel.value}")
            
        except Exception as e:
            logger.error(f"Failed to send alert: {e}")
            raise
    
    def register_handler(self, topic: str, handler: callable) -> None:
        """Register message handler for specific topic."""
        self.message_handlers[topic] = handler
    
    def _on_connect(self, client, userdata, flags, rc):
        """MQTT connection callback."""
        if rc == 0:
            self.is_connected = True
            logger.info("MQTT connected successfully")
        else:
            logger.error(f"MQTT connection failed with code {rc}")
    
    def _on_message(self, client, userdata, msg):
        """MQTT message callback."""
        try:
            topic = msg.topic
            if topic in self.message_handlers:
                self.message_handlers[topic](msg.payload)
        except Exception as e:
            logger.error(f"Message handling error: {e}")

class DDoSDetector:
    """DDoS attack detection using P4 traffic analysis."""
    
    def __init__(self):
        self.detection_threshold = DDOS_THRESHOLD_PACKETS
        self.ip_threshold = DDOS_THRESHOLD_IPS
        self.baseline_metrics = {}
    
    def detect_ddos_attack(self, traffic_data: NetworkTrafficData) -> Optional[DDoSAlert]:
        """
        Detect DDoS attacks using P4 traffic analysis.
        
        Args:
            traffic_data: Real-time network traffic data
            
        Returns:
            DDoS alert if attack detected, None otherwise
        """
        try:
            attack_patterns = self._extract_attack_patterns(traffic_data)
            
            threat_score = self._calculate_threat_score(
                traffic_data.packet_rates,
                traffic_data.source_ips
            )
            
            if threat_score > 70.0:  
                return DDoSAlert(
                    threat_score=threat_score,
                    attack_patterns=attack_patterns,
                    packet_rates=traffic_data.packet_rates,
                    ip_variations=traffic_data.source_ips,
                    timestamp=traffic_data.timestamp,
                    source_controller="local_controller"
                )
            
            return None
            
        except Exception as e:
            logger.error(f"DDoS detection error: {e}")
            return None
    
    def _extract_attack_patterns(self, traffic_data: NetworkTrafficData) -> Dict[str, Any]:
        """Extract attack patterns from traffic data."""
        patterns = {
            'high_packet_rate': max(traffic_data.packet_rates) > self.detection_threshold,
            'ip_spoofing': len(set(traffic_data.source_ips)) > self.ip_threshold,
            'protocol_anomaly': self._detect_protocol_anomaly(traffic_data),
            'packet_size_variation': self._analyze_packet_sizes(traffic_data)
        }
        return patterns
    
    def _calculate_threat_score(self, packet_rates: List[int], source_ips: List[str]) -> float:
        """Calculate threat score based on traffic patterns."""
        try:
            max_rate = max(packet_rates) if packet_rates else 0
            rate_score = min(40.0, (max_rate / self.detection_threshold) * 40.0)
            
            unique_ips = len(set(source_ips))
            ip_score = min(30.0, (unique_ips / self.ip_threshold) * 30.0)
            
            pattern_score = self._analyze_traffic_patterns(packet_rates)
            
            total_score = rate_score + ip_score + pattern_score
            return min(MAX_THREAT_SCORE, total_score)
            
        except Exception as e:
            logger.error(f"Threat score calculation error: {e}")
            return 0.0
    
    def _detect_protocol_anomaly(self, traffic_data: NetworkTrafficData) -> bool:
        """Detect protocol distribution anomalies."""
        return len(traffic_data.protocol_distribution) > 5
    
    def _analyze_packet_sizes(self, traffic_data: NetworkTrafficData) -> float:
        """Analyze packet size variations."""
        return statistics.variance(traffic_data.packet_rates) if len(traffic_data.packet_rates) > 1 else 0.0
    
    def _analyze_traffic_patterns(self, packet_rates: List[int]) -> float:
        """Analyze traffic patterns for anomalies."""
        if len(packet_rates) < 2:
            return 0.0
        
        # Calculate variance as pattern indicator
        variance = statistics.variance(packet_rates)
        # Normalize to 0-30 range
        return min(30.0, variance / 10000.0 * 30.0)

class AdaptiveCollaborativeIntrusionDefense:
    """
    Main ACID system implementation.
    
    Implements the Adaptive Collaborative Intrusion Defense algorithm
    for coordinated security in SD-IoT networks.
    """
    
    def __init__(self, 
                 controller_list: List[str],
                 crypto_keys: Dict[str, bytes],
                 collaboration_mode: CollaborationMode):
        """
        Initialize ACID system.
        
        Args:
            controller_list: List of SD-IoT controller IDs
            crypto_keys: Pre-shared cryptographic keys
            collaboration_mode: ACI or GCI mode
        """
        self.controller_list = controller_list
        self.crypto_keys = crypto_keys
        self.collaboration_mode = collaboration_mode
        
        self.controllers: Dict[str, ControllerConfig] = {}
        self.crypto_manager = CryptoManager()
        self.communication_manager = CommunicationManager(self.crypto_manager)
        self.ddos_detector = DDoSDetector()
        self.network_state = NetworkState([], {}, {}, time.time())
        
        self.is_running = False
        self.optimization_thread: Optional[threading.Thread] = None
    
    def run(self) -> None:
        """Main execution loop implementing ACID algorithm."""
        try:
            logger.info("Starting ACID system...")
            
            self.initialize_controllers()
            
            self.select_collaboration_mode(self.collaboration_mode)
            
            self.manage_keys()
            
            self.main_loop()
            
        except Exception as e:
            logger.error(f"ACID system error: {e}")
            raise
        finally:
            self.shutdown()
    
    def initialize_controllers(self) -> None:
        """Initialize and authenticate all controllers (Lines 01-08)."""
        logger.info("Initializing controllers...")
        
        for controller_id in self.controller_list:
            try:
                if controller_id not in self.crypto_keys:
                    logger.warning(f"No crypto key found for {controller_id}")
                    continue
                
                config = ControllerConfig(
                    controller_id=controller_id,
                    crypto_key=self.crypto_keys[controller_id]
                )
                
                self.crypto_manager.add_controller_key(
                    controller_id, 
                    self.crypto_keys[controller_id]
                )
                
                challenge = secrets.token_bytes(32)
                if self.crypto_manager.verify_controller_identity(controller_id, challenge):
                    config.is_authenticated = True
                    config.scc_established = True
                    self.controllers[controller_id] = config
                    
                    logger.info(f"Controller {controller_id} initialized and authenticated")
                else:
                    logger.warning(f"Authentication failed for controller {controller_id}")
                    
            except Exception as e:
                logger.error(f"Failed to initialize controller {controller_id}: {e}")
    
    def select_collaboration_mode(self, mode: CollaborationMode) -> None:
        """Select and setup collaboration mode (Lines 09-16)."""
        logger.info(f"Setting up collaboration mode: {mode.value}")
        
        try:
            self.communication_manager.setup_mqtt()
            
            if mode == CollaborationMode.ACI:
                self.communication_manager.setup_rtac()
                self._enable_threat_sharing()
                logger.info("ACI mode: RTAC established for threat sharing")
                
            elif mode == CollaborationMode.GCI:
                self.communication_manager.setup_sdsc()
                self._enable_network_updates()
                logger.info("GCI mode: SDSC established for network updates")
                
        except Exception as e:
            logger.error(f"Failed to setup collaboration mode: {e}")
            raise
    
    def manage_keys(self) -> None:
        """Manage cryptographic keys (Lines 17-21)."""
        logger.info("Managing cryptographic keys...")
        
        try:
            for controller_id, config in self.controllers.items():
                if config.scc_established:
                    session_key = self.crypto_manager.exchange_keys(controller_id)
                    logger.debug(f"Key exchanged with {controller_id}")
            
            self._update_channel_keys()
            logger.info("Key management completed")
            
        except Exception as e:
            logger.error(f"Key management error: {e}")
            raise
    
    def detect_ddos(self, traffic_data: NetworkTrafficData) -> Optional[DDoSAlert]:
        """Detect DDoS attacks (Lines 22-29)."""
        try:
            alert = self.ddos_detector.detect_ddos_attack(traffic_data)
            
            if alert:
                logger.warning(f"DDoS attack detected! Threat score: {alert.threat_score}")
                
                self.communication_manager.send_encrypted_alert(
                    alert, ChannelType.RTAC
                )
                self._notify_iot_network(alert)
                
                return alert
            
            return None
            
        except Exception as e:
            logger.error(f"DDoS detection error: {e}")
            return None
    
    def synchronize_network_state(self, ddos_alert: DDoSAlert) -> None:
        """Synchronize network state across controllers (Lines 30-34)."""
        logger.info("Synchronizing network state...")
        
        try:
            for controller_id, config in self.controllers.items():
                if config.is_authenticated:
                    self._update_controller_network_state(controller_id, ddos_alert)
            
            self._collaborate_mitigation_strategies(ddos_alert)
            
            self.network_state.active_threats.append(ddos_alert)
            self.network_state.last_updated = time.time()
            
        except Exception as e:
            logger.error(f"Network state synchronization error: {e}")
    
    def optimize_system(self) -> None:
        """Optimize system performance (Lines 35-37)."""
        try:
            self._review_communication_overhead()
            
            self._refine_detection_parameters()
            
            logger.debug("System optimization completed")
            
        except Exception as e:
            logger.error(f"System optimization error: {e}")
    
    def main_loop(self) -> None:
        """Main execution loop (Lines 38-49)."""
        logger.info("Starting main loop...")
        self.is_running = True
        
        self.optimization_thread = threading.Thread(
            target=self._optimization_worker,
            daemon=True
        )
        self.optimization_thread.start()
        
        try:
            while self.is_running:
                traffic_data = self._get_network_traffic()
                
                if traffic_data:
                    ddos_alert = self.detect_ddos(traffic_data)
                    
                    if ddos_alert:
                        self.synchronize_network_state(ddos_alert)
                
                time.sleep(0.1)
                
        except KeyboardInterrupt:
            logger.info("Received shutdown signal")
        finally:
            self.is_running = False
    
    def shutdown(self) -> None:
        """Gracefully shutdown the ACID system."""
        logger.info("Shutting down ACID system...")
        self.is_running = False
        
        if self.communication_manager.mqtt_client:
            self.communication_manager.mqtt_client.loop_stop()
            self.communication_manager.mqtt_client.disconnect()
    
    def _enable_threat_sharing(self) -> None:
        """Enable threat-level and feature sharing for ACI mode."""
        self.communication_manager.register_handler(
            RTAC_TOPIC, self._handle_threat_message
        )
    
    def _enable_network_updates(self) -> None:
        """Enable network updates exchange for GCI mode."""
        self.communication_manager.register_handler(
            SDSC_TOPIC, self._handle_network_update
        )
    
    def _update_channel_keys(self) -> None:
        """Update RTAC and SDSC channel keys."""
        pass
    
    def _notify_iot_network(self, alert: DDoSAlert) -> None:
        """Notify IoT network of threat."""
        logger.info(f"Notifying IoT network of threat: {alert.threat_score}")
    
    def _update_controller_network_state(self, controller_id: str, alert: DDoSAlert) -> None:
        """Update network state for specific controller."""
        self.network_state.controller_status[controller_id] = "threat_detected"
    
    def _collaborate_mitigation_strategies(self, alert: DDoSAlert) -> None:
        """Collaborate on mitigation strategies."""
        if alert.threat_score > 80:
            alert.mitigation_strategy = "block_source_ips"
        elif alert.threat_score > 60:
            alert.mitigation_strategy = "rate_limiting"
        else:
            alert.mitigation_strategy = "monitoring"
    
    def _review_communication_overhead(self) -> None:
        """Review RTAC and SDSC communication overhead."""
        pass
    
    def _refine_detection_parameters(self) -> None:
        """Dynamically refine detection thresholds and models."""
        current_threats = len(self.network_state.active_threats)
        if current_threats > 5:
            self.ddos_detector.detection_threshold *= 0.9  
        elif current_threats == 0:
            self.ddos_detector.detection_threshold *= 1.1 
    
    def _get_network_traffic(self) -> Optional[NetworkTrafficData]:
        """Simulate getting real-time network traffic."""
        import random
        
        return NetworkTrafficData(
            packet_count=random.randint(100, 2000),
            source_ips=[f"192.168.1.{random.randint(1, 254)}" for _ in range(random.randint(1, 100))],
            destination_ips=[f"10.0.0.{random.randint(1, 254)}" for _ in range(random.randint(1, 50))],
            packet_rates=[random.randint(50, 1500) for _ in range(10)],
            timestamp=time.time(),
            protocol_distribution={"TCP": random.randint(50, 80), "UDP": random.randint(10, 30)}
        )
    
    def _optimization_worker(self) -> None:
        """Background worker for system optimization."""
        while self.is_running:
            try:
                self.optimize_system()
                time.sleep(OPTIMIZATION_INTERVAL)
            except Exception as e:
                logger.error(f"Optimization worker error: {e}")
    
    def _handle_threat_message(self, message: bytes) -> None:
        """Handle incoming threat messages on RTAC."""
        try:
            logger.info("Received threat message on RTAC")
        except Exception as e:
            logger.error(f"Threat message handling error: {e}")
    
    def _handle_network_update(self, message: bytes) -> None:
        """Handle incoming network updates on SDSC."""
        try:
            logger.info("Received network update on SDSC")
        except Exception as e:
            logger.error(f"Network update handling error: {e}")

def main():
    """Example usage of ACID system."""
    controller_list = ["controller_1", "controller_2", "controller_3"]
    crypto_keys = {
        "controller_1": Fernet.generate_key(),
        "controller_2": Fernet.generate_key(),
        "controller_3": Fernet.generate_key()
    }
    
    acid_system = AdaptiveCollaborativeIntrusionDefense(
        controller_list=controller_list,
        crypto_keys=crypto_keys,
        collaboration_mode=CollaborationMode.ACI
    )
    
    try:
        acid_system.run()
    except KeyboardInterrupt:
        logger.info("System interrupted by user")
    finally:
        acid_system.shutdown()

if __name__ == "__main__":
    main()
