import threading
import time
import datetime
import logging
from config import Config

logger = logging.getLogger("ids_system")

# Import Scapy components safely
SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, conf
    SCAPY_AVAILABLE = True
except ImportError:
    logger.error("Scapy is not installed. Please install scapy using requirements.txt")

def get_interfaces_list():
    """
    Retrieves a list of available network interfaces with descriptions and IP addresses.
    Returns: List of dicts, e.g. [{'name': '...', 'description': '...', 'ip': '...'}]
    """
    interfaces = []
    if not SCAPY_AVAILABLE:
        return interfaces

    try:
        # Get active network interfaces from Scapy's interface manager
        for iface_name, iface in conf.ifaces.items():
            # Filter out loopback or inactive if needed, but keeping them allows testing
            ip = iface.ip if hasattr(iface, 'ip') and iface.ip else "N/A"
            mac = iface.mac if hasattr(iface, 'mac') and iface.mac else "N/A"
            description = iface.description if hasattr(iface, 'description') and iface.description else iface.name
            
            interfaces.append({
                "guid": iface.guid if hasattr(iface, 'guid') else iface_name,
                "name": iface.name,
                "description": description,
                "ip": ip,
                "mac": mac
            })
    except Exception as e:
        logger.error(f"Error enumerating interfaces: {e}")
    
    return interfaces

def parse_packet_data(pkt):
    """
    Parses a raw Scapy packet and extracts necessary fields.
    """
    try:
        pkt_len = len(pkt)
        epoch_time = float(pkt.time)
        timestamp = datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        epoch_time = time.time()
        timestamp = datetime.datetime.fromtimestamp(epoch_time).strftime('%Y-%m-%d %H:%M:%S')
        pkt_len = 0

    src_ip = None
    dst_ip = None
    protocol = "Other"
    src_port = None
    dst_port = None
    flags = ""

    # Parse Layer 3 (IP / IPv6 / ARP)
    if SCAPY_AVAILABLE:
        try:
            if pkt.haslayer(IP):
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                proto_num = pkt[IP].proto
                if proto_num == 1:
                    protocol = "ICMP"
                elif proto_num == 6:
                    protocol = "TCP"
                elif proto_num == 17:
                    protocol = "UDP"
            elif pkt.haslayer(IPv6):
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst
                nh = pkt[IPv6].nh
                if nh == 58:
                    protocol = "ICMP"
                elif nh == 6:
                    protocol = "TCP"
                elif nh == 17:
                    protocol = "UDP"
            elif pkt.haslayer(ARP):
                src_ip = pkt[ARP].psrc
                dst_ip = pkt[ARP].pdst
                protocol = "ARP"

            # Parse Layer 4 (TCP / UDP)
            if pkt.haslayer(TCP):
                protocol = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                flags = str(pkt[TCP].flags)
            elif pkt.haslayer(UDP):
                protocol = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)

            # Check for DNS traffic (UDP/TCP Port 53, or DNS Layer)
            if pkt.haslayer(DNS) or src_port == 53 or dst_port == 53:
                protocol = "DNS"

        except Exception as e:
            logger.debug(f"Error parsing layers in packet: {e}")

    # Fallback to standard fields if not resolved
    if not src_ip:
        src_ip = "0.0.0.0"
    if not dst_ip:
        dst_ip = "0.0.0.0"

    return {
        "timestamp": timestamp,
        "epoch_time": epoch_time,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": pkt_len,
        "flags": flags
    }

class PacketSnifferEngine:
    def __init__(self, interface_name, packet_handler):
        """
        Initializes the sniffer engine.
        interface_name: internal name or guid of the network interface.
        packet_handler: callback function receiving a parsed packet dictionary.
        """
        self.interface = interface_name
        self.packet_handler = packet_handler
        self.stop_event = threading.Event()
        self.sniffer_thread = None

    def start(self):
        """Starts packet sniffing in a background thread."""
        if not SCAPY_AVAILABLE:
            logger.error("Sniffer cannot start because Scapy is unavailable.")
            return

        self.stop_event.clear()
        self.sniffer_thread = threading.Thread(target=self._run_sniff, name="SnifferEngine")
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        logger.info(f"Sniffer thread started on interface '{self.interface}'")

    def stop(self):
        """Stops the sniffing thread."""
        self.stop_event.set()
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=2.0)
            logger.info("Sniffer thread stopped.")

    def _should_stop(self, pkt):
        """Callback to determine if Scapy sniff should stop."""
        return self.stop_event.is_set()

    def _run_sniff(self):
        """Internal worker function running the Scapy sniff loop."""
        try:
            # Check if sniffing on a specific interface or all interfaces
            iface_arg = self.interface if self.interface and self.interface != "all" else None
            
            # Start scapy sniffer
            sniff(
                iface=iface_arg,
                prn=self._process_scapy_packet,
                stop_filter=self._should_stop,
                store=0  # Do not store packets in memory (prevents memory leaks)
            )
        except Exception as e:
            logger.error(f"Critical error in packet sniffing loop: {e}")

    def _process_scapy_packet(self, pkt):
        """Converts scapy packet to dict and fires user-defined callback."""
        if self.stop_event.is_set():
            return
        
        parsed = parse_packet_data(pkt)
        self.packet_handler(parsed)
