import time
from collections import defaultdict
import logging
from config import Config

logger = logging.getLogger("ids_system")

class DetectionEngine:
    def __init__(self, alert_callback):
        """
        Initializes the detection engine.
        alert_callback: function that accepts an alert dictionary to process triggered alerts.
        """
        self.alert_callback = alert_callback

        # Memory for sliding window checks: key -> list of timestamps
        self.port_scan_history = defaultdict(list)     # src_ip -> list of (timestamp, dst_port)
        self.syn_flood_history = defaultdict(list)     # src_ip -> list of timestamp
        self.icmp_flood_history = defaultdict(list)    # src_ip -> list of timestamp
        self.dns_abuse_history = defaultdict(list)     # src_ip -> list of timestamp
        self.brute_force_history = defaultdict(list)    # (src_ip, dst_ip, dst_port) -> list of timestamp
        self.packet_rate_history = defaultdict(list)    # src_ip -> list of timestamp

        # Cooldown map to prevent spamming duplicate alerts: (src_ip, alert_type) -> last_triggered_time
        self.alert_cooldown = {}
        self.cooldown_seconds = 10.0

    def _should_trigger_alert(self, src_ip, alert_type, current_time):
        """Helper to enforce cooldowns on duplicate alerts to avoid flooding the system."""
        key = (src_ip, alert_type)
        if key in self.alert_cooldown:
            if current_time - self.alert_cooldown[key] < self.cooldown_seconds:
                return False
        self.alert_cooldown[key] = current_time
        return True

    def process_packet(self, packet):
        """
        Processes a single parsed packet dictionary and runs detection rules.
        packet: {
            "timestamp": "ISO 8601 string",
            "epoch_time": float,
            "src_ip": "IP",
            "dst_ip": "IP",
            "protocol": "TCP/UDP/ICMP/DNS/ARP",
            "src_port": int or None,
            "dst_port": int or None,
            "length": int,
            "flags": str (for TCP, e.g., "S" for SYN)
        }
        """
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        protocol = packet.get("protocol")
        src_port = packet.get("src_port")
        dst_port = packet.get("dst_port")
        length = packet.get("length", 0)
        flags = packet.get("flags", "")
        current_time = packet.get("epoch_time", time.time())

        # Skip packets without a source IP (like some raw Layer 2 packets)
        if not src_ip:
            return

        # 1. Suspicious Traffic Rate Detection (High Packet Rate)
        self._check_packet_rate(src_ip, current_time)

        # 2. Protocol Specific Rules
        if protocol == "TCP":
            # SYN Flood Detection
            if "S" in flags and "A" not in flags:  # SYN flag set, ACK flag not set (SYN Request)
                self._check_syn_flood(src_ip, current_time)
            
            # Brute Force Connection Detection (Repeated connection attempts to same port)
            if dst_port is not None:
                self._check_brute_force(src_ip, dst_ip, dst_port, current_time)
                self._check_port_scan(src_ip, dst_port, current_time)

        elif protocol == "UDP":
            if dst_port is not None:
                self._check_port_scan(src_ip, dst_port, current_time)

        elif protocol == "ICMP":
            self._check_icmp_flood(src_ip, current_time)

        elif protocol == "DNS":
            self._check_dns_abuse(src_ip, current_time)

    def _check_packet_rate(self, src_ip, current_time):
        """Detect abnormal packet rates from a single source IP."""
        history = self.packet_rate_history[src_ip]
        # Clean expired timestamps
        cutoff = current_time - Config.SUSPICIOUS_RATE_WINDOW
        while history and history[0] < cutoff:
            history.pop(0)

        history.append(current_time)

        if len(history) > Config.SUSPICIOUS_RATE_THRESHOLD:
            if self._should_trigger_alert(src_ip, "Suspicious Traffic", current_time):
                rate = len(history) / Config.SUSPICIOUS_RATE_WINDOW
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "Suspicious Traffic",
                    "source_ip": src_ip,
                    "severity": "Medium",
                    "description": f"Abnormal packet rate: {rate:.1f} packets/sec (Limit: {Config.SUSPICIOUS_RATE_THRESHOLD})"
                }
                self.alert_callback(alert)

    def _check_port_scan(self, src_ip, dst_port, current_time):
        """Detect when one source IP accesses more than X unique ports within Y seconds."""
        history = self.port_scan_history[src_ip]
        # Clean expired
        cutoff = current_time - Config.PORT_SCAN_WINDOW
        while history and history[0][0] < cutoff:
            history.pop(0)

        # Append new port request
        history.append((current_time, dst_port))

        # Count unique ports
        unique_ports = {port for _, port in history}

        if len(unique_ports) > Config.PORT_SCAN_THRESHOLD:
            if self._should_trigger_alert(src_ip, "Port Scan", current_time):
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "Port Scan",
                    "source_ip": src_ip,
                    "severity": "High",
                    "description": f"Port scan detected. Source IP accessed {len(unique_ports)} unique ports in {Config.PORT_SCAN_WINDOW} seconds."
                }
                self.alert_callback(alert)

    def _check_syn_flood(self, src_ip, current_time):
        """Detect excessive SYN packets from one source IP."""
        history = self.syn_flood_history[src_ip]
        cutoff = current_time - Config.SYN_FLOOD_WINDOW
        while history and history[0] < cutoff:
            history.pop(0)

        history.append(current_time)

        if len(history) > Config.SYN_FLOOD_THRESHOLD:
            if self._should_trigger_alert(src_ip, "SYN Flood", current_time):
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "SYN Flood",
                    "source_ip": src_ip,
                    "severity": "High",
                    "description": f"SYN flood attempt. Source IP generated {len(history)} SYN requests in {Config.SYN_FLOOD_WINDOW} seconds."
                }
                self.alert_callback(alert)

    def _check_icmp_flood(self, src_ip, current_time):
        """Detect excessive ICMP packets."""
        history = self.icmp_flood_history[src_ip]
        cutoff = current_time - Config.ICMP_FLOOD_WINDOW
        while history and history[0] < cutoff:
            history.pop(0)

        history.append(current_time)

        if len(history) > Config.ICMP_FLOOD_THRESHOLD:
            if self._should_trigger_alert(src_ip, "ICMP Flood", current_time):
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "ICMP Flood",
                    "source_ip": src_ip,
                    "severity": "Medium",
                    "description": f"ICMP flood attempt. Source IP generated {len(history)} ICMP requests in {Config.ICMP_FLOOD_WINDOW} seconds."
                }
                self.alert_callback(alert)

    def _check_dns_abuse(self, src_ip, current_time):
        """Detect excessive DNS queries."""
        history = self.dns_abuse_history[src_ip]
        cutoff = current_time - Config.DNS_ABUSE_WINDOW
        while history and history[0] < cutoff:
            history.pop(0)

        history.append(current_time)

        if len(history) > Config.DNS_ABUSE_THRESHOLD:
            if self._should_trigger_alert(src_ip, "DNS Abuse", current_time):
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "DNS Abuse",
                    "source_ip": src_ip,
                    "severity": "Medium",
                    "description": f"DNS query flood or abuse. Source IP generated {len(history)} DNS queries in {Config.DNS_ABUSE_WINDOW} seconds."
                }
                self.alert_callback(alert)

    def _check_brute_force(self, src_ip, dst_ip, dst_port, current_time):
        """Detect repeated connection attempts against the same destination port."""
        key = (src_ip, dst_ip, dst_port)
        history = self.brute_force_history[key]
        cutoff = current_time - Config.BRUTE_FORCE_WINDOW
        while history and history[0] < cutoff:
            history.pop(0)

        history.append(current_time)

        if len(history) > Config.BRUTE_FORCE_THRESHOLD:
            if self._should_trigger_alert(src_ip, "Brute Force", current_time):
                # Standard administrative ports warning
                service_map = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 3389: "RDP", 445: "SMB"}
                service = service_map.get(dst_port, f"Port {dst_port}")
                alert = {
                    "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
                    "alert_type": "Brute Force",
                    "source_ip": src_ip,
                    "severity": "High",
                    "description": f"Repeated connection attempts ({len(history)} counts) to {dst_ip} on service {service} in {Config.BRUTE_FORCE_WINDOW} seconds."
                }
                self.alert_callback(alert)
