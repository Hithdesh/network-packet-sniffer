import os

class Config:
    # Base Directory
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    # Database Settings
    DB_DIR = os.path.join(BASE_DIR, "database")
    DB_PATH = os.path.join(DB_DIR, "ids.db")

    # Logging Settings
    LOG_DIR = os.path.join(BASE_DIR, "logs")
    PACKETS_LOG = os.path.join(LOG_DIR, "packets.log")
    ALERTS_LOG = os.path.join(LOG_DIR, "alerts.log")
    SYSTEM_LOG = os.path.join(LOG_DIR, "system.log")

    # Intrusion Detection System Thresholds
    
    # Port Scan: Accessing > X unique ports within Y seconds from a single source IP
    PORT_SCAN_THRESHOLD = 15
    PORT_SCAN_WINDOW = 10

    # SYN Flood: > X SYN packets within Y seconds from a single source IP
    SYN_FLOOD_THRESHOLD = 30
    SYN_FLOOD_WINDOW = 5

    # ICMP Flood: > X ICMP echo-request packets within Y seconds from a single source IP
    ICMP_FLOOD_THRESHOLD = 20
    ICMP_FLOOD_WINDOW = 5

    # DNS Abuse: > X DNS queries within Y seconds from a single source IP
    DNS_ABUSE_THRESHOLD = 20
    DNS_ABUSE_WINDOW = 5

    # Brute Force: > X connection attempts to the same destination port within Y seconds from a single source IP
    BRUTE_FORCE_THRESHOLD = 10
    BRUTE_FORCE_WINDOW = 10

    # Suspicious Traffic: Overall packets per second from a single source IP exceeds X
    SUSPICIOUS_RATE_THRESHOLD = 100
    SUSPICIOUS_RATE_WINDOW = 1

    # Flask Settings
    FLASK_HOST = "127.0.0.1"
    FLASK_PORT = 5000
