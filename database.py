import sqlite3
import os
import logging
from config import Config

logger = logging.getLogger("ids_system")

def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(Config.DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Creates database folder and initializes the database tables if they do not exist."""
    # Ensure database directory exists
    if not os.path.exists(Config.DB_DIR):
        os.makedirs(Config.DB_DIR)
        logger.info(f"Created database directory: {Config.DB_DIR}")

    # Ensure logs directory exists
    if not os.path.exists(Config.LOG_DIR):
        os.makedirs(Config.LOG_DIR)
        logger.info(f"Created logs directory: {Config.LOG_DIR}")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Create packets table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        src_ip TEXT,
        dst_ip TEXT,
        protocol TEXT,
        src_port INTEGER,
        dst_port INTEGER,
        length INTEGER
    )
    """)

    # Create alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        alert_type TEXT NOT NULL,
        source_ip TEXT,
        severity TEXT NOT NULL,
        description TEXT
    )
    """)

    conn.commit()
    conn.close()
    logger.info("Database initialized successfully.")

def insert_packet(conn, p):
    """Inserts a packet record into the database. Assumes conn is an active SQLite connection."""
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO packets (timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        p.get("timestamp"),
        p.get("src_ip"),
        p.get("dst_ip"),
        p.get("protocol"),
        p.get("src_port"),
        p.get("dst_port"),
        p.get("length")
    ))
    conn.commit()
    return cursor.lastrowid

def insert_alert(conn, a):
    """Inserts an alert record into the database. Assumes conn is an active SQLite connection."""
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO alerts (timestamp, alert_type, source_ip, severity, description)
    VALUES (?, ?, ?, ?, ?)
    """, (
        a.get("timestamp"),
        a.get("alert_type"),
        a.get("source_ip"),
        a.get("severity"),
        a.get("description")
    ))
    conn.commit()
    return cursor.lastrowid

def get_recent_packets(limit=50):
    """Fetches recent packets from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM packets ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_recent_alerts(limit=50):
    """Fetches recent alerts from the database."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_stats():
    """Calculates statistics from the database tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM packets")
    total_packets = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM alerts")
    total_alerts = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM packets WHERE protocol = 'TCP'")
    tcp_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM packets WHERE protocol = 'UDP'")
    udp_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM packets WHERE protocol = 'ICMP'")
    icmp_count = cursor.fetchone()[0]

    conn.close()

    return {
        "total_packets": total_packets,
        "total_alerts": total_alerts,
        "tcp_count": tcp_count,
        "udp_count": udp_count,
        "icmp_count": icmp_count
    }
