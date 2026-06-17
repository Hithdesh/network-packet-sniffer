import os
import sys
import time
import datetime
import queue
import ctypes
import winreg
import logging
import threading
import random
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit

from config import Config
from database import (
    initialize_database,
    get_db_connection,
    insert_packet,
    insert_alert,
    get_recent_packets,
    get_recent_alerts,
    get_stats
)
from detector import DetectionEngine
from packet_sniffer import get_interfaces_list, PacketSnifferEngine

# -------------------------------------------------------------
# Setup Application Logging
# -------------------------------------------------------------
# Ensure logs folder exists
if not os.path.exists(Config.LOG_DIR):
    os.makedirs(Config.LOG_DIR)

# Configure logger
logger = logging.getLogger("ids_system")
logger.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] [%(threadName)s] %(message)s')

# System Log File Handler
sys_handler = logging.FileHandler(Config.SYSTEM_LOG, encoding='utf-8')
sys_handler.setFormatter(formatter)
logger.addHandler(sys_handler)

# Console Handler
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

logger.info("Initializing Network Packet Sniffer & IDS System...")

# Setup custom file logging for Packets and Alerts
def log_packet_to_file(pkt):
    with open(Config.PACKETS_LOG, "a", encoding="utf-8") as f:
        log_line = f"[{pkt['timestamp']}] PROTO: {pkt['protocol']} | SRC: {pkt['src_ip']}:{pkt['src_port']} -> DST: {pkt['dst_ip']}:{pkt['dst_port']} | LEN: {pkt['length']} | FLAGS: {pkt['flags']}\n"
        f.write(log_line)

def log_alert_to_file(alt):
    with open(Config.ALERTS_LOG, "a", encoding="utf-8") as f:
        log_line = f"[{alt['timestamp']}] [ALERT: {alt['alert_type'].upper()}] [SEVERITY: {alt['severity'].upper()}] SRC: {alt['source_ip']} - {alt['description']}\n"
        f.write(log_line)

# -------------------------------------------------------------
# Startup Checks
# -------------------------------------------------------------
def is_admin():
    """Checks if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def is_npcap_installed():
    """Checks if Npcap (or WinPcap) is installed on the system."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap")
        winreg.CloseKey(key)
        return True
    except WindowsError:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npf")
            winreg.CloseKey(key)
            return True
        except WindowsError:
            return False

# Initialize DB structure at startup
initialize_database()

# -------------------------------------------------------------
# Thread-safe Queues
# -------------------------------------------------------------
packet_queue = queue.Queue()  # From Sniffer -> Detector
db_queue = queue.Queue()      # From Detector -> Database Writer
socket_queue = queue.Queue()  # From Detector -> SocketIO Broadcaster

# Thread stopping flags
stop_threads_event = threading.Event()

# Active Sniffer Engine Reference
sniffer_engine = None
active_interface = None
is_sniffing = False
simulation_thread = None
is_simulation = False

# -------------------------------------------------------------
# Detection Thread Wrapper
# -------------------------------------------------------------
def detection_worker():
    logger.info("Detection thread worker started.")
    
    # Callback triggered when DetectionEngine identifies an alert
    def alert_callback(alert_dict):
        logger.warning(f"IDS Alert Triggered: {alert_dict['alert_type']} - Src: {alert_dict['source_ip']}")
        # Push alert to DB Queue and Socket Queue
        db_queue.put({"type": "alert", "data": alert_dict})
        socket_queue.put({"type": "alert", "data": alert_dict})

    engine = DetectionEngine(alert_callback=alert_callback)

    while not stop_threads_event.is_set():
        try:
            # Block with timeout to allow periodic stop checks
            pkt = packet_queue.get(timeout=1.0)
            
            # 1. Run detection rules
            engine.process_packet(pkt)
            
            # 2. Push packet to DB Queue and Socket Queue for visualization
            db_queue.put({"type": "packet", "data": pkt})
            socket_queue.put({"type": "packet", "data": pkt})
            
            packet_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in detection worker: {e}")

    logger.info("Detection thread worker stopped.")

# -------------------------------------------------------------
# Database Writer Thread
# -------------------------------------------------------------
def db_writer_worker():
    logger.info("Database writer thread started.")
    conn = get_db_connection()

    while not stop_threads_event.is_set():
        try:
            item = db_queue.get(timeout=1.0)
            item_type = item.get("type")
            data = item.get("data")

            if item_type == "packet":
                # Save to database
                insert_packet(conn, data)
                # Log packet to file
                log_packet_to_file(data)
            elif item_type == "alert":
                # Save to database
                insert_alert(conn, data)
                # Log alert to file
                log_alert_to_file(data)

            db_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in database writer worker: {e}")
            # Try to reconnect if database has closed/failed
            try:
                conn.close()
            except:
                pass
            conn = get_db_connection()

    conn.close()
    logger.info("Database writer thread stopped.")

# -------------------------------------------------------------
# SocketIO Broadcaster Thread
# -------------------------------------------------------------
def socket_broadcaster_worker(socketio_instance):
    logger.info("SocketIO broadcaster thread started.")
    while not stop_threads_event.is_set():
        try:
            item = socket_queue.get(timeout=1.0)
            item_type = item.get("type")
            data = item.get("data")

            # Emits in real time to all connected WebSocket clients
            if item_type == "packet":
                socketio_instance.emit("live_packet", data)
            elif item_type == "alert":
                socketio_instance.emit("live_alert", data)

            socket_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Error in SocketIO broadcaster worker: {e}")

    logger.info("SocketIO broadcaster thread stopped.")

# -------------------------------------------------------------
# Simulation Mode Sniffer (Mock Traffic Engine)
# -------------------------------------------------------------
def run_traffic_simulation():
    """
    Generates mock network packets to test signature detection and interface displays,
    especially if admin privileges are not available or Npcap is missing.
    """
    logger.info("Mock network traffic simulation thread started.")
    
    ips = ["192.168.1.10", "192.168.1.15", "10.0.0.4", "10.0.0.12", "172.16.5.25", "185.220.101.4", "8.8.8.8"]
    dest_ips = ["192.168.1.1", "192.168.1.100", "10.0.0.1", "10.0.0.254", "8.8.4.4"]
    protocols = ["TCP", "UDP", "ICMP", "DNS", "ARP"]
    ports = [21, 22, 23, 53, 80, 443, 3389, 445, 8080, 12345]

    # Counter for scheduling attacks
    cycle = 0

    while not stop_threads_event.is_set() and is_simulation:
        try:
            cycle += 1
            
            # Simple Attack Simulator Cycles
            # Every 30 seconds, simulate a Port Scan
            if cycle % 60 == 0:
                logger.info("Simulating Port Scan attack...")
                attacker = random.choice(ips)
                victim = random.choice(dest_ips)
                # Query 20 unique ports sequentially
                for port in range(1000, 1025):
                    pkt = {
                        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "epoch_time": time.time(),
                        "src_ip": attacker,
                        "dst_ip": victim,
                        "protocol": "TCP",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": port,
                        "length": 60,
                        "flags": "S"
                    }
                    packet_queue.put(pkt)
                    time.sleep(0.05)
                
            # Every 45 seconds, simulate a SYN Flood
            elif cycle % 90 == 0:
                logger.info("Simulating SYN Flood attack...")
                attacker = "185.220.101.99"
                victim = random.choice(dest_ips)
                # Send 50 SYN packets in rapid succession
                for _ in range(50):
                    pkt = {
                        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "epoch_time": time.time(),
                        "src_ip": attacker,
                        "dst_ip": victim,
                        "protocol": "TCP",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 80,
                        "length": 60,
                        "flags": "S"
                    }
                    packet_queue.put(pkt)
                    time.sleep(0.01)

            # Every 50 seconds, simulate an ICMP Flood
            elif cycle % 100 == 0:
                logger.info("Simulating ICMP Flood attack...")
                attacker = random.choice(ips)
                victim = random.choice(dest_ips)
                for _ in range(30):
                    pkt = {
                        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        "epoch_time": time.time(),
                        "src_ip": attacker,
                        "dst_ip": victim,
                        "protocol": "ICMP",
                        "src_port": None,
                        "dst_port": None,
                        "length": 74,
                        "flags": ""
                    }
                    packet_queue.put(pkt)
                    time.sleep(0.01)

            # Standard random background traffic
            else:
                proto = random.choice(protocols)
                src = random.choice(ips)
                dst = random.choice(dest_ips)
                sp = random.choice(ports) if proto in ["TCP", "UDP"] else None
                dp = random.choice(ports) if proto in ["TCP", "UDP"] else None
                flags = "S" if proto == "TCP" and random.random() < 0.2 else "A" if proto == "TCP" else ""
                
                # Check protocol DNS
                if proto == "DNS":
                    sp = random.randint(1024, 65535)
                    dp = 53
                elif proto == "ARP":
                    sp = None
                    dp = None

                pkt = {
                    "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "epoch_time": time.time(),
                    "src_ip": src,
                    "dst_ip": dst,
                    "protocol": proto,
                    "src_port": sp,
                    "dst_port": dp,
                    "length": random.randint(40, 1500),
                    "flags": flags
                }
                packet_queue.put(pkt)

            # Adaptive delay to simulate network pacing
            time.sleep(random.uniform(0.1, 0.6))
        except Exception as e:
            logger.error(f"Error in traffic simulation: {e}")
            time.sleep(1)

    logger.info("Mock network traffic simulation thread stopped.")

# -------------------------------------------------------------
# Flask + SocketIO Application Config
# -------------------------------------------------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ids_soc_secret_2026_key!'
socketio = SocketIO(app, async_mode='threading', cors_allowed_origins="*")

@app.route('/')
def index():
    """Renders the main dashboard HTML."""
    return render_template('index.html')

@app.route('/api/status', methods=['GET'])
def get_system_status():
    """Returns administrative privileges, Npcap setup, and sniffing status."""
    return jsonify({
        "admin_privileges": is_admin(),
        "npcap_installed": is_npcap_installed(),
        "is_sniffing": is_sniffing,
        "is_simulation": is_simulation,
        "active_interface": active_interface
    })

@app.route('/api/interfaces', methods=['GET'])
def list_interfaces():
    """Lists available network adapters on the system."""
    adapters = get_interfaces_list()
    # Add simulation adapter option
    adapters.insert(0, {
        "guid": "simulation",
        "name": "Simulation Adapter",
        "description": "Virtual interface generating synthetic attack patterns",
        "ip": "127.0.0.1",
        "mac": "00:00:00:00:00:00"
    })
    return jsonify(adapters)

@app.route('/api/start', methods=['POST'])
def start_capture():
    """Starts network packet capturing on the specified interface."""
    global sniffer_engine, active_interface, is_sniffing, simulation_thread, is_simulation
    
    if is_sniffing or is_simulation:
        return jsonify({"success": False, "message": "Capture is already running."}), 400

    data = request.get_json() or {}
    iface = data.get("interface")

    if not iface:
        return jsonify({"success": False, "message": "No interface selected."}), 400

    active_interface = iface

    if iface == "simulation":
        is_simulation = True
        simulation_thread = threading.Thread(target=run_traffic_simulation, name="TrafficSimulation")
        simulation_thread.daemon = True
        simulation_thread.start()
        logger.info("Started synthetic capture in Simulation Mode.")
        return jsonify({"success": True, "message": "Simulation capture started successfully."})
    else:
        # Standard hardware interface sniffing
        # Perform security privilege checks
        if not is_admin():
            return jsonify({
                "success": False, 
                "message": "Administrator privileges are required to sniff raw hardware interfaces on Windows."
            }), 403
        
        if not is_npcap_installed():
            return jsonify({
                "success": False, 
                "message": "Npcap or WinPcap driver was not detected. Please install Npcap in WinPcap-compatibility mode."
            }), 400

        try:
            # Initialize Scapy sniffer callback linking to the shared packet_queue
            def handle_captured_packet(parsed_pkt):
                packet_queue.put(parsed_pkt)

            sniffer_engine = PacketSnifferEngine(iface, handle_captured_packet)
            sniffer_engine.start()
            is_sniffing = True
            logger.info(f"Started hardware sniffer on: {iface}")
            return jsonify({"success": True, "message": f"Hardware packet capture started on {iface}."})
        except Exception as e:
            logger.error(f"Failed to start hardware sniffer: {e}")
            return jsonify({"success": False, "message": f"Sniffer error: {str(e)}"}), 500

@app.route('/api/stop', methods=['POST'])
def stop_capture():
    """Stops the active capture driver or simulation."""
    global sniffer_engine, active_interface, is_sniffing, simulation_thread, is_simulation

    if not is_sniffing and not is_simulation:
        return jsonify({"success": False, "message": "No active capture is running."}), 400

    if is_simulation:
        is_simulation = False
        if simulation_thread:
            simulation_thread.join(timeout=2.0)
            simulation_thread = None
        logger.info("Simulation capture stopped.")
    
    if is_sniffing:
        is_sniffing = False
        if sniffer_engine:
            sniffer_engine.stop()
            sniffer_engine = None
        logger.info(f"Hardware capture stopped on {active_interface}.")

    active_interface = None
    return jsonify({"success": True, "message": "Capture stopped successfully."})

@app.route('/api/stats', methods=['GET'])
def get_database_stats():
    """Exposes statistics calculation endpoints."""
    return jsonify(get_stats())

@app.route('/api/packets', methods=['GET'])
def get_packet_logs():
    """Returns database record subsets of packets."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_recent_packets(limit))

@app.route('/api/alerts', methods=['GET'])
def get_alert_logs():
    """Returns database record subsets of alerts."""
    limit = request.args.get('limit', 50, type=int)
    return jsonify(get_recent_alerts(limit))

# -------------------------------------------------------------
# App Cleanup
# -------------------------------------------------------------
def shutdown_handlers():
    """Stops all running engine threads."""
    logger.info("Stopping all background processes...")
    global sniffer_engine, is_sniffing, is_simulation
    
    stop_threads_event.set()
    
    is_simulation = False
    is_sniffing = False
    
    if sniffer_engine:
        sniffer_engine.stop()

# -------------------------------------------------------------
# Main Application Launcher
# -------------------------------------------------------------
if __name__ == '__main__':
    # Startup thread pools
    stop_threads_event.clear()

    # Start Detection Worker Thread
    t_detect = threading.Thread(target=detection_worker, name="DetectionEngine")
    t_detect.daemon = True
    t_detect.start()

    # Start Database Writer Thread
    t_db = threading.Thread(target=db_writer_worker, name="DBWriter")
    t_db.daemon = True
    t_db.start()

    # Start SocketIO Broadcaster Thread
    t_socket = threading.Thread(target=socket_broadcaster_worker, args=(socketio,), name="SocketIOBroadcaster")
    t_socket.daemon = True
    t_socket.start()

    # Start the Flask web server
    try:
        logger.info(f"SOC App is running. Connect to: http://{Config.FLASK_HOST}:{Config.FLASK_PORT}")
        socketio.run(app, host=Config.FLASK_HOST, port=Config.FLASK_PORT, debug=False, allow_unsafe_werkzeug=True)
    finally:
        shutdown_handlers()
