"""
NetVision Packet Sniffer Engine
Supports Live Network Capture (Scapy + Npcap), Offline PCAP File Analysis,
and synthetic Traffic Simulation for non-root / classroom demonstration environments.
"""

import time
import threading
import random
import logging
from collections import deque
from typing import List, Dict, Any, Optional, Callable

from analyzer.packet_parser import parse_packet
from analyzer.traffic_statistics import TrafficStatistics
from analyzer.protocol_analyzer import ProtocolAnalyzer
from analyzer.anomaly_detector import AnomalyDetector

try:
    from scapy.all import sniff, conf, get_if_list, rdpcap, AsyncSniffer
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] [Sniffer] %(message)s")
logger = logging.getLogger("NetVision.Sniffer")


class PacketSnifferEngine:
    def __init__(self, max_packets: int = 10000):
        self.max_packets = max_packets
        self.packets: deque = deque(maxlen=max_packets)
        self._lock = threading.Lock()
        self._is_capturing = False
        self._is_paused = False
        self.capture_mode: str = "simulation"  # "live", "pcap", "simulation"
        self.selected_interface: Optional[str] = None
        self.bpf_filter: str = ""
        self.packet_counter: int = 0

        # Sub-engines
        self.stats = TrafficStatistics()
        self.protocol_analyzer = ProtocolAnalyzer()
        self.anomaly_detector = AnomalyDetector()

        # Threads & runners
        self._capture_thread: Optional[threading.Thread] = None
        self._async_sniffer = None
        self._simulation_running = False
        self.status_message: str = "Ready"
        self.error_message: Optional[str] = None

        # Listeners
        self.packet_callbacks: List[Callable[[Dict[str, Any]], None]] = []

    def get_interfaces(self) -> List[str]:
        """List active network interfaces available on the host machine."""
        if not SCAPY_AVAILABLE:
            return ["Simulation-Virtual-NIC (Loopback)"]
        try:
            interfaces = get_if_list()
            # On Windows, human-friendly names are in conf.ifaces
            friendly_names = []
            for iface in conf.ifaces.values():
                friendly_names.append(f"{iface.name} ({getattr(iface, 'description', iface.name)})")
            return friendly_names if friendly_names else interfaces
        except Exception as e:
            logger.warning(f"Failed to query network interfaces: {e}")
            return ["Simulation-Virtual-NIC", "Local Area Connection", "Wi-Fi"]

    def add_callback(self, cb: Callable[[Dict[str, Any]], None]) -> None:
        self.packet_callbacks.append(cb)

    @property
    def is_capturing(self) -> bool:
        return self._is_capturing

    @property
    def is_paused(self) -> bool:
        return self._is_paused

    def toggle_pause(self) -> bool:
        self._is_paused = not self._is_paused
        return self._is_paused

    def clear(self) -> None:
        """Clear captured buffer and reset analyzers."""
        with self._lock:
            self.packets.clear()
            self.packet_counter = 0
            self.stats.reset()
            self.protocol_analyzer = ProtocolAnalyzer()
            self.anomaly_detector.reset()
            self.status_message = "Capture buffer cleared."

    def _ingest_packet(self, raw_or_parsed: Any, interface_name: str = "Default") -> Dict[str, Any]:
        """Ingest a single packet into statistics, protocol engine, and anomaly detector."""
        if self._is_paused:
            return {}

        self.packet_counter += 1
        record = parse_packet(raw_or_parsed, packet_id=self.packet_counter, interface_name=interface_name)

        with self._lock:
            self.packets.append(record)
            self.stats.update(record)
            self.protocol_analyzer.process_packet(record)
            self.anomaly_detector.evaluate_packet(record)

        for cb in self.packet_callbacks:
            try:
                cb(record)
            except Exception:
                pass

        return record

    def start_live_capture(self, interface: Optional[str] = None, bpf_filter: str = "") -> bool:
        """Start capturing actual network packets on selected interface using Scapy."""
        if self._is_capturing:
            logger.warning("Capture already active.")
            return False

        if not SCAPY_AVAILABLE:
            self.error_message = "Scapy library not available. Please run in Simulation Mode."
            return False

        self.clear()
        self.capture_mode = "live"
        self.selected_interface = interface
        self.bpf_filter = bpf_filter
        self._is_capturing = True
        self.error_message = None
        self.status_message = f"Live Capture Active on {interface or 'Default'}..."

        self._capture_thread = threading.Thread(target=self._run_live_sniff, daemon=True, name="LiveSnifferThread")
        self._capture_thread.start()
        return True

    def _run_live_sniff(self) -> None:
        """Scapy sniffing thread with graceful permission and Npcap error handling."""
        try:
            # Resolve actual interface name if description was prepended
            iface = self.selected_interface
            if iface and "(" in iface:
                iface = iface.split(" (")[0].strip()

            def scapy_packet_handler(pkt):
                if not self._is_capturing:
                    return
                self._ingest_packet(pkt, interface_name=str(iface or "Live"))

            sniff_kwargs = {
                "prn": scapy_packet_handler,
                "store": False,
                "stop_filter": lambda _: not self._is_capturing
            }
            if iface and iface != "Default":
                sniff_kwargs["iface"] = iface
            if self.bpf_filter:
                sniff_kwargs["filter"] = self.bpf_filter

            sniff(**sniff_kwargs)

        except Exception as e:
            err_str = str(e)
            logger.error(f"Live sniff failed: {err_str}")
            self.error_message = (
                f"Live capture error: {err_str}. "
                "Note: Live packet capture on Windows requires Npcap (https://npcap.com) "
                "installed with 'WinPcap API-compatible Mode' enabled and Administrator privileges. "
                "You can switch to Simulation Mode for zero-privilege demonstrations."
            )
            self._is_capturing = False
            self.status_message = "Capture Stopped with Error."

    def stop_capture(self) -> None:
        """Gracefully stop any active capture thread or simulation."""
        self._is_capturing = False
        self._simulation_running = False
        self.status_message = "Capture Stopped."
        logger.info("Packet capture stopped.")

    def load_pcap_file(self, filepath: str) -> int:
        """Import and parse packets from an offline .pcap or .pcapng file."""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is required to read PCAP files.")

        self.clear()
        self.capture_mode = "pcap"
        self.status_message = f"Loading PCAP file: {filepath}..."

        try:
            packets = rdpcap(filepath)
            loaded_count = 0
            for pkt in packets:
                self._ingest_packet(pkt, interface_name="PCAP-Import")
                loaded_count += 1

            self.status_message = f"Successfully imported {loaded_count} packets from {filepath}"
            return loaded_count
        except Exception as e:
            self.error_message = f"Failed to parse PCAP file: {e}"
            self.status_message = "PCAP Load Failed."
            raise

    # -----------------------------------------------------------------
    # SIMULATION MODE ENGINE (For College Viva & Classroom Demos)
    # -----------------------------------------------------------------
    def start_simulation(self, traffic_rate: int = 10, inject_anomalies: bool = False) -> bool:
        """
        Start synthetic traffic generation mode.
        Generates realistic TCP handshakes, HTTP, DNS, ICMP, and file transfer packets.
        Works 100% without Administrator rights or Npcap!
        """
        if self._is_capturing:
            self.stop_capture()
            time.sleep(0.3)

        self.clear()
        self.capture_mode = "simulation"
        self._is_capturing = True
        self._simulation_running = True
        self.error_message = None
        self.status_message = "Simulation Mode Active (Zero-Privilege Classroom Demo)"

        self._capture_thread = threading.Thread(
            target=self._run_simulation_loop,
            args=(traffic_rate, inject_anomalies),
            daemon=True,
            name="TrafficSimulationThread"
        )
        self._capture_thread.start()
        return True

    def _run_simulation_loop(self, rate: int, inject_anomalies: bool) -> None:
        """Simulate continuous multi-node network traffic."""
        laptop_a_ip = "192.168.1.10"
        laptop_b_ip = "192.168.1.25"
        gateway_ip = "192.168.1.1"
        dns_server = "8.8.8.8"
        external_web = ["142.250.190.46", "104.244.42.1", "151.101.65.140"]

        sim_tick = 0
        interval = max(1.0 / rate, 0.02)

        while self._is_capturing and self._simulation_running:
            sim_tick += 1
            now = time.time()
            dt_str = time.strftime("%H:%M:%S", time.localtime(now)) + f".{int((now % 1) * 1000):03d}"

            # 1. Simulate TCP 3-Way Handshake + File Transfer burst (Laptop A -> Laptop B)
            if sim_tick % 15 == 0:
                client_port = random.randint(49152, 65000)
                server_port = 65432  # NetVision transfer port

                # Step 1: SYN
                syn_pkt = {
                    "timestamp": now, "time_formatted": dt_str,
                    "src_ip": laptop_a_ip, "dst_ip": laptop_b_ip,
                    "protocol": "TCP", "src_port": client_port, "dst_port": server_port,
                    "packet_size": 66, "tcp_flags": "SYN",
                    "interface": "Wi-Fi (Simulated)", "ttl": 128,
                    "summary": f"TCP {laptop_a_ip}:{client_port} -> {laptop_b_ip}:{server_port} [SYN] Seq=0 Win=64240"
                }
                self._ingest_packet(syn_pkt)
                time.sleep(0.02)

                # Step 2: SYN-ACK
                syn_ack_pkt = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": laptop_b_ip, "dst_ip": laptop_a_ip,
                    "protocol": "TCP", "src_port": server_port, "dst_port": client_port,
                    "packet_size": 66, "tcp_flags": "SYN-ACK",
                    "interface": "Wi-Fi (Simulated)", "ttl": 128,
                    "summary": f"TCP {laptop_b_ip}:{server_port} -> {laptop_a_ip}:{client_port} [SYN, ACK] Seq=0 Ack=1"
                }
                self._ingest_packet(syn_ack_pkt)
                time.sleep(0.01)

                # Step 3: ACK
                ack_pkt = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": laptop_a_ip, "dst_ip": laptop_b_ip,
                    "protocol": "TCP", "src_port": client_port, "dst_port": server_port,
                    "packet_size": 54, "tcp_flags": "ACK",
                    "interface": "Wi-Fi (Simulated)", "ttl": 128,
                    "summary": f"TCP {laptop_a_ip}:{client_port} -> {laptop_b_ip}:{server_port} [ACK] Seq=1 Ack=1"
                }
                self._ingest_packet(ack_pkt)

                # Data chunks
                for _ in range(random.randint(2, 6)):
                    data_pkt = {
                        "timestamp": time.time(), "time_formatted": dt_str,
                        "src_ip": laptop_a_ip, "dst_ip": laptop_b_ip,
                        "protocol": "TCP", "src_port": client_port, "dst_port": server_port,
                        "packet_size": random.randint(512, 1460), "tcp_flags": "PSH-ACK",
                        "interface": "Wi-Fi (Simulated)", "ttl": 128,
                        "summary": f"TCP {laptop_a_ip}:{client_port} -> {laptop_b_ip}:{server_port} [PSH, ACK] Length=1400"
                    }
                    self._ingest_packet(data_pkt)
                    time.sleep(0.01)

            # 2. Simulate ICMP Ping (Echo Request / Echo Reply)
            elif sim_tick % 10 == 0:
                ping_req = {
                    "timestamp": now, "time_formatted": dt_str,
                    "src_ip": laptop_a_ip, "dst_ip": gateway_ip,
                    "protocol": "ICMP", "src_port": None, "dst_port": None,
                    "packet_size": 74, "tcp_flags": "N/A",
                    "interface": "Wi-Fi (Simulated)", "ttl": 64,
                    "summary": f"ICMP Echo (ping) request id=0x0001 seq={sim_tick//10}"
                }
                self._ingest_packet(ping_req)
                time.sleep(0.01)
                ping_rep = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": gateway_ip, "dst_ip": laptop_a_ip,
                    "protocol": "ICMP", "src_port": None, "dst_port": None,
                    "packet_size": 74, "tcp_flags": "N/A",
                    "interface": "Wi-Fi (Simulated)", "ttl": 64,
                    "summary": f"ICMP Echo (ping) reply id=0x0001 seq={sim_tick//10}"
                }
                self._ingest_packet(ping_rep)

            # 3. Simulate DNS Query/Response
            elif sim_tick % 7 == 0:
                dns_req = {
                    "timestamp": now, "time_formatted": dt_str,
                    "src_ip": laptop_a_ip, "dst_ip": dns_server,
                    "protocol": "DNS (UDP)", "src_port": random.randint(50000, 60000), "dst_port": 53,
                    "packet_size": 78, "tcp_flags": "N/A",
                    "interface": "Wi-Fi (Simulated)", "ttl": 64,
                    "summary": "Standard query 0x12a4 A college-demo.net"
                }
                self._ingest_packet(dns_req)
                time.sleep(0.01)
                dns_resp = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": dns_server, "dst_ip": laptop_a_ip,
                    "protocol": "DNS (UDP)", "src_port": 53, "dst_port": dns_req["src_port"],
                    "packet_size": 94, "tcp_flags": "N/A",
                    "interface": "Wi-Fi (Simulated)", "ttl": 115,
                    "summary": "Standard query response 0x12a4 A 142.250.190.46"
                }
                self._ingest_packet(dns_resp)

            # 4. Normal Web HTTPS Traffic
            else:
                ext_ip = random.choice(external_web)
                pkt = {
                    "timestamp": now, "time_formatted": dt_str,
                    "src_ip": laptop_a_ip if random.random() > 0.4 else ext_ip,
                    "dst_ip": ext_ip if random.random() > 0.4 else laptop_a_ip,
                    "protocol": "TCP",
                    "src_port": random.randint(49152, 65000),
                    "dst_port": 443,
                    "packet_size": random.randint(80, 1480),
                    "tcp_flags": random.choice(["ACK", "PSH-ACK", "ACK"]),
                    "interface": "Wi-Fi (Simulated)", "ttl": 128,
                    "summary": f"HTTPS Application Data [{random.randint(100, 1400)} bytes]"
                }
                self._ingest_packet(pkt)

            # 5. Anomaly Injection (If enabled)
            if inject_anomalies:
                # Every 40 ticks, inject a simulated port scan
                if sim_tick % 45 == 0:
                    attacker_ip = "192.168.1.99"
                    for target_port in [21, 22, 23, 80, 443, 3389, 8080, 65432, 9000]:
                        scan_pkt = {
                            "timestamp": time.time(), "time_formatted": dt_str,
                            "src_ip": attacker_ip, "dst_ip": laptop_a_ip,
                            "protocol": "TCP", "src_port": random.randint(40000, 50000), "dst_port": target_port,
                            "packet_size": 60, "tcp_flags": "SYN",
                            "interface": "Wi-Fi (Simulated)", "ttl": 64,
                            "summary": f"TCP {attacker_ip} -> {laptop_a_ip}:{target_port} [SYN] Port Probe"
                        }
                        self._ingest_packet(scan_pkt)
                        time.sleep(0.01)

                # Every 70 ticks, inject a SYN flood burst
                elif sim_tick % 75 == 0:
                    flood_ip = "192.168.1.188"
                    for _ in range(30):
                        syn_burst = {
                            "timestamp": time.time(), "time_formatted": dt_str,
                            "src_ip": flood_ip, "dst_ip": laptop_b_ip,
                            "protocol": "TCP", "src_port": random.randint(30000, 60000), "dst_port": 80,
                            "packet_size": 64, "tcp_flags": "SYN",
                            "interface": "Wi-Fi (Simulated)", "ttl": 64,
                            "summary": f"TCP {flood_ip} -> {laptop_b_ip}:80 [SYN] Half-Open Burst"
                        }
                        self._ingest_packet(syn_burst)
                        time.sleep(0.005)

            time.sleep(interval)

    def trigger_anomaly_simulation(self, anomaly_type: str = "port_scan") -> None:
        """Manually trigger a safe simulated anomaly on demand for live viva demonstrations."""
        now = time.time()
        dt_str = time.strftime("%H:%M:%S", time.localtime(now))

        if anomaly_type == "port_scan":
            attacker = "192.168.1.77"
            target = "192.168.1.10"
            for p in [21, 22, 23, 25, 80, 110, 143, 443, 3306, 3389, 65432]:
                pkt = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": attacker, "dst_ip": target,
                    "protocol": "TCP", "src_port": random.randint(40000, 60000), "dst_port": p,
                    "packet_size": 60, "tcp_flags": "SYN",
                    "interface": "Wi-Fi (Simulated)", "ttl": 64,
                    "summary": f"Simulated Port Probe: {attacker} -> {target}:{p} [SYN]"
                }
                self._ingest_packet(pkt)
                time.sleep(0.02)

        elif anomaly_type == "syn_flood":
            flood_src = "192.168.1.155"
            target = "192.168.1.25"
            for _ in range(35):
                pkt = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": flood_src, "dst_ip": target,
                    "protocol": "TCP", "src_port": random.randint(30000, 65000), "dst_port": 80,
                    "packet_size": 64, "tcp_flags": "SYN",
                    "interface": "Wi-Fi (Simulated)", "ttl": 64,
                    "summary": f"Simulated SYN Flood Burst: {flood_src} -> {target}:80 [SYN]"
                }
                self._ingest_packet(pkt)
                time.sleep(0.01)

        elif anomaly_type == "traffic_spike":
            for _ in range(160):
                pkt = {
                    "timestamp": time.time(), "time_formatted": dt_str,
                    "src_ip": "192.168.1.10", "dst_ip": "192.168.1.25",
                    "protocol": "TCP", "src_port": 65432, "dst_port": 65432,
                    "packet_size": 1460, "tcp_flags": "PSH-ACK",
                    "interface": "Wi-Fi (Simulated)", "ttl": 128,
                    "summary": "Simulated High Throughput Burst [1460 bytes]"
                }
                self._ingest_packet(pkt)

    def get_packets(
        self,
        protocol: Optional[str] = None,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        port: Optional[int] = None,
        min_size: Optional[int] = None,
        max_size: Optional[int] = None,
        search_query: Optional[str] = None,
        limit: int = 1000
    ) -> List[Dict[str, Any]]:
        """Filter and retrieve stored packets matching criteria."""
        with self._lock:
            pkts = list(self.packets)

        filtered = []
        q = search_query.lower() if search_query else None

        for p in reversed(pkts):
            if protocol and protocol != "All":
                if protocol == "TCP" and "TCP" not in p.get("protocol", ""):
                    continue
                elif protocol == "UDP" and "UDP" not in p.get("protocol", ""):
                    continue
                elif protocol == "ICMP" and "ICMP" not in p.get("protocol", ""):
                    continue
                elif protocol not in ("TCP", "UDP", "ICMP") and p.get("protocol") != protocol:
                    continue

            if src_ip and src_ip.strip():
                if src_ip.strip().lower() not in p.get("src_ip", "").lower():
                    continue

            if dst_ip and dst_ip.strip():
                if dst_ip.strip().lower() not in p.get("dst_ip", "").lower():
                    continue

            if port is not None and port > 0:
                if p.get("src_port") != port and p.get("dst_port") != port:
                    continue

            size = p.get("packet_size", 0)
            if min_size is not None and size < min_size:
                continue
            if max_size is not None and size > max_size:
                continue

            if q:
                row_str = f"{p.get('src_ip')} {p.get('dst_ip')} {p.get('protocol')} {p.get('summary')} {p.get('tcp_flags')}".lower()
                if q not in row_str:
                    continue

            filtered.append(p)
            if len(filtered) >= limit:
                break

        return filtered
