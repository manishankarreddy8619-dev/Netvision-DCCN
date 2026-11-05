"""
NetVision Protocol Analyzer
Performs in-depth protocol inspection: TCP three-way handshake tracking,
connection state machines, ICMP echo round-trip correlation, and service identification.
"""

from typing import Dict, Any, List, Optional, Tuple
from collections import defaultdict


KNOWN_PORTS = {
    20: "FTP-Data",
    21: "FTP-Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    65432: "NetVision-Transfer",
    8080: "HTTP-Proxy",
    8501: "Streamlit-Web"
}


class ProtocolAnalyzer:
    def __init__(self):
        # TCP connection state tracking: key -> stream info
        # key format: canonical stream key (min_ip:port, max_ip:port)
        self.tcp_streams: Dict[str, Dict[str, Any]] = {}
        self.completed_handshakes: List[Dict[str, Any]] = []
        self.icmp_requests: Dict[str, float] = {}  # identifier -> request timestamp
        self.icmp_rtt_history: List[Dict[str, Any]] = []

    def get_service_name(self, port: Optional[int]) -> str:
        """Resolve common well-known port numbers to human-friendly service names."""
        if not port:
            return "Unknown"
        return KNOWN_PORTS.get(port, f"Port {port}")

    def _get_stream_key(self, ip1: str, p1: int, ip2: str, p2: int) -> Tuple[str, bool]:
        """Generate canonical key for bidirectional stream tracking."""
        endpoint1 = f"{ip1}:{p1}"
        endpoint2 = f"{ip2}:{p2}"
        if endpoint1 <= endpoint2:
            return f"{endpoint1} <-> {endpoint2}", True
        else:
            return f"{endpoint2} <-> {endpoint1}", False

    def process_packet(self, packet: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process packet through protocol state engines.
        Returns notification event dict if a state milestone (e.g. 3-way handshake) is achieved.
        """
        proto = packet.get("protocol", "")
        ts = packet.get("timestamp", 0.0)

        # 1. TCP Analysis & Handshake State Machine
        if proto == "TCP":
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            src_port = packet.get("src_port")
            dst_port = packet.get("dst_port")
            flags = packet.get("tcp_flags", "")

            if src_port and dst_port and src_ip and dst_ip:
                stream_key, is_forward = self._get_stream_key(src_ip, src_port, dst_ip, dst_port)

                if stream_key not in self.tcp_streams:
                    self.tcp_streams[stream_key] = {
                        "stream_id": stream_key,
                        "client": f"{src_ip}:{src_port}",
                        "server": f"{dst_ip}:{dst_port}",
                        "state": "INIT",
                        "syn_time": None,
                        "syn_ack_time": None,
                        "established_time": None,
                        "handshake_latency_ms": None,
                        "total_packets": 0,
                        "total_bytes": 0,
                        "start_time": ts,
                        "service": self.get_service_name(dst_port) if dst_port in KNOWN_PORTS else self.get_service_name(src_port)
                    }

                stream = self.tcp_streams[stream_key]
                stream["total_packets"] += 1
                stream["total_bytes"] += packet.get("packet_size", 0)

                # State 1: SYN (Client initiates)
                if "SYN" in flags and "ACK" not in flags:
                    stream["state"] = "SYN_SENT"
                    stream["syn_time"] = ts

                # State 2: SYN-ACK (Server responds)
                elif "SYN" in flags and "ACK" in flags:
                    if stream["state"] in ("SYN_SENT", "INIT"):
                        stream["state"] = "SYN_RECEIVED"
                        stream["syn_ack_time"] = ts

                # State 3: ACK (Client completes 3-way handshake)
                elif flags == "ACK" and stream["state"] == "SYN_RECEIVED":
                    stream["state"] = "ESTABLISHED"
                    stream["established_time"] = ts
                    if stream["syn_time"]:
                        latency_ms = (ts - stream["syn_time"]) * 1000.0
                        stream["handshake_latency_ms"] = round(latency_ms, 2)
                        handshake_event = {
                            "type": "tcp_handshake_completed",
                            "stream": stream_key,
                            "client": stream["client"],
                            "server": stream["server"],
                            "latency_ms": stream["handshake_latency_ms"],
                            "timestamp": ts,
                            "summary": f"TCP 3-Way Handshake established: {stream['client']} ➔ {stream['server']} ({latency_ms:.2f} ms)"
                        }
                        self.completed_handshakes.append(handshake_event)
                        return handshake_event

                # Teardown: FIN or RST
                elif "FIN" in flags:
                    stream["state"] = "FIN_WAIT"
                elif "RST" in flags:
                    stream["state"] = "RESET"

        # 2. ICMP Echo Request / Reply Matching
        elif proto == "ICMP":
            summary = packet.get("summary", "")
            src_ip = packet.get("src_ip")
            dst_ip = packet.get("dst_ip")
            key = f"{src_ip}->{dst_ip}"
            rev_key = f"{dst_ip}->{src_ip}"

            if "Echo Request" in summary:
                self.icmp_requests[key] = ts
            elif "Echo Reply" in summary:
                if rev_key in self.icmp_requests:
                    req_time = self.icmp_requests.pop(rev_key)
                    rtt_ms = round((ts - req_time) * 1000.0, 2)
                    rtt_event = {
                        "type": "icmp_ping_rtt",
                        "sender": dst_ip,
                        "target": src_ip,
                        "rtt_ms": rtt_ms,
                        "timestamp": ts,
                        "summary": f"ICMP Ping RTT: {dst_ip} ↔ {src_ip} = {rtt_ms} ms"
                    }
                    self.icmp_rtt_history.append(rtt_event)
                    return rtt_event

        return None

    def get_active_streams(self) -> List[Dict[str, Any]]:
        """Return list of active and recent TCP connections."""
        return list(self.tcp_streams.values())

    def get_handshake_records(self) -> List[Dict[str, Any]]:
        """Return all recorded TCP 3-way handshakes."""
        return list(self.completed_handshakes)
