"""
NetVision Packet Parser
Safely parses raw network packets into structured, standardized dictionary records.
Preserves privacy by never storing sensitive application payloads or credentials.
"""

import time
import socket
from datetime import datetime
from typing import Dict, Any, Optional

try:
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.packet import Packet as ScapyPacket
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    ScapyPacket = Any

TCP_FLAGS_MAP = {
    "F": "FIN",
    "S": "SYN",
    "R": "RST",
    "P": "PSH",
    "A": "ACK",
    "U": "URG",
    "E": "ECE",
    "C": "CWR"
}

ICMP_TYPES_MAP = {
    0: "Echo Reply",
    3: "Destination Unreachable",
    5: "Redirect",
    8: "Echo Request",
    11: "Time Exceeded"
}


def parse_tcp_flags(flags_val: Any) -> str:
    """Translate Scapy flag representation into human-readable format (e.g., 'SYN, ACK')."""
    if not flags_val:
        return "None"

    flags_str = str(flags_val)
    active_flags = []
    for char, name in TCP_FLAGS_MAP.items():
        if char in flags_str:
            active_flags.append(name)

    return "-".join(active_flags) if active_flags else flags_str


def determine_direction(src_ip: str, dst_ip: str, local_ip: Optional[str] = None) -> str:
    """Determine traffic direction relative to local host IP."""
    if not local_ip:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"

    if src_ip == local_ip and dst_ip == local_ip:
        return "Loopback"
    elif src_ip == local_ip:
        return "Outbound"
    elif dst_ip == local_ip:
        return "Inbound"
    else:
        return "Transit / External"


def parse_packet(
    pkt: Any,
    packet_id: int = 1,
    interface_name: str = "Default",
    local_ip: Optional[str] = None
) -> Dict[str, Any]:
    """
    Parse a network packet (Scapy Packet or synthetic dict) into a unified dictionary record.
    Guarantees no raw sensitive payloads are retained.
    """
    if isinstance(pkt, dict):
        # Synthetic / simulated packet record
        record = dict(pkt)
        record["packet_id"] = packet_id
        if "direction" not in record:
            record["direction"] = determine_direction(record.get("src_ip", ""), record.get("dst_ip", ""), local_ip)
        return record

    # Real Scapy Packet parsing
    ts = float(getattr(pkt, "time", time.time()))
    dt = datetime.fromtimestamp(ts)
    time_str = dt.strftime("%H:%M:%S.") + f"{int(dt.microsecond / 1000):03d}"

    src_ip = "N/A"
    dst_ip = "N/A"
    ip_version = 4
    ttl = 64

    if SCAPY_AVAILABLE and pkt.haslayer(IP):
        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        ip_version = 4
        ttl = ip_layer.ttl
    elif SCAPY_AVAILABLE and pkt.haslayer(IPv6):
        ip6_layer = pkt[IPv6]
        src_ip = ip6_layer.src
        dst_ip = ip6_layer.dst
        ip_version = 6
        ttl = getattr(ip6_layer, "hlim", 64)
    elif SCAPY_AVAILABLE and pkt.haslayer(ARP):
        arp = pkt[ARP]
        src_ip = arp.psrc
        dst_ip = arp.pdst
        return {
            "packet_id": packet_id,
            "timestamp": ts,
            "time_formatted": time_str,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": "ARP",
            "src_port": None,
            "dst_port": None,
            "packet_size": len(pkt),
            "tcp_flags": "N/A",
            "direction": determine_direction(src_ip, dst_ip, local_ip),
            "interface": interface_name,
            "ttl": ttl,
            "summary": f"ARP Request/Reply: {src_ip} -> {dst_ip}"
        }

    protocol = "Other"
    src_port = None
    dst_port = None
    tcp_flags = "N/A"
    summary_parts = []

    if SCAPY_AVAILABLE and pkt.haslayer(TCP):
        protocol = "TCP"
        tcp = pkt[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        tcp_flags = parse_tcp_flags(tcp.flags)
        summary_parts.append(f"Seq={tcp.seq} Ack={tcp.ack} Flags=[{tcp_flags}]")

    elif SCAPY_AVAILABLE and pkt.haslayer(UDP):
        protocol = "UDP"
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        if src_port == 53 or dst_port == 53:
            protocol = "DNS (UDP)"
        summary_parts.append(f"Length={len(pkt[UDP])}")

    elif SCAPY_AVAILABLE and pkt.haslayer(ICMP):
        protocol = "ICMP"
        icmp = pkt[ICMP]
        icmp_type_name = ICMP_TYPES_MAP.get(icmp.type, f"Type {icmp.type}")
        summary_parts.append(f"{icmp_type_name} (Code {icmp.code})")

    summary = f"{protocol} {src_ip}:{src_port or ''} -> {dst_ip}:{dst_port or ''} {' '.join(summary_parts)}".strip()

    return {
        "packet_id": packet_id,
        "timestamp": ts,
        "time_formatted": time_str,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "ip_version": ip_version,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "packet_size": len(pkt),
        "tcp_flags": tcp_flags,
        "direction": determine_direction(src_ip, dst_ip, local_ip),
        "interface": interface_name,
        "ttl": ttl,
        "summary": summary
    }
