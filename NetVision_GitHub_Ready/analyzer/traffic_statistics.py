"""
NetVision Traffic Statistics Engine
Computes real-time and aggregate metrics: protocol breakdown, bandwidth rates,
packet size distributions, and conversation matrices for visualization.
"""

from collections import Counter, defaultdict
from typing import List, Dict, Any, Tuple
import math


class TrafficStatistics:
    def __init__(self):
        self.reset()

    def reset(self) -> None:
        """Reset all statistical counters."""
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.protocol_counter: Counter = Counter()
        self.tcp_flags_counter: Counter = Counter()
        self.src_ip_counter: Counter = Counter()
        self.dst_ip_counter: Counter = Counter()
        self.ip_pair_counter: Counter = Counter()
        self.port_counter: Counter = Counter()
        self.size_bins: Dict[str, int] = {
            "< 64 B": 0,
            "64-128 B": 0,
            "129-512 B": 0,
            "513-1024 B": 0,
            "1025-1518 B": 0,
            "> 1518 B": 0,
        }
        self.time_series_sec: Dict[int, Dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
        self.start_timestamp: float = 0.0
        self.last_timestamp: float = 0.0

    def update(self, packet: Dict[str, Any]) -> None:
        """Update metrics with a single parsed packet record."""
        size = packet.get("packet_size", 0)
        ts = packet.get("timestamp", 0.0)

        if self.total_packets == 0:
            self.start_timestamp = ts
        self.last_timestamp = max(self.last_timestamp, ts)

        self.total_packets += 1
        self.total_bytes += size

        # Protocol
        proto = packet.get("protocol", "Other")
        self.protocol_counter[proto] += 1

        # TCP flags
        flags = packet.get("tcp_flags", "N/A")
        if flags and flags != "N/A":
            for f in flags.split("-"):
                f = f.strip()
                if f:
                    self.tcp_flags_counter[f] += 1

        # IP Talkers
        src_ip = packet.get("src_ip", "")
        dst_ip = packet.get("dst_ip", "")
        if src_ip and src_ip != "N/A":
            self.src_ip_counter[src_ip] += 1
        if dst_ip and dst_ip != "N/A":
            self.dst_ip_counter[dst_ip] += 1
        if src_ip and dst_ip and src_ip != "N/A" and dst_ip != "N/A":
            pair = f"{src_ip} ↔ {dst_ip}"
            self.ip_pair_counter[pair] += 1

        # Ports
        dst_port = packet.get("dst_port")
        if dst_port:
            self.port_counter[f"{dst_port}"] += 1

        # Size distribution
        if size < 64:
            self.size_bins["< 64 B"] += 1
        elif size <= 128:
            self.size_bins["64-128 B"] += 1
        elif size <= 512:
            self.size_bins["129-512 B"] += 1
        elif size <= 1024:
            self.size_bins["513-1024 B"] += 1
        elif size <= 1518:
            self.size_bins["1025-1518 B"] += 1
        else:
            self.size_bins["> 1518 B"] += 1

        # Time series by whole second
        sec = int(ts)
        self.time_series_sec[sec]["packets"] += 1
        self.time_series_sec[sec]["bytes"] += size

    def update_batch(self, packets: List[Dict[str, Any]]) -> None:
        """Batch update from multiple packets."""
        for p in packets:
            self.update(p)

    def get_summary(self) -> Dict[str, Any]:
        """Return high-level summary metrics for KPI cards."""
        duration = max(self.last_timestamp - self.start_timestamp, 0.0) if self.total_packets > 0 else 0.0
        avg_size = (self.total_bytes / self.total_packets) if self.total_packets > 0 else 0.0
        avg_pps = (self.total_packets / duration) if duration > 0.5 else float(self.total_packets)
        avg_bps = (self.total_bytes / duration) if duration > 0.5 else float(self.total_bytes)

        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "avg_packet_size": round(avg_size, 1),
            "capture_duration_seconds": round(duration, 1),
            "avg_packets_per_sec": round(avg_pps, 1),
            "avg_bytes_per_sec": round(avg_bps, 1),
            "tcp_count": self.protocol_counter.get("TCP", 0),
            "udp_count": self.protocol_counter.get("UDP", 0) + self.protocol_counter.get("DNS (UDP)", 0),
            "icmp_count": self.protocol_counter.get("ICMP", 0),
            "other_count": sum(c for p, c in self.protocol_counter.items() if not ("TCP" in p or "UDP" in p or "ICMP" in p)),
        }

    def get_protocol_distribution(self) -> Dict[str, int]:
        """Return protocol breakdown dictionary."""
        return dict(self.protocol_counter)

    def get_tcp_flags_distribution(self) -> Dict[str, int]:
        """Return TCP flags count dictionary."""
        return dict(self.tcp_flags_counter)

    def get_size_distribution(self) -> Dict[str, int]:
        """Return packet size bin counts."""
        return dict(self.size_bins)

    def get_top_talkers(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Return top communicating IP addresses by packet count."""
        combined = Counter()
        for ip, count in self.src_ip_counter.items():
            combined[ip] += count
        for ip, count in self.dst_ip_counter.items():
            combined[ip] += count
        return combined.most_common(limit)

    def get_top_ip_pairs(self, limit: int = 5) -> List[Tuple[str, int]]:
        """Return top IP pairs communicating."""
        return self.ip_pair_counter.most_common(limit)

    def get_time_series_data(self) -> Dict[str, List[Any]]:
        """Return ordered lists of timestamps, packets/sec, and bytes/sec for graphing."""
        if not self.time_series_sec:
            return {"seconds": [], "pps": [], "bps": [], "kbps": []}

        sorted_secs = sorted(self.time_series_sec.keys())
        first_sec = sorted_secs[0]

        rel_secs = [s - first_sec for s in sorted_secs]
        pps = [self.time_series_sec[s]["packets"] for s in sorted_secs]
        bps = [self.time_series_sec[s]["bytes"] for s in sorted_secs]
        kbps = [round(b / 1024.0, 2) for b in bps]

        return {
            "seconds": rel_secs,
            "pps": pps,
            "bps": bps,
            "kbps": kbps
        }
