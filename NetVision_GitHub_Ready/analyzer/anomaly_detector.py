"""
NetVision Anomaly Detection Engine
Transparent, rule-based and statistical anomaly detection for educational network analysis.
Identifies suspicious traffic patterns (port scans, SYN bursts, traffic spikes)
without making unfounded claims of confirmed cyberattacks.
"""

import time
from collections import defaultdict, deque
from typing import List, Dict, Any, Optional
import math


class AnomalyDetector:
    def __init__(
        self,
        time_window: float = 3.0,
        pps_threshold: int = 150,
        syn_burst_threshold: int = 25,
        port_scan_threshold: int = 8,
        spike_multiplier: float = 3.5,
    ):
        """
        Initialize anomaly detector with configurable sensitivity thresholds.

        Args:
            time_window: Evaluation time window in seconds (default: 3.0s).
            pps_threshold: Maximum expected packets per second before alert.
            syn_burst_threshold: Maximum SYN packets from single host in window.
            port_scan_threshold: Maximum distinct destination ports probed in window.
            spike_multiplier: Ratio above baseline average to trigger traffic spike alert.
        """
        self.time_window = time_window
        self.pps_threshold = pps_threshold
        self.syn_burst_threshold = syn_burst_threshold
        self.port_scan_threshold = port_scan_threshold
        self.spike_multiplier = spike_multiplier

        # Sliding window tracking buffers
        self.packet_times: deque = deque()
        self.byte_history: deque = deque()  # (timestamp, bytes)
        self.syn_tracker: Dict[str, deque] = defaultdict(deque)  # src_ip -> deque of timestamps
        self.port_scan_tracker: Dict[str, Dict[int, float]] = defaultdict(dict)  # src_ip -> {dst_port: timestamp}
        self.protocol_tracker: deque = deque()  # (timestamp, protocol)

        # Baseline running averages
        self.baseline_rates: deque = deque(maxlen=60)  # past 60 windows of rate
        self.alerts: List[Dict[str, Any]] = []
        self._last_alert_cooldown: Dict[str, float] = {}  # signature -> last_alert_time

    def set_thresholds(
        self,
        time_window: Optional[float] = None,
        pps_threshold: Optional[int] = None,
        syn_burst_threshold: Optional[int] = None,
        port_scan_threshold: Optional[int] = None,
        spike_multiplier: Optional[float] = None
    ) -> None:
        """Dynamically update detection thresholds."""
        if time_window is not None:
            self.time_window = max(1.0, float(time_window))
        if pps_threshold is not None:
            self.pps_threshold = int(pps_threshold)
        if syn_burst_threshold is not None:
            self.syn_burst_threshold = int(syn_burst_threshold)
        if port_scan_threshold is not None:
            self.port_scan_threshold = int(port_scan_threshold)
        if spike_multiplier is not None:
            self.spike_multiplier = max(1.5, float(spike_multiplier))

    def reset(self) -> None:
        """Clear detection buffers and alerts."""
        self.packet_times.clear()
        self.byte_history.clear()
        self.syn_tracker.clear()
        self.port_scan_tracker.clear()
        self.protocol_tracker.clear()
        self.baseline_rates.clear()
        self.alerts.clear()
        self._last_alert_cooldown.clear()

    def _should_trigger_alert(self, signature: str, cooldown_sec: float = 4.0) -> bool:
        """Prevent alert flooding for identical continuous events."""
        now = time.time()
        last = self._last_alert_cooldown.get(signature, 0.0)
        if now - last >= cooldown_sec:
            self._last_alert_cooldown[signature] = now
            return True
        return False

    def evaluate_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluate incoming packet against multi-point anomaly detection rules.
        Returns list of newly generated alert records (if any).
        """
        ts = packet.get("timestamp", time.time())
        size = packet.get("packet_size", 0)
        src_ip = packet.get("src_ip", "0.0.0.0")
        dst_ip = packet.get("dst_ip", "0.0.0.0")
        protocol = packet.get("protocol", "Other")
        flags = packet.get("tcp_flags", "")
        dst_port = packet.get("dst_port")

        cutoff = ts - self.time_window
        new_alerts = []

        # 1. Update sliding window buffers
        self.packet_times.append(ts)
        self.byte_history.append((ts, size))
        self.protocol_tracker.append((ts, protocol))

        # Evict old entries
        while self.packet_times and self.packet_times[0] < cutoff:
            self.packet_times.popleft()
        while self.byte_history and self.byte_history[0][0] < cutoff:
            self.byte_history.popleft()
        while self.protocol_tracker and self.protocol_tracker[0][0] < cutoff:
            self.protocol_tracker.popleft()

        current_pps = len(self.packet_times) / self.time_window
        current_bps = sum(b for _, b in self.byte_history) / self.time_window

        # Maintain baseline for statistical anomaly detection
        self.baseline_rates.append(current_pps)

        # -------------------------------------------------------------
        # RULE 1: Unusually High Packet Rate
        # -------------------------------------------------------------
        if current_pps > self.pps_threshold:
            sig = "high_packet_rate"
            if self._should_trigger_alert(sig, cooldown_sec=5.0):
                alert = {
                    "alert_id": len(self.alerts) + 1,
                    "timestamp": ts,
                    "time_formatted": packet.get("time_formatted", time.strftime("%H:%M:%S")),
                    "category": "High Packet Rate",
                    "severity": "Medium",
                    "observed_evidence": f"Observed {round(current_pps, 1)} pkts/sec over {self.time_window}s window (Threshold: {self.pps_threshold} pkts/sec)",
                    "explanation": "Potentially suspicious network activity detected: packet generation rate exceeded baseline operating limit. Could indicate automated script or network stress test.",
                    "recommended_investigation": "Inspect top communicating IP addresses and active socket connections to determine originating application.",
                    "source_ip": src_ip,
                    "destination_ip": dst_ip
                }
                self.alerts.append(alert)
                new_alerts.append(alert)

        # -------------------------------------------------------------
        # RULE 2: Sudden Traffic Spike (Statistical deviation)
        # -------------------------------------------------------------
        if len(self.baseline_rates) >= 20:
            avg_rate = sum(self.baseline_rates) / len(self.baseline_rates)
            if avg_rate > 5 and current_pps > (avg_rate * self.spike_multiplier):
                sig = "sudden_traffic_spike"
                if self._should_trigger_alert(sig, cooldown_sec=6.0):
                    alert = {
                        "alert_id": len(self.alerts) + 1,
                        "timestamp": ts,
                        "time_formatted": packet.get("time_formatted", time.strftime("%H:%M:%S")),
                        "category": "Sudden Traffic Spike",
                        "severity": "High",
                        "observed_evidence": f"Instantaneous rate {round(current_pps, 1)} pkts/sec is {round(current_pps / avg_rate, 1)}x higher than moving baseline ({round(avg_rate, 1)} pkts/sec)",
                        "explanation": "Potentially suspicious network activity detected: rapid surge in network throughput. Consistent with bursty data exfiltration, large file dumps, or DoS flood attempts.",
                        "recommended_investigation": "Correlate with active file transfers or benchmark utilities. Identify participating endpoints.",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # -------------------------------------------------------------
        # RULE 3: SYN Flood Indicator (High rate of SYN packets)
        # -------------------------------------------------------------
        if protocol == "TCP" and "SYN" in flags and "ACK" not in flags and src_ip != "N/A":
            syn_q = self.syn_tracker[src_ip]
            syn_q.append(ts)
            while syn_q and syn_q[0] < cutoff:
                syn_q.popleft()

            if len(syn_q) >= self.syn_burst_threshold:
                sig = f"syn_burst_{src_ip}"
                if self._should_trigger_alert(sig, cooldown_sec=5.0):
                    alert = {
                        "alert_id": len(self.alerts) + 1,
                        "timestamp": ts,
                        "time_formatted": packet.get("time_formatted", time.strftime("%H:%M:%S")),
                        "category": "SYN Flood Indicator",
                        "severity": "High",
                        "observed_evidence": f"Host {src_ip} transmitted {len(syn_q)} TCP SYN packets without establishing handshakes within {self.time_window}s (Threshold: {self.syn_burst_threshold})",
                        "explanation": "Potentially suspicious network activity detected: excessive half-open TCP connection requests. Typical signature of SYN flood or aggressive port sweeps.",
                        "recommended_investigation": "Check if destination server back-log queue is exhausted. Verify whether source IP belongs to an authorized scanning tool or legitimate client.",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # -------------------------------------------------------------
        # RULE 4: Port Scan Indicator (Multiple destination ports probed)
        # -------------------------------------------------------------
        if protocol == "TCP" and dst_port and src_ip != "N/A":
            port_dict = self.port_scan_tracker[src_ip]
            port_dict[dst_port] = ts
            # Clean expired port accesses
            expired_ports = [p for p, t in port_dict.items() if t < cutoff]
            for p in expired_ports:
                del port_dict[p]

            if len(port_dict) >= self.port_scan_threshold:
                sig = f"port_scan_{src_ip}"
                if self._should_trigger_alert(sig, cooldown_sec=6.0):
                    scanned_ports = sorted(list(port_dict.keys()))[:8]
                    alert = {
                        "alert_id": len(self.alerts) + 1,
                        "timestamp": ts,
                        "time_formatted": packet.get("time_formatted", time.strftime("%H:%M:%S")),
                        "category": "Port Scan Indicator",
                        "severity": "High",
                        "observed_evidence": f"Host {src_ip} probed {len(port_dict)} distinct destination ports within {self.time_window}s (Ports probed include: {scanned_ports}...)",
                        "explanation": "Potentially suspicious network activity detected: sequential or distributed port probing. Characteristic signature of network discovery tools (e.g., Nmap, netcat).",
                        "recommended_investigation": "Identify process owning source IP. Review host access logs and ensure unnecessary ports are firewalled.",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        # -------------------------------------------------------------
        # RULE 5: ICMP Ping Flood / Protocol Shift Indicator
        # -------------------------------------------------------------
        if protocol == "ICMP" and len(self.protocol_tracker) >= 30:
            icmp_count = sum(1 for _, p in self.protocol_tracker if p == "ICMP")
            icmp_ratio = icmp_count / len(self.protocol_tracker)
            if icmp_ratio >= 0.85 and icmp_count >= 25:
                sig = f"icmp_flood_{src_ip}"
                if self._should_trigger_alert(sig, cooldown_sec=6.0):
                    alert = {
                        "alert_id": len(self.alerts) + 1,
                        "timestamp": ts,
                        "time_formatted": packet.get("time_formatted", time.strftime("%H:%M:%S")),
                        "category": "ICMP Echo Flood Indicator",
                        "severity": "Medium",
                        "observed_evidence": f"ICMP packets comprise {round(icmp_ratio * 100, 1)}% of all traffic ({icmp_count} echo packets in {self.time_window}s)",
                        "explanation": "Potentially suspicious network activity detected: abnormal concentration of control protocol packets. Consistent with Ping Flood or continuous network sweeps.",
                        "recommended_investigation": "Confirm whether ICMP echo tests or network diagnostics are intentionally running between test laptops.",
                        "source_ip": src_ip,
                        "destination_ip": dst_ip
                    }
                    self.alerts.append(alert)
                    new_alerts.append(alert)

        return new_alerts

    def get_all_alerts(self) -> List[Dict[str, Any]]:
        """Return full history of generated alerts."""
        return list(self.alerts)

    def get_alert_summary(self) -> Dict[str, Any]:
        """Return categorical count and severity statistics."""
        severity_counts = {"Low": 0, "Medium": 0, "High": 0}
        category_counts = defaultdict(int)
        for a in self.alerts:
            sev = a.get("severity", "Medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            cat = a.get("category", "General")
            category_counts[cat] += 1

        return {
            "total_alerts": len(self.alerts),
            "severity_breakdown": severity_counts,
            "category_breakdown": dict(category_counts),
        }
