"""
NetVision - Sample PCAP File Generator
Generates a realistic offline PCAP file containing TCP 3-way handshakes,
HTTP traffic, DNS lookups, ICMP pings, and simulated port scans for offline analysis testing.
"""

import os
from pathlib import Path

try:
    from scapy.all import wrpcap, Ether, IP, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


def generate_sample_pcap(output_path: str) -> bool:
    """Generate sample PCAP file with Scapy."""
    if not SCAPY_AVAILABLE:
        print("Scapy not available to generate PCAP.")
        return False

    packets = []
    base_time = 1700000000.0

    ip_laptop_a = "192.168.1.10"
    ip_laptop_b = "192.168.1.25"
    ip_gateway = "192.168.1.1"
    ip_dns = "8.8.8.8"
    ip_web = "93.184.216.34"  # example.com

    # 1. DNS Query & Response
    dns_q = Ether()/IP(src=ip_laptop_a, dst=ip_dns)/UDP(sport=54321, dport=53)/Raw(load=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01")
    dns_q.time = base_time + 0.1
    packets.append(dns_q)

    dns_r = Ether()/IP(src=ip_dns, dst=ip_laptop_a)/UDP(sport=53, dport=54321)/Raw(load=b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04]\xb8\xd8\"")
    dns_r.time = base_time + 0.13
    packets.append(dns_r)

    # 2. ICMP Ping Request & Reply
    icmp_req = Ether()/IP(src=ip_laptop_a, dst=ip_gateway)/ICMP(type=8, code=0, id=1, seq=1)/Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    icmp_req.time = base_time + 0.5
    packets.append(icmp_req)

    icmp_rep = Ether()/IP(src=ip_gateway, dst=ip_laptop_a)/ICMP(type=0, code=0, id=1, seq=1)/Raw(load=b"abcdefghijklmnopqrstuvwabcdefghi")
    icmp_rep.time = base_time + 0.52
    packets.append(icmp_rep)

    # 3. TCP 3-Way Handshake (Laptop A -> Laptop B on port 65432)
    client_port = 51234
    syn = Ether()/IP(src=ip_laptop_a, dst=ip_laptop_b)/TCP(sport=client_port, dport=65432, flags="S", seq=1000)
    syn.time = base_time + 1.0
    packets.append(syn)

    syn_ack = Ether()/IP(src=ip_laptop_b, dst=ip_laptop_a)/TCP(sport=65432, dport=client_port, flags="SA", seq=2000, ack=1001)
    syn_ack.time = base_time + 1.015
    packets.append(syn_ack)

    ack = Ether()/IP(src=ip_laptop_a, dst=ip_laptop_b)/TCP(sport=client_port, dport=65432, flags="A", seq=1001, ack=2001)
    ack.time = base_time + 1.02
    packets.append(ack)

    # Data transfer
    data = Ether()/IP(src=ip_laptop_a, dst=ip_laptop_b)/TCP(sport=client_port, dport=65432, flags="PA", seq=1001, ack=2001)/Raw(load=b"NetVision Protocol Test Data Stream Chunk")
    data.time = base_time + 1.05
    packets.append(data)

    data_ack = Ether()/IP(src=ip_laptop_b, dst=ip_laptop_a)/TCP(sport=65432, dport=client_port, flags="A", seq=2001, ack=1043)
    data_ack.time = base_time + 1.06
    packets.append(data_ack)

    # FIN teardown
    fin = Ether()/IP(src=ip_laptop_a, dst=ip_laptop_b)/TCP(sport=client_port, dport=65432, flags="FA", seq=1043, ack=2001)
    fin.time = base_time + 1.10
    packets.append(fin)

    fin_ack = Ether()/IP(src=ip_laptop_b, dst=ip_laptop_a)/TCP(sport=65432, dport=client_port, flags="A", seq=2001, ack=1044)
    fin_ack.time = base_time + 1.11
    packets.append(fin_ack)

    # 4. Simulated Port Scan
    scanner_ip = "192.168.1.99"
    scan_ports = [21, 22, 23, 80, 443, 3389, 8080, 65432, 9000]
    for idx, p in enumerate(scan_ports):
        p_pkt = Ether()/IP(src=scanner_ip, dst=ip_laptop_a)/TCP(sport=40000+idx, dport=p, flags="S", seq=500+idx)
        p_pkt.time = base_time + 2.0 + (idx * 0.05)
        packets.append(p_pkt)

    output = Path(output_path).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), packets)
    print(f"[+] Generated {len(packets)} sample packets in {output}")
    return True


if __name__ == "__main__":
    out = os.path.join(os.path.dirname(__file__), "sample_traffic.pcap")
    generate_sample_pcap(out)
