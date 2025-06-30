from scapy.all import sniff, IP, TCP, UDP, DNS

def packet_callback(pkt):
    if IP in pkt:
        proto = "TCP" if TCP in pkt else "UDP" if UDP in pkt else "IP"
        src = pkt[IP].src
        dst = pkt[IP].dst
        print(f"[{proto}] {src} -> {dst}")
    elif DNS in pkt:
        print(f"[DNS] Query: {pkt[DNS].qd.qname.decode()}")

def run():
    print("[*] Starting packet capture... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=0)
