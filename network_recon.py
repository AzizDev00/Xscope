import scapy.all as scapy
import socket

def arp_scan(ip_range):
    arp_req = scapy.ARP(pdst=ip_range)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp_req
    result = scapy.srp(packet, timeout=2, verbose=0)[0]

    print("Discovered Hosts:")
    for sent, received in result:
        print(f"{received.psrc} - {received.hwsrc}")
        port_scan(received.psrc)

def port_scan(ip):
    ports = [21, 22, 23, 80, 443, 445]
    for port in ports:
        try:
            sock = socket.socket()
            sock.settimeout(0.5)
            sock.connect((ip, port))
            print(f"  [OPEN] Port {port}")
            sock.close()
        except:
            pass

def run():
    target = input("Enter IP range (e.g., 192.168.1.0/24): ")
    arp_scan(target)
