from scapy import *
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
import sys
from scapy.layers.l2 import ARP, Ether
from colorama import init, Fore, Style
from datetime import datetime

def macdedecter(ip_address2):
    def scan_my_network(ip):
        arp_request_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet/arp_request_packet
        (answered_list, unanswered_list) = scapy.srp(combined_packet, timeout=1, verbose=False)
        if answered_list:
            ismac = answered_list[0][1].hwsrc
            return ismac
        else:
            print(f"{ip} mac adress not dedected")
            return None
    target_mac = scan_my_network(ip_address2)
    return target_mac
def monitorMOD():
    
    init(autoreset=True)

    def ts_now():
        
        return datetime.now().strftime("%H:%M:%S")

    def get_packet_info(pkt):
       
        if pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load
            return "".join([chr(b) if 32 <= b < 127 else "." for b in payload[:50]])
        return "No Raw Data"

    def scan_my_network(ip):
        
        print(Fore.CYAN + f"[*] {ip}  MAC seeking")
        arp_request_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet / arp_request_packet
        
        answered_list = scapy.srp(combined_packet, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def pkt_handler(pkt):
        
        proto, src_ip, dst_ip, info, color = "OTHER", "N/A", "N/A", "", Fore.WHITE

        
        if pkt.haslayer(ARP):
            proto = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            info = f"Who has {dst_ip}? Tell {src_ip}"
            color = Fore.YELLOW

        
        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            if pkt.haslayer(TCP):
                proto = "TCP"
                info = f"{pkt[TCP].sport} -> {pkt[TCP].dport} [{pkt[TCP].flags}] | {get_packet_info(pkt)}"
                color = Fore.CYAN
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info = f"{pkt[UDP].sport} -> {pkt[UDP].dport} | {get_packet_info(pkt)}"
                color = Fore.MAGENTA
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"Type: {pkt[ICMP].type}"
                color = Fore.GREEN

       
        log_entry = f"[{ts_now()}] [{proto:5}] {src_ip} -> {dst_ip} | {info}"
        
        
        print(f"{color}{log_entry}{Style.RESET_ALL}")

       
        with open("sniff.log", "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")

    def monitor(interface=None):
        
        print(Fore.GREEN + f"[*] sniffing (logging: sniff.log)")
        print("-" * 85)
        try:
            scapy.sniff(iface=interface, prn=pkt_handler, store=0)
        except PermissionError:
            print(Fore.RED + "[!] Error: Start admin or root.")
        except Exception as e:
            print(Fore.RED + f"[!] Critical Error {e}")

    if __name__ == "__main__":
        
        target_ip = "127.0.0.1" 
        mac = scan_my_network(target_ip)
        if mac:
            print(Fore.GREEN + f"[+]Target MAC: {mac}")
        
        # Ardından trafiği izlemeye başla
        monitor()
def sender(target, port=None, protocol='tcp', **kwargs):
    """
    A highly flexible packet sender supporting multiple protocols.
    :param target: IP or MAC address depending on the protocol.
    :param port: Destination port (ignored for protocols like ARP/ICMP).
    :param protocol: The protocol to use (tcp, udp, icmp, arp, sctp, dns, igmp).
    :param kwargs: Additional fields for Scapy layers (e.g., payload="hello").
    """
    protocol = protocol.lower().strip()
    pkt = None
    
    try:
        # --- Layer 2 Protocols ---
        if protocol == "arp":
            # Target here is the destination IP to resolve
            pkt = ARP(pdst=target)
            print(f"[INFO] Crafting ARP Request for {target}")

        # --- Layer 3/4 Protocols ---
        else:
            ip_layer = IP(dst=target)
            
            if protocol == "tcp":
                pkt = ip_layer / TCP(dport=int(port), flags=kwargs.get("flags", "S"))
            
            elif protocol == "udp":
                pkt = ip_layer / UDP(dport=int(port))
            
            elif protocol == "icmp":
                pkt = ip_layer / ICMP(type=8) # Echo Request
            
            elif protocol == "sctp":
                # Common in telecom and signaling
                pkt = ip_layer / SCTP(dport=int(port))
            
            elif protocol == "dns":
                # Defaulting to a standard A-record query for google.com
                query = kwargs.get("query", "google.com")
                pkt = ip_layer / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query))
            
            elif protocol == "igmp":
                pkt = ip_layer / IGMP()
            
            else:
                print(f"[ERROR] Protocol '{protocol}' is not implemented yet.")
                return

        # Attach raw payload if provided
        if "payload" in kwargs and pkt:
            pkt = pkt / Raw(load=kwargs["payload"])

        # Sending the packet
        if protocol == "arp":
            # ARP uses sendp (Layer 2)
            sendp(Ether(dst="ff:ff:ff:ff:ff:ff")/pkt, verbose=False)
        else:
            send(pkt, verbose=False)
            
        print(f"[SUCCESS] {protocol.upper()} packet sent to {target}")

    except Exception as e:
        print(f"[FAILURE] Error sending {protocol}: {e}")
