from scapy import *
import scapy.all as scapy
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
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
is_mac = macdedecter("192.168.17.23")
def monitorMOD():
    init(autoreset=True)

    def ts_now():
        """Şu anki zamanı döndürür."""
        return datetime.now().strftime("%H:%M:%S")

    def get_packet_info(pkt):
        """Paket içeriğindeki ham veriyi güvenli bir string'e çevirir."""
        if pkt.haslayer(scapy.Raw):
            payload = pkt[scapy.Raw].load
            return "".join([chr(b) if 32 <= b < 127 else "." for b in payload[:50]])
        return "No Raw Data"

    def scan_my_network(ip):
        """Belirli bir IP için MAC adresini sorgular (ARP Scan)."""
        print(Fore.CYAN + f"[*] {ip} için MAC adresi sorgulanıyor...")
        arp_request_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        combined_packet = broadcast_packet / arp_request_packet
        
        answered_list = scapy.srp(combined_packet, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None

    def pkt_handler(pkt):
        """Yakalanan her paketi analiz eder ve ekrana/dosyaya yazar."""
        proto, src_ip, dst_ip, info, color = "OTHER", "N/A", "N/A", "", Fore.WHITE

        # ARP Katmanı Analizi
        if pkt.haslayer(ARP):
            proto = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            info = f"Who has {dst_ip}? Tell {src_ip}"
            color = Fore.YELLOW

        # IP Katmanı Analizi (TCP, UDP, ICMP)
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

        # Çıktıyı Formatla
        log_entry = f"[{ts_now()}] [{proto:5}] {src_ip} -> {dst_ip} | {info}"
        
        # Ekrana Renkli Yazdır
        print(f"{color}{log_entry}{Style.RESET_ALL}")

        # Dosyaya Kaydet
        with open("network_dump.txt", "a", encoding="utf-8") as f:
            f.write(log_entry + "\n")

    def monitor(interface=None):
        """Sniffer'ı başlatır."""
        print(Fore.GREEN + f"[*] Dinleme başlatıldı... (Kayıt: network_dump.txt)")
        print("-" * 85)
        try:
            scapy.sniff(iface=interface, prn=pkt_handler, store=0)
        except PermissionError:
            print(Fore.RED + "[!] HATA: Terminali 'Yönetici Olarak Çalıştır' modunda açın.")
        except Exception as e:
            print(Fore.RED + f"[!] Beklenmedik Hata: {e}")

    if __name__ == "__main__":
        # Önce bir test taraması yap (İsteğe bağlı)
        target_ip = "192.168.1.1" # Kendi gateway IP'nle değiştirebilirsin
        mac = scan_my_network(target_ip)
        if mac:
            print(Fore.GREEN + f"[+] Hedef MAC: {mac}")
        
        # Ardından trafiği izlemeye başla
        monitor()

   