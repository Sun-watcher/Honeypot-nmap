#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, Ether, sendp
import datetime

LOG_FILE = "honeypot_hits_stateless.log"

OPEN_PORTS = {
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<h1>Hello</h1>",
    7898: b"Hello fake port opened"
}

INTERFACE = "eth0" 

def log_hit(action, src_ip, src_port, dst_port):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {action} from {src_ip}:{src_port} -> port {dst_port}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def handle_packet(pkt):
    if Ether in pkt and IP in pkt and TCP in pkt:
        src_mac = pkt[Ether].src
        dst_mac = pkt[Ether].dst
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        # Stateless : on répond uniquement au SYN par un SYN-ACK fixe
        if flags == "S":
            if dport in OPEN_PORTS:
                log_hit("SYN", src_ip, sport, dport)

                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                # Seq et ack fixes, arbitraires
                tcp = TCP(sport=dport, dport=sport, flags="SA",
                          seq=1000, ack=pkt[TCP].seq + 1)
                sendp(ether/ip/tcp, iface=INTERFACE)
            else:
                log_hit("RST", src_ip, sport, dport)

                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=pkt[TCP].seq + 1)
                sendp(ether/ip/tcp, iface=INTERFACE)
        else:
            # On ignore tout autre paquet (ACK, FIN, PSH...)
            pass

if __name__ == "__main__":
    print("[*] Honeypot stateless démarré...")
    sniff(filter="tcp", prn=handle_packet, store=0, iface=INTERFACE)
