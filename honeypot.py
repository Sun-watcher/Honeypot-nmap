#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, Ether, sendp
import random
import datetime

LOG_FILE = "honeypot_hits.log"

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

        # --- Répondre à un SYN ---
        if flags == "S":
            if dport in OPEN_PORTS:
                log_hit("SYN", src_ip, sport, dport)
            
                my_seq = random.randint(0, 0xFFFF_FFFF)
                their_seq = pkt[TCP].seq + 1

                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="SA",
                          seq=my_seq, ack=their_seq)
                sendp(ether/ip/tcp)
            else:
                log_hit("RST", src_ip, sport, dport)
            
                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=pkt[TCP].seq + 1)
                sendp(ether/ip/tcp, iface=INTERFACE)

        # --- Répondre avec bannière après ACK ---
        elif flags == "A":
            log_hit("ACK", src_ip, sport, dport)
        
            my_seq, their_seq = pkt[TCP].ack, pkt[TCP].seq
            banner = OPEN_PORTS.get(sport)
            if banner:
                my_seq += len(banner)
                
                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=sport, dport=dport, flags="PA",
                          seq=my_seq, ack=their_seq)
                sendp(ether/ip/tcp/banner, iface=INTERFACE)

        # --- FIN ---
        elif "F" in flags:
            log_hit("FIN", src_ip, sport, dport)
            
            my_seq, their_seq = pkt[TCP].ack, pkt[TCP].seq
            their_seq += 1  # on a reçu un FIN (1 octet)

            ether = Ether(src=dst_mac, dst=src_mac)
            # ACK du FIN reçu
            ip_ack = IP(src=dst_ip, dst=src_ip, ttl=64)
            tcp_ack = TCP(sport=sport, dport=dport, flags="A",
                          seq=my_seq, ack=their_seq)
            sendp(ether/ip_ack/tcp_ack)

            # Notre propre FIN pour fermer côté serveur
            ip_fin = IP(src=dst_ip, dst=src_ip, ttl=64)
            tcp_fin = TCP(sport=sport, dport=dport, flags="FA",
                          seq=my_seq, ack=their_seq)
            sendp(ether/ip_fin/tcp_fin, iface=INTERFACE)

if __name__ == "__main__":
    print("[*] Honeypot leurre Nmap démarré...")
    sniff(filter="tcp", prn=handle_packet, store=0, iface=INTERFACE)
