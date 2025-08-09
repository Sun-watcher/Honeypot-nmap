#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, send
import random

OPEN_PORTS = {
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<h1>Hello</h1>"
}

sessions = {} 

def handle_packet(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        flags = pkt[TCP].flags

        # --- Répondre à un SYN ---
        if flags == "S":
            if dport in OPEN_PORTS:
                my_seq = random.randint(0, 0xFFFF_FFFF)
                their_seq = pkt[TCP].seq + 1

                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="SA",
                          seq=my_seq, ack=their_seq)
                send(ip/tcp)
            else:
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=pkt[TCP].seq + 1)
                send(ip/tcp)

        # --- Répondre avec bannière après ACK ---
        elif flags == "A":
            my_seq, their_seq = pkt[TCP].ack, pkt[TCP].seq
            banner = OPEN_PORTS[sport]
            if banner:
                my_seq += len(banner)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=sport, dport=dport, flags="PA",
                          seq=my_seq, ack=their_seq)
                send(ip/tcp/banner)

        # --- FIN ---
        elif "F" in flags:
            my_seq, their_seq = pkt[TCP].ack, pkt[TCP].seq
            their_seq += 1  # on a reçu un FIN (1 octet)
            
            # ACK du FIN reçu
            ip_ack = IP(src=dst_ip, dst=src_ip, ttl=64)
            tcp_ack = TCP(sport=sport, dport=dport, flags="A",
                          seq=my_seq, ack=their_seq)
            send(ip_ack/tcp_ack)

            # Notre propre FIN pour fermer côté serveur
            ip_fin = IP(src=dst_ip, dst=src_ip, ttl=64)
            tcp_fin = TCP(sport=sport, dport=dport, flags="FA",
                          seq=my_seq, ack=their_seq)
            send(ip_fin/tcp_fin, verbose=False)

if __name__ == "__main__":
    print("[*] Honeypot leurre Nmap démarré...")
    sniff(filter="tcp", prn=handle_packet, store=0)
