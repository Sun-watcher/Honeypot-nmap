#!/usr/bin/env python3
from scapy.all import sniff, IP, TCP, Ether, sendp
import random
import datetime
import threading
import time

LOG_FILE = "honeypot_hits.log"
INTERFACE = "eth0"

OPEN_PORTS = {
    22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.4\r\n",
    80: b"HTTP/1.1 200 OK\r\nServer: Apache\r\n\r\n<h1>Hello</h1>",
    7898: b"Hello fake port opened"
}

# Etat minimal des connexions : clé = (src_ip, src_port, dst_port)
# Valeur = dict { 'state': "SYN_RECEIVED" ou "ESTABLISHED", 'my_seq': int, 'their_seq': int, 'last_seen': timestamp }
connections = {}

# Durée avant timeout d'une connexion (en secondes)
CONN_TIMEOUT = 60

# Throttling simple : max 10 paquets par IP dans la fenêtre TIME_WINDOW
PACKET_LIMIT = 10
TIME_WINDOW = 5
packet_times = {}

lock = threading.Lock()

def log_hit(action, src_ip, src_port, dst_port):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] {action} from {src_ip}:{src_port} -> port {dst_port}"
    print(log_entry)
    with open(LOG_FILE, "a") as f:
        f.write(log_entry + "\n")

def clean_connections():
    """Thread qui supprime les connexions inactives."""
    while True:
        now = time.time()
        with lock:
            to_delete = [key for key, val in connections.items() if now - val['last_seen'] > CONN_TIMEOUT]
            for key in to_delete:
                del connections[key]
        time.sleep(10)

def throttle_ip(ip):
    """Retourne True si on doit drop le paquet (flood), sinon False."""
    now = time.time()
    times = packet_times.get(ip, [])
    times = [t for t in times if now - t < TIME_WINDOW]
    times.append(now)
    packet_times[ip] = times
    return len(times) > PACKET_LIMIT

def handle_packet(pkt):
    if not (Ether in pkt and IP in pkt and TCP in pkt):
        return

    src_mac = pkt[Ether].src
    dst_mac = pkt[Ether].dst
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    flags = pkt[TCP].flags

    # Throttle anti-flood
    if throttle_ip(src_ip):
        # Optionnel : log flood ou juste silent drop
        return

    # Bits flags TCP
    SYN = 0x02
    ACK = 0x10
    FIN = 0x01
    RST = 0x04

    key = (src_ip, sport, dport)

    with lock:
        conn = connections.get(key)

        # --- SYN (nouvelle connexion) ---
        if flags & SYN and not flags & ACK:
            if dport in OPEN_PORTS:
                log_hit("SYN", src_ip, sport, dport)

                my_seq = random.randint(0, 0xFFFFFFFF)
                their_seq = pkt[TCP].seq + 1

                # Enregistrer état SYN_RECEIVED
                connections[key] = {
                    'state': 'SYN_RECEIVED',
                    'my_seq': my_seq,
                    'their_seq': their_seq,
                    'last_seen': time.time()
                }

                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="SA",
                          seq=my_seq, ack=their_seq)
                sendp(ether/ip/tcp, iface=INTERFACE)
            else:
                # Port fermé => RST
                log_hit("RST", src_ip, sport, dport)

                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                # seq = 0, ack = seq+1 si SYN est reçu (ici oui)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=pkt[TCP].seq + 1)
                sendp(ether/ip/tcp, iface=INTERFACE)

        # --- ACK (potentiellement fin handshake ou data) ---
        elif flags & ACK:
            if conn is not None:
                # Mettre à jour dernier timestamp
                conn['last_seen'] = time.time()

                # Si on attendait handshake final SYN+ACK -> ACK (état SYN_RECEIVED)
                if conn['state'] == 'SYN_RECEIVED':
                    # Handshake terminé
                    conn['state'] = 'ESTABLISHED'

                    log_hit("ACK handshake", src_ip, sport, dport)

                elif conn['state'] == 'ESTABLISHED':
                    # Connexion établie, envoyer la bannière si data attendue
                    banner = OPEN_PORTS.get(dport)
                    if banner:
                        my_seq = conn['my_seq']
                        their_seq = pkt[TCP].seq
                        
                        # Envoi bannière avec flag PSH+ACK
                        ether = Ether(src=dst_mac, dst=src_mac)
                        ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                        tcp = TCP(sport=dport, dport=sport, flags="PA",
                                  seq=my_seq, ack=their_seq)
                        sendp(ether/ip/tcp/banner, iface=INTERFACE)

                        # Mise à jour de notre séquence
                        conn['my_seq'] += len(banner)
                        log_hit("BANNIERE envoyée", src_ip, sport, dport)
                else:
                    # Etat inconnu ou pas pris en charge
                    pass

            else:
                # Pas de connexion, envoie RST
                log_hit("RST (ACK sans connexion)", src_ip, sport, dport)
                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=0)
                sendp(ether/ip/tcp, iface=INTERFACE)

        # --- FIN ---
        elif flags & FIN:
            if conn is not None:
                log_hit("FIN", src_ip, sport, dport)
                conn['last_seen'] = time.time()

                my_seq = conn['my_seq']
                their_seq = pkt[TCP].seq + 1

                ether = Ether(src=dst_mac, dst=src_mac)

                # ACK du FIN reçu
                ip_ack = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp_ack = TCP(sport=dport, dport=sport, flags="A",
                              seq=my_seq, ack=their_seq)
                sendp(ether/ip_ack/tcp_ack, iface=INTERFACE)

                # Notre FIN pour fermer côté serveur
                ip_fin = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp_fin = TCP(sport=dport, dport=sport, flags="FA",
                              seq=my_seq, ack=their_seq)
                sendp(ether/ip_fin/tcp_fin, iface=INTERFACE)

                # Supprimer la connexion
                del connections[key]
            else:
                # FIN reçu sans connexion connue
                log_hit("FIN sans connexion", src_ip, sport, dport)
                ether = Ether(src=dst_mac, dst=src_mac)
                ip = IP(src=dst_ip, dst=src_ip, ttl=64)
                tcp = TCP(sport=dport, dport=sport, flags="R",
                          seq=0, ack=0)
                sendp(ether/ip/tcp, iface=INTERFACE)

        # --- RST ---
        elif flags & RST:
            # Nettoyer la connexion si existante
            if conn is not None:
                log_hit("RST reçu", src_ip, sport, dport)
                del connections[key]

if __name__ == "__main__":
    print("[*] Honeypot stateful démarré...")

    # Lancer thread de nettoyage des connexions
    cleaner_thread = threading.Thread(target=clean_connections, daemon=True)
    cleaner_thread.start()

    sniff(filter="tcp", prn=handle_packet, store=0, iface=INTERFACE)

