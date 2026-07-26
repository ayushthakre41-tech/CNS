import os
import csv
import time
import random
import threading
from datetime import datetime

class PacketSniffer:
    """
    Dual-mode Network Packet Interceptor:
    1. Real Socket Sniffer: Uses Scapy on TCP port 5000 when driver/admin privileges are present.
    2. Simulated Sniffer Fallback: Intercepts Flask transactions and logs realistic TCP segment metadata
       (Handshake, Payload Transmits, ACKs, Teardowns) to CSV without requiring admin access.
    """

    def __init__(self, port=5000, csv_path=None):
        self.port = port
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.reports_dir = os.path.join(self.base_dir, "reports")
        os.makedirs(self.reports_dir, exist_ok=True)
        
        self.csv_path = csv_path or os.path.join(self.reports_dir, "captured_packets.csv")
        self.mode = "simulated"  # Default fallback mode
        self.running = False
        self.thread = None
        self._lock = threading.Lock()
        
        self._init_csv()

    def _init_csv(self):
        """Initializes CSV file with header if it doesn't exist."""
        if not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0:
            with open(self.csv_path, mode="w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Timestamp",
                    "Source IP",
                    "Destination IP",
                    "Source Port",
                    "Destination Port",
                    "Protocol",
                    "Packet Size",
                    "Traffic Direction"
                ])

    def start(self):
        """Attempts real Scapy sniffing in a background thread, falling back to simulation if needed."""
        self.running = True
        self.thread = threading.Thread(target=self._run_scapy_sniffer, daemon=True)
        self.thread.start()

    def _run_scapy_sniffer(self):
        """Attempts to initialize raw socket sniffing via Scapy."""
        try:
            from scapy.all import sniff, TCP, IP
            print(f"[PacketSniffer] Attempting Scapy live capture on TCP port {self.port}...")

            def process_packet(pkt):
                if not self.running:
                    return
                if pkt.haslayer(TCP) and pkt.haslayer(IP):
                    ip_src = pkt[IP].src
                    ip_dst = pkt[IP].dst
                    sport = pkt[TCP].sport
                    dport = pkt[TCP].dport
                    size = len(pkt)
                    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
                    direction = "Client -> Relay" if dport == self.port else "Relay -> Client"
                    
                    self.log_packet(ts, ip_src, ip_dst, sport, dport, "TCP", size, direction)

            # Try sniffing 1 packet to test permissions
            sniff(filter=f"tcp port {self.port}", prn=process_packet, count=1, timeout=2)
            self.mode = "real"
            print(f"[PacketSniffer] Real socket sniffing ACTIVE on TCP port {self.port}.")
            
            # Continuous sniffing
            sniff(filter=f"tcp port {self.port}", prn=process_packet, stop_filter=lambda p: not self.running)

        except Exception as e:
            self.mode = "simulated"
            print(f"[PacketSniffer] Scapy raw socket capture unavailable ({str(e)}). Running in SIMULATED Mode.")

    def log_packet(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, size, direction):
        """Thread-safe append of captured packet metadata to CSV."""
        with self._lock:
            try:
                with open(self.csv_path, mode="a", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        timestamp,
                        src_ip,
                        dst_ip,
                        src_port,
                        dst_port,
                        protocol,
                        size,
                        direction
                    ])
            except Exception as e:
                print(f"[PacketSniffer Error] Could not write packet log: {str(e)}")

    def simulate_http_transaction(self, client_ip="127.0.0.1", is_send=True, payload_size=300):
        """
        Generates realistic TCP segment metadata for an HTTP request/response exchange.
        Simulates: SYN, SYN-ACK, ACK, Data Payload (HTTP POST/GET), ACK, FIN.
        """
        server_ip = "127.0.0.1"
        server_port = self.port
        client_port = random.randint(49152, 65535)

        base_time = time.time()
        
        def fmt_time(offset):
            return datetime.fromtimestamp(base_time + offset).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

        if is_send:
            # Client POST message sequence
            seq = [
                (fmt_time(0.001), client_ip, server_ip, client_port, server_port, "TCP", 66, "Client -> Relay"),   # SYN
                (fmt_time(0.002), server_ip, client_ip, server_port, client_port, "TCP", 66, "Relay -> Client"),   # SYN-ACK
                (fmt_time(0.003), client_ip, server_ip, client_port, server_port, "TCP", 54, "Client -> Relay"),   # ACK
                (fmt_time(0.005), client_ip, server_ip, client_port, server_port, "HTTP/TCP", payload_size + 210, "Client -> Relay"), # HTTP POST
                (fmt_time(0.008), server_ip, client_ip, server_port, client_port, "HTTP/TCP", 185, "Relay -> Client"), # 200 OK
                (fmt_time(0.010), client_ip, server_ip, client_port, server_port, "TCP", 54, "Client -> Relay"),   # FIN-ACK
            ]
        else:
            # Receiver GET message sequence
            seq = [
                (fmt_time(0.001), client_ip, server_ip, client_port, server_port, "TCP", 66, "Client -> Relay"),   # SYN
                (fmt_time(0.002), server_ip, client_ip, server_port, client_port, "TCP", 66, "Relay -> Client"),   # SYN-ACK
                (fmt_time(0.003), client_ip, server_ip, client_port, server_port, "TCP", 54, "Client -> Relay"),   # ACK
                (fmt_time(0.004), client_ip, server_ip, client_port, server_port, "HTTP/TCP", 195, "Client -> Relay"), # HTTP GET
                (fmt_time(0.007), server_ip, client_ip, server_port, client_port, "HTTP/TCP", payload_size + 240, "Relay -> Client"), # HTTP Response Payload
                (fmt_time(0.009), client_ip, server_ip, client_port, server_port, "TCP", 54, "Client -> Relay"),   # ACK
            ]

        for pkt in seq:
            self.log_packet(*pkt)

    def clear_logs(self):
        """Wipes the CSV file and re-initializes header."""
        with self._lock:
            try:
                with open(self.csv_path, mode="w", newline="", encoding="utf-8") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        "Timestamp",
                        "Source IP",
                        "Destination IP",
                        "Source Port",
                        "Destination Port",
                        "Protocol",
                        "Packet Size",
                        "Traffic Direction"
                    ])
            except Exception as e:
                print(f"[PacketSniffer Error] Could not clear log: {str(e)}")

    def stop(self):
        """Stops sniffer loop."""
        self.running = False
