import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg') # Non-interactive backend for server generation
import matplotlib.pyplot as plt
from datetime import datetime

class MetadataAnalyzer:
    """
    Traffic Analysis & Side-Channel Reconstruction Engine:
    - Parses CSV packet captures using Pandas.
    - Computes statistical metrics (size distribution, frequency, exposure matrix).
    - Performs side-channel traffic analysis to estimate plaintext size and conversation patterns.
    - Exports dark-themed cyber charts for presentation and report inclusion.
    """

    def __init__(self, csv_path=None):
        self.base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.reports_dir = os.path.join(self.base_dir, "reports")
        self.csv_path = csv_path or os.path.join(self.reports_dir, "captured_packets.csv")
        self.charts_dir = os.path.join(self.base_dir, "dashboard", "static", "charts")
        os.makedirs(self.charts_dir, exist_ok=True)

    def analyze_metadata(self) -> dict:
        """
        Parses captured packet CSV and extracts comprehensive traffic metrics,
        exposed header counts, and side-channel reconstruction estimations.
        """
        default_stats = {
            "total_packets": 0,
            "total_bytes": 0,
            "avg_packet_size": 0,
            "min_packet_size": 0,
            "max_packet_size": 0,
            "exposed_ips": [],
            "exposed_ports": [],
            "unique_directions": {},
            "traffic_matrix": [],
            "reconstruction_analysis": {
                "estimated_messages_sent": 0,
                "size_correlation_detected": False,
                "length_inferences": [],
                "timing_bursts_count": 0
            },
            "observations": ["No network packets captured yet. Execute a simulation to log traffic."]
        }

        if not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0:
            return default_stats

        try:
            df = pd.read_csv(self.csv_path)
            if df.empty or len(df) <= 1: # Only header or empty
                return default_stats

            # Clean and ensure correct data types
            df["Packet Size"] = pd.to_numeric(df["Packet Size"], errors="coerce").fillna(0)

            total_packets = len(df)
            total_bytes = int(df["Packet Size"].sum())
            avg_size = float(round(df["Packet Size"].mean(), 2))
            min_size = int(df["Packet Size"].min())
            max_size = int(df["Packet Size"].max())

            # Exposed metadata lists
            src_ips = set(df["Source IP"].dropna().unique())
            dst_ips = set(df["Destination IP"].dropna().unique())
            all_ips = sorted(list(src_ips.union(dst_ips)))

            src_ports = set(df["Source Port"].dropna().astype(str).unique())
            dst_ports = set(df["Destination Port"].dropna().astype(str).unique())
            all_ports = sorted(list(src_ports.union(dst_ports)))

            # Directions
            dir_counts = df["Traffic Direction"].value_counts().to_dict()

            # Side-channel traffic analysis: Filter HTTP payload data packets (> 150 bytes)
            payload_pkts = df[df["Packet Size"] > 150].copy()
            estimated_msgs = len(payload_pkts)

            length_inferences = []
            for idx, row in payload_pkts.iterrows():
                pkt_sz = row["Packet Size"]
                # Approximate header & JSON overhead ~220 Bytes
                approx_ciphertext_len = max(0, pkt_sz - 220)
                # GCM wrapper overhead (salt 16B, IV 12B, tag 16B, base64 expansion ~1.33x)
                approx_plaintext_len = max(1, int(approx_ciphertext_len / 1.4) - 30)
                length_inferences.append({
                    "timestamp": row["Timestamp"],
                    "packet_size": int(pkt_sz),
                    "estimated_plaintext_len": approx_plaintext_len,
                    "direction": row["Traffic Direction"]
                })

            # Observations generation
            observations = [
                f"Sniffed {total_packets} TCP segments totaling {total_bytes} bytes across localhost interfaces.",
                f"Exposed Network Metadata: {len(all_ips)} IP addresses and {len(all_ports)} active ports clearly identified.",
                "E2EE payload encryption DOES NOT obfuscate TCP segment length or frame headers.",
                f"Attacker Side-Channel Inference: Identified {estimated_msgs} payload transfers and estimated character counts from packet sizes."
            ]

            return {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "avg_packet_size": avg_size,
                "min_packet_size": min_size,
                "max_packet_size": max_size,
                "exposed_ips": all_ips,
                "exposed_ports": all_ports,
                "unique_directions": dir_counts,
                "reconstruction_analysis": {
                    "estimated_messages_sent": estimated_msgs,
                    "size_correlation_detected": estimated_msgs > 0,
                    "length_inferences": length_inferences[:10], # Top 10 sample inferences
                    "timing_bursts_count": min(estimated_msgs, total_packets)
                },
                "observations": observations
            }

        except Exception as e:
            print(f"[MetadataAnalyzer Error] Analysis failed: {str(e)}")
            return default_stats

    def generate_charts(self):
        """Generates static dark-theme cyber charts using Matplotlib for PDF report and dashboard backup."""
        # Dark Cyber Theme Palette
        plt.style.use('dark_background')
        bg_color = '#0b0f19'
        card_bg = '#111827'
        cyan_color = '#06b6d4'
        green_color = '#10b981'
        orange_color = '#f59e0b'
        red_color = '#ef4444'
        grid_color = '#1f2937'

        try:
            if not os.path.exists(self.csv_path) or os.path.getsize(self.csv_path) == 0:
                self._generate_empty_charts(bg_color, cyan_color)
                return

            df = pd.read_csv(self.csv_path)
            if df.empty:
                self._generate_empty_charts(bg_color, cyan_color)
                return

            df["Packet Size"] = pd.to_numeric(df["Packet Size"], errors="coerce").fillna(0)

            # Chart 1: Packet Size vs Time
            fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=bg_color)
            ax.set_facecolor(card_bg)
            ax.plot(df.index, df["Packet Size"], color=cyan_color, marker='o', markersize=4, linewidth=1.5, label='Packet Size (Bytes)')
            ax.set_title('Captured Packet Size Over Time', color='white', fontsize=12, fontweight='bold', pad=10)
            ax.set_xlabel('Packet Index Sequence', color='#9ca3af', fontsize=9)
            ax.set_ylabel('Size (Bytes)', color='#9ca3af', fontsize=9)
            ax.grid(True, color=grid_color, linestyle='--', alpha=0.6)
            ax.tick_params(colors='#9ca3af', labelsize=8)
            plt.tight_layout()
            fig.savefig(os.path.join(self.charts_dir, "packet_size_time.png"), dpi=150, facecolor=bg_color)
            plt.close(fig)

            # Chart 2: Traffic Direction & Frequency
            fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=bg_color)
            ax.set_facecolor(card_bg)
            dir_counts = df["Traffic Direction"].value_counts()
            colors = [cyan_color, orange_color, green_color, red_color][:len(dir_counts)]
            bars = ax.bar(dir_counts.index, dir_counts.values, color=colors, width=0.4, edgecolor='#374151')
            ax.set_title('Traffic Distribution by Flow Direction', color='white', fontsize=12, fontweight='bold', pad=10)
            ax.set_ylabel('Packet Count', color='#9ca3af', fontsize=9)
            ax.grid(True, axis='y', color=grid_color, linestyle='--', alpha=0.6)
            ax.tick_params(colors='#9ca3af', labelsize=8)
            for bar in bars:
                height = bar.get_height()
                ax.annotate(f'{height}', xy=(bar.get_x() + bar.get_width() / 2, height),
                            xytext=(0, 3), textcoords="offset points", ha='center', va='bottom', color='white', fontsize=9, fontweight='bold')
            plt.tight_layout()
            fig.savefig(os.path.join(self.charts_dir, "packet_frequency.png"), dpi=150, facecolor=bg_color)
            plt.close(fig)

            # Chart 3: Metadata Exposure vs Content Protection
            fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=bg_color)
            ax.set_facecolor(card_bg)
            categories = ['Source/Dest IP', 'TCP Ports', 'Packet Size', 'Timing/Frequency', 'Payload Content']
            exposure_pct = [100, 100, 100, 100, 0] # Payload content 0% exposed with E2EE
            bar_colors = [red_color, red_color, orange_color, orange_color, green_color]
            
            bars = ax.barh(categories, exposure_pct, color=bar_colors, height=0.5)
            ax.set_title('Metadata Exposure Matrix (%)', color='white', fontsize=12, fontweight='bold', pad=10)
            ax.set_xlabel('Exposure Percentage on Network Wire', color='#9ca3af', fontsize=9)
            ax.set_xlim(0, 110)
            ax.grid(True, axis='x', color=grid_color, linestyle='--', alpha=0.6)
            ax.tick_params(colors='#9ca3af', labelsize=8)
            for bar in bars:
                width = bar.get_width()
                label_text = "EXPOSED (100%)" if width == 100 else "PROTECTED (0%)"
                ax.annotate(label_text, xy=(width + 2, bar.get_y() + bar.get_height() / 2),
                            xytext=(0, 0), textcoords="offset points", ha='left', va='center', color='white', fontsize=8, fontweight='bold')
            plt.tight_layout()
            fig.savefig(os.path.join(self.charts_dir, "metadata_exposure.png"), dpi=150, facecolor=bg_color)
            plt.close(fig)

        except Exception as e:
            print(f"[MetadataAnalyzer Chart Error] Could not render matplotlib charts: {str(e)}")

    def _generate_empty_charts(self, bg_color, cyan_color):
        """Renders placeholder charts when CSV is empty."""
        for chart_name, title in [
            ("packet_size_time.png", "Packet Size Over Time (No Data)"),
            ("packet_frequency.png", "Traffic Frequency (No Data)"),
            ("metadata_exposure.png", "Metadata Exposure Matrix (No Data)")
        ]:
            fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=bg_color)
            ax.set_facecolor('#111827')
            ax.text(0.5, 0.5, 'Run Simulation to Generate Chart Data', color='#9ca3af', ha='center', va='center', fontsize=11)
            ax.set_title(title, color='white', fontsize=12, fontweight='bold', pad=10)
            ax.axis('off')
            plt.tight_layout()
            fig.savefig(os.path.join(self.charts_dir, chart_name), dpi=150, facecolor=bg_color)
            plt.close(fig)
