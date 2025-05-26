
"""
MIT License

Copyright (c) 2025 Md. Abu Naser Nayeem [Tanjib Isham]


Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

**** Unified OSINT DDoS Simulation & Forensic Tool (GreeDos)

This tool integrates the strengths of:
  • MHDDoS (multi‑vector, high‑concurrency attack simulation),
  • Security Onion (deep packet inspection, forensic logging),
  • Splunk/ELK (robust log aggregation and real‑time alerting),
  • Zeek (detailed protocol analysis with custom detection).

It is designed to overcome known limitations (resource intensity, static proxy dependency,
complexity of configuration, etc.) by providing a modular, Python‑based, CMD dashboard tool.

Usage:
  python3 greeDos.py --target <target_URL_or_IP> --threads <num> --duration <seconds>
"""

import argparse
import asyncio
import threading
import time
import sqlite3
import random
import sys
from datetime import datetime
from collections import deque

# For a rich text CMD interface:
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

# Global console for Rich
console = Console()

# -------------------------------------------------------------------
# GreeDoS ASCII Logo (to be displayed as a headline)
# -------------------------------------------------------------------
GreeDos_LOGO = r"""
    __________________              ________          _________
 /  _____/\______   \ ____   ____ \______ \   ____ /   _____/
/   \  ___ |       _// __ \_/ __ \ |    |  \ /  _ \\_____  \ 
\    \_\  \|    |   \  ___/\  ___/ |    `   (  <_> )        \
 \______  /|____|_  /\___  >\___  >_______  /\____/_______  /
        \/        \/     \/     \/        \/              \/ 
"""

# -------------------------------------------------------------------
# Global Configuration & Constants
# -------------------------------------------------------------------
ALERT_THRESHOLD = 100  # Example threshold (number of requests) for alert generation

# -------------------------------------------------------------------
# Database & Logging Utilities (Inspired by Security Onion / Splunk/ELK)
# -------------------------------------------------------------------
def init_database():
    """Initialize the SQLite database for storing event logs (forensic data)."""
    conn = sqlite3.connect("osint_tool.db")
    cur = conn.cursor()
    cur.execute("""
        
    """)
    conn.commit()
    conn.close()

def log_event_to_db(event_type: str, details: str):
    """Log an event to the database."""
    conn = sqlite3.connect("osint_tool.db")
    cur = conn.cursor()
    cur.execute("INSERT INTO events (event_type, details) VALUES (?, ?)", (event_type, details))
    conn.commit()
    conn.close()

# -------------------------------------------------------------------
# Attack Simulation Module (Inspired by MHDDoS Strengths)
# -------------------------------------------------------------------
class AttackSimulator:
    """
    Simulate multi‑vector DDoS attacks.

    Strengths:
      - Supports multiple attack vectors (e.g., HTTP floods, SYN/UDP floods, amplification).
      - Customizable parameters: Threads, duration, randomized headers.
      - High‑concurrency using multi‑threading.
    """
    def __init__(self, target: str, threads: int = 5, duration: int = 30):
        self.target = target
        self.threads = threads
        self.duration = duration  # seconds
        self.running = False
        self.requests_sent = 0
        self.lock = threading.Lock()

    def simulate_http_flood(self):
        """
        Simulated HTTP flood.
        Replace this with real network code (e.g., aiohttp or requests) for actual HTTP GET/POST floods.
        """
        end_time = time.time() + self.duration
        while time.time() < end_time and self.running:
            time.sleep(0.05 + random.uniform(0, 0.1))  # simulate network delay
            with self.lock:
                self.requests_sent += 1
            # (Optional) Log each request for forensic data:
            # log_event_to_db("HTTP_FLOOD", f"Request sent to {self.target}")
        log_event_to_db("SIMULATION", "One simulation thread has finished.")

    def start(self):
        """Start the attack simulation using multi-threading."""
        self.running = True
        thread_list = []
        for i in range(self.threads):
            t = threading.Thread(target=self.simulate_http_flood, name=f"FloodThread-{i+1}")
            t.start()
            thread_list.append(t)
        for t in thread_list:
            t.join()
        self.running = False

    def stop(self):
        self.running = False

# -------------------------------------------------------------------
# Forensic Analyzer Module (Inspired by Security Onion & Splunk/ELK)
# -------------------------------------------------------------------
class ForensicAnalyzer:
    """
    Collect and store forensic logs and events for later analysis.
    Keeps a small in‑memory queue of recent events and logs to a SQLite database.
    """
    def __init__(self):
        self.event_queue = deque(maxlen=50)

    def log_event(self, event_type: str, details: str):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        event = {"timestamp": timestamp, "event_type": event_type, "details": details}
        self.event_queue.append(event)
        log_event_to_db(event_type, details)

    def get_recent_events(self, count: int = 10):
        return list(self.event_queue)[-count:]

# -------------------------------------------------------------------
# Protocol Analyzer Module (Inspired by Zeek’s Strengths)
# -------------------------------------------------------------------
class ProtocolAnalyzer:
    """
    Analyze network traffic at the protocol level.
    
    Strengths:
      - Granular packet inspection using custom rules.
    For the blueprint, we simulate packet capture/analysis. In production, you could integrate Scapy.
    """
    def __init__(self, analyzer: ForensicAnalyzer):
        self.analyzer = analyzer

    def analyze_packet(self, packet):
        # In a real implementation, you would parse and inspect 'packet' content.
        # Here, we simulate a 5% chance of detecting an anomaly.
        if random.random() < 0.05:
            self.analyzer.log_event("PROTOCOL_ALERT", f"Suspicious packet detected: {packet}")

    def start_sniffing(self):
        """
        Simulates packet sniffing.
        For real capturing, consider using: sniff(filter="ip", prn=self.analyze_packet, store=0)
        """
        while True:
            time.sleep(random.uniform(0.1, 0.5))
            dummy_packet = f"Packet-{random.randint(1,1000)}"
            self.analyzer.log_event("PACKET", f"Captured {dummy_packet}")
            self.analyze_packet(dummy_packet)

# -------------------------------------------------------------------
# Alert Detector Module (Inspired by Splunk/ELK Real-Time Alerting)
# -------------------------------------------------------------------
class AlertDetector:
    """
    Detect anomalies by correlating simulation stats and forensic logs.
    
    Strength:
      - Provides real-time alerts when thresholds (e.g., number of requests) are exceeded.
    """
    def __init__(self, simulator: AttackSimulator, analyzer: ForensicAnalyzer):
        self.simulator = simulator
        self.analyzer = analyzer
        self.alerts = []

    def check_for_alerts(self):
        with self.simulator.lock:
            req_count = self.simulator.requests_sent
        if req_count > ALERT_THRESHOLD:
            alert_msg = f"High traffic alert: {req_count} requests sent!"
            if alert_msg not in self.alerts:
                self.alerts.append(alert_msg)
                self.analyzer.log_event("TRAFFIC_ALERT", alert_msg)
        return self.alerts

# -------------------------------------------------------------------
# CMD Dashboard Module using Rich (Unified Output)
# -------------------------------------------------------------------
class Dashboard:
    """
    Provides a unified, real-time CMD dashboard that combines:
      - Attack simulation statistics (MHDDoS strength),
      - Forensic logs & alerts (Security Onion, Splunk/ELK),
      - Protocol analysis events (Zeek).
    """
    def __init__(self, simulator: AttackSimulator, analyzer: ForensicAnalyzer, detector: AlertDetector):
        self.simulator = simulator
        self.analyzer = analyzer
        self.detector = detector

    def render_dashboard(self):
        # Build a table for simulation statistics:
        table = Table(title="GreeDoS Dashboard")
        table.add_column("Metric", style="cyan", no_wrap=True)
        table.add_column("Value", style="magenta")
        table.add_row("Target", self.simulator.target)
        table.add_row("Threads", str(self.simulator.threads))
        table.add_row("Duration (sec)", str(self.simulator.duration))
        with self.simulator.lock:
            table.add_row("Requests Sent", str(self.simulator.requests_sent))
        # Build a panel for recent forensic events:
        recent_events = self.analyzer.get_recent_events(5)
        logs_str = "\n".join([f"{ev['timestamp']} | {ev['event_type']}: {ev['details']}" for ev in recent_events])
        log_panel = Panel(logs_str if logs_str else "No events", title="Forensic Log", border_style="red")
        # Build a panel for alert messages:
        alerts = self.detector.alerts[-5:]
        alert_panel = Panel("\n".join(alerts) if alerts else "No alerts", title="Alerts", border_style="yellow")
        return table, log_panel, alert_panel

    async def display(self):
        with Live(refresh_per_second=2, console=console) as live:
            while True:
                self.detector.check_for_alerts()
                table, log_panel, alert_panel = self.render_dashboard()
                combined = Panel.fit(table, title="Main Dashboard")
                live.update(combined)
                console.print(log_panel)
                console.print(alert_panel)
                await asyncio.sleep(2)

# -------------------------------------------------------------------
# Main Program Entry Point
# -------------------------------------------------------------------
async def main(args):
    # Display the ASCII art logo at startup
    console.print(GreeDos_LOGO, style="bold cyan", justify="center")
    
    # Initialize the forensic database
    init_database()

    # Instantiate modules
    analyzer = ForensicAnalyzer()
    simulator = AttackSimulator(args.target, args.threads, args.duration)
    detector = AlertDetector(simulator, analyzer)
    dashboard = Dashboard(simulator, analyzer, detector)
    protocol_analyzer = ProtocolAnalyzer(analyzer)

    # Start the attack simulation in a separate thread (representing MHDDoS strengths)
    sim_thread = threading.Thread(target=simulator.start, name="AttackSimulatorThread")
    sim_thread.start()

    # Start protocol analysis in a daemon thread (simulate Zeek's functionality)
    proto_thread = threading.Thread(target=protocol_analyzer.start_sniffing, name="ProtocolAnalyzerThread", daemon=True)
    proto_thread.start()

    # Run the dashboard asynchronously to display real-time unified output
    await dashboard.display()

# -------------------------------------------------------------------
# Entry Point: Command-Line Argument Parsing
# -------------------------------------------------------------------
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="Unified OSINT DDoS Simulation & Forensic Tool (GreeDos)")
    parser.add_argument('--target', type=str, required=True,
                        help='Target URL or IP address for simulation')
    parser.add_argument('--threads', type=int, default=5,
                        help='Number of threads for attack simulation')
    parser.add_argument('--duration', type=int, default=30,
                        help='Duration of the simulation in seconds')
    args = parser.parse_args()

    try:
        asyncio.run(main(args))
    except KeyboardInterrupt:
        console.log("[bold red]Tool terminated by user.[/bold red]")
        sys.exit(0)