from scapy.all import *
from datetime import datetime
from manuf import manuf
import signal
import sys

interface = 'wlan0mon'

seen_ssids = []

parser = manuf.MacParser()

log_file = "probe_requests.log"

def log_to_file(entry):
    with open(log_file, "a") as f:
        f.write(entry + "\n")

def handle_packet(packet):
    if packet.haslayer(Dot11ProbeReq):
        ssid = packet.info.decode(errors='ignore') if packet.info else "<Hidden SSID>"
        mac = packet.addr2

        if ssid not in seen_ssids:
            seen_ssids.append(ssid)
            vendor = parser.get_manuf(mac) or "Unknown Vendor"
            signal_strength = None

            if packet.haslayer(RadioTap):
                try:
                    signal_strength = packet.dBm_AntSignal
                except:
                    pass

            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_entry = f"[{time_str}] {mac} ({vendor}) requested SSID: '{ssid}'"
            if signal_strength:
                log_entry += f" | Signal: {signal_strength} dBm"

            print(log_entry)
            log_to_file(log_entry)

def stop_sniffing(sig, frame):
    print("\n[+] Sniffing stopped by user.")
    sys.exit(0)

signal.signal(signal.SIGINT, stop_sniffing)

print("[*] Starting WiFi Probe Sniffer...")
sniff(iface=interface, prn=handle_packet)
