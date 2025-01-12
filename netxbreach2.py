import os
import time
from pywifi import PyWiFi, const, Profile
from scapy.all import sniff, ARP, send, get_if_list, IP, TCP, UDP, ICMP, sr1
import nmap
from rich.console import Console
from rich.text import Text
from rich.panel import Panel
from rich.prompt import Prompt

# Initialize the console for rich output
console = Console()

# -------------------------------
# Display Banner with Rich
# -------------------------------
def display_banner():
    banner = Text("""
    ===========================================
          NetXbreach by IllusiveHacks
    ===========================================
    """, style="bold cyan")
    console.print(Panel(banner, style="bold green", title="Welcome", title_align="center"))

# -------------------------------
# Clear the Command Prompt Terminal
# -------------------------------
def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

# -------------------------------
# Step 1: Scan for Wi-Fi Networks
# -------------------------------
def scan_wifi():
    console.print("\n[bold magenta]Scanning for available Wi-Fi networks...[/bold magenta]")
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.scan()
    time.sleep(3)  # Allow the scan to complete
    results = iface.scan_results()
    console.print("[bold green]Available Networks:[/bold green]")
    for i, network in enumerate(results):
        console.print(f"[cyan]{i + 1}. SSID: {network.ssid}, Signal: {network.signal}, "
                      f"BSSID: {network.bssid}, Encryption: {network.auth}[/cyan]")
    return results

# ----------------------------------------
# Disconnect from the Current Wi-Fi Network
# ----------------------------------------
def disconnect_wifi():
    console.print("\n[bold yellow]Disconnecting from the current Wi-Fi network...[/bold yellow]")
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.disconnect()
    time.sleep(3)
    if iface.status() == const.IFACE_DISCONNECTED:
        console.print("[green]Successfully disconnected from the current network.[/green]")
        return True
    else:
        console.print("[red]Failed to disconnect from the current network.[/red]")
        return False

# ----------------------------------------
# Step 2: Connect to a Wi-Fi Network
# ----------------------------------------
def connect_to_wifi(ssid, password):
    console.print(f"\n[bold blue]Attempting to connect to {ssid}...[/bold blue]")
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password
    iface.remove_all_network_profiles()
    iface.add_network_profile(profile)
    iface.connect(profile)
    time.sleep(5)
    if iface.status() == const.IFACE_CONNECTED:
        console.print(f"[green]Successfully connected to {ssid}.[/green]")
        return True
    else:
        console.print(f"[red]Failed to connect to {ssid}. Please check the credentials.[/red]")
        return False

# ----------------------------------------
# Step 3: Discover Devices on the Network
# ----------------------------------------
def scan_connected_devices(network_range, custom_arguments=None):
    """
    Scans for connected devices on the network.
    
    :param network_range: The network range to scan (e.g., '192.168.1.0/24').
    :param custom_arguments: Optional custom nmap arguments (e.g., '-sS -O').
    """
    console.print("\n[bold magenta]Scanning for connected devices on the network...[/bold magenta]")
    
    nm = nmap.PortScanner()
    
    # Use the provided custom arguments or default to a valid scan type
    arguments = custom_arguments if custom_arguments else '-sS -O'
    
    try:
        # Perform the scan using specified or default arguments
        nm.scan(hosts=network_range, arguments=arguments)
    except Exception as e:
        console.print(f"[bold red]Error during scan: {e}[/bold red]")
        return []
    
    devices = []
    
    for host in nm.all_hosts():
        device_info = {}
        # Check if the host has an IPv4 address
        device_info['IP'] = nm[host]['addresses'].get('ipv4', 'N/A')

        # Check if the host has a MAC address
        device_info['MAC'] = nm[host]['addresses'].get('mac', 'N/A')
        
        # Retrieve Hostname (if available)
        device_info['Hostname'] = nm[host]['hostnames'][0]['name'] if nm[host]['hostnames'] else 'Unknown'

        # Get Operating System details (if available)
        if 'osmatch' in nm[host]:
            device_info['OS'] = nm[host]['osmatch'][0]['name']
        else:
            device_info['OS'] = 'Unknown'

        # Get Service version details (if available)
        if 'tcp' in nm[host]:
            services = nm[host]['tcp']
            service_info = {}
            for port, data in services.items():
                service_info[port] = {'name': data['name'], 'version': data['version']}
            device_info['Services'] = service_info
        else:
            device_info['Services'] = 'N/A'
        
        devices.append(device_info)
    
    # Displaying the gathered details
    for device in devices:
        console.print(f"\n[bold cyan]IP:[/bold cyan] {device['IP']}  [bold cyan]MAC:[/bold cyan] {device['MAC']}  "
                      f"[bold cyan]Hostname:[/bold cyan] {device['Hostname']}")
        console.print(f"  [bold green]Operating System:[/bold green] {device['OS']}")
        if device['Services'] != 'N/A':
            console.print("[bold green]Services:[/bold green]")
            for port, service in device['Services'].items():
                console.print(f"    [bold yellow]Port:[/bold yellow] {port}  [bold yellow]Service:[/bold yellow] {service['name']} "
                              f"  [bold yellow]Version:[/bold yellow] {service['version']}")
        console.print("-" * 50)
    
    return devices

# ----------------------------------------
# Step 4: Monitor Network Traffic
# ----------------------------------------
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        # Determine protocol type
        if protocol == 6:  # TCP
            proto_name = "TCP"
            if TCP in packet:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
                console.print(f"[bold magenta]{proto_name}[/bold magenta] | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        elif protocol == 17:  # UDP
            proto_name = "UDP"
            if UDP in packet:
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport
                console.print(f"[bold magenta]{proto_name}[/bold magenta] | {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
        elif protocol == 1:  # ICMP
            proto_name = "ICMP"
            console.print(f"[bold magenta]{proto_name}[/bold magenta] | {ip_src} -> {ip_dst}")
        else:
            proto_name = "Other"
            console.print(f"[bold magenta]{proto_name}[/bold magenta] | {ip_src} -> {ip_dst}")

        # Display payload data (if any)
        if packet[IP].payload:
            console.print(f"[bold green]Payload:[/bold green] {bytes(packet[IP].payload)}")

# -------------------------------
# List available network interfaces
# -------------------------------
def list_available_interfaces():
    interfaces = get_if_list()
    return interfaces

# -------------------------------
# Start traffic monitoring
# -------------------------------
def monitor_traffic():
    interfaces = list_available_interfaces()
    console.print("\n[bold yellow]Select an interface to monitor:[/bold yellow]")
    for idx, iface in enumerate(interfaces):
        console.print(f"[bold cyan]{idx + 1}. {iface}[/bold cyan]")
    
    while True:
        try:
            choice = int(Prompt.ask("Enter the number corresponding to the interface"))
            if 1 <= choice <= len(interfaces):
                selected_interface = interfaces[choice - 1]
                break
            else:
                console.print("[bold red]Invalid choice. Please select a valid number.[/bold red]")
        except ValueError:
            console.print("[bold red]Invalid input. Please enter a number.[/bold red]")

    console.print(f"\n[bold green]Starting traffic monitoring on interface {selected_interface}...[/bold green]")
    console.print("[bold cyan]Capturing packets... Press Ctrl+C to stop.[/bold cyan]")
    sniff(iface=selected_interface, prn=packet_callback, store=False)

# ----------------------------------------
# Step 5: Manipulate Packets
# ----------------------------------------
def send_custom_packet():
    console.print("\n[bold cyan]=== Packet Manipulation Options ===[/bold cyan]")
    console.print("[bold yellow]1.[/bold yellow] Send a spoofed ARP packet")
    console.print("[bold yellow]2.[/bold yellow] Send a custom ICMP (ping) packet")
    console.print("[bold yellow]3.[/bold yellow] Send a custom TCP packet")
    console.print("[bold red]4.[/bold red] Exit")

    while True:
        choice = input("\n[bold magenta]Choose an option (1-4):[/bold magenta] ")

        if choice == "1":
            # ARP Spoofing
            target_ip = input("[bold yellow]Enter the target IP address: [/bold yellow]")
            target_mac = input("[bold yellow]Enter the target MAC address: [/bold yellow]")
            spoof_ip = input("[bold yellow]Enter the spoofed IP address: [/bold yellow]")

            console.print(f"[bold green]Sending spoofed ARP packet to {target_ip}, pretending to be {spoof_ip}...[/bold green]")
            packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
            send(packet, verbose=False)
            console.print(f"[bold green]ARP packet sent to {target_ip}.[/bold green]")

        elif choice == "2":
            # ICMP Ping
            target_ip = input("[bold yellow]Enter the target IP address: [/bold yellow]")
            message = input("[bold yellow]Enter a custom ICMP payload (optional): [/bold yellow]") or "Ping Test"

            console.print(f"[bold green]Sending ICMP packet to {target_ip}...[/bold green]")
            packet = IP(dst=target_ip)/ICMP()/message
            response = sr1(packet, timeout=2, verbose=False)

            if response:
                console.print(f"[bold green]Response received from {target_ip}: {response.summary()}[/bold green]")
            else:
                console.print(f"[bold red]No response from {target_ip}.[/bold red]")

        elif choice == "3":
            # Custom TCP Packet
            target_ip = input("[bold yellow]Enter the target IP address: [/bold yellow]")
            target_port = int(input("[bold yellow]Enter the target TCP port: [/bold yellow]"))

            console.print(f"[bold green]Sending custom TCP packet to {target_ip}:{target_port}...[/bold green]")
            packet = IP(dst=target_ip)/TCP(dport=target_port, flags="S")
            send(packet, verbose=False)
            console.print(f"[bold green]TCP packet sent to {target_ip}:{target_port}.[/bold green]")

        elif choice == "4":
            console.print("[bold red]Exiting packet manipulation.[/bold red]")
            break

        else:
            console.print("[bold red]Invalid choice. Please select between 1 and 4.[/bold red]")

# ----------------------------------------
# Main Program Flow
# ----------------------------------------
def main():
    clear_terminal()
    display_banner()
    
    while True:
        console.print("\n[bold blue]=== NetXbreach Main Menu ===[/bold blue]")
        console.print("[bold yellow]1.[/bold yellow] Scan Wi-Fi Networks")
        console.print("[bold yellow]2.[/bold yellow] Disconnect Wi-Fi Network")
        console.print("[bold yellow]3.[/bold yellow] Connect to Wi-Fi Network")
        console.print("[bold yellow]4.[/bold yellow] Scan Connected Devices")
        console.print("[bold yellow]5.[/bold yellow] Monitor Network Traffic")
        console.print("[bold yellow]6.[/bold yellow] Packet Manipulation")
        console.print("[bold red]7.[/bold red] Exit")
        
        choice = input("\n[bold cyan]Choose an option (1-7):[/bold cyan] ")
        
        if choice == "1":
            scan_wifi()
        elif choice == "2":
            disconnect_wifi()
        elif choice == "3":
            ssid = input("[bold cyan]Enter the SSID: [/bold cyan]")
            password = input("[bold cyan]Enter the password: [/bold cyan]")
            connect_to_wifi(ssid, password)
        elif choice == "4":
            network_range = input("[bold cyan]Enter the network range (e.g., '192.168.1.0/24'): [/bold cyan]")
            scan_connected_devices(network_range)
        elif choice == "5":
            monitor_traffic()
        elif choice == "6":
            send_custom_packet()
        elif choice == "7":
            console.print("[bold red]Exiting...[/bold red]")
            break
        else:
            console.print("[bold red]Invalid option. Please select a valid number between 1 and 7.[/bold red]")

# Start the program
if __name__ == "__main__":
    main()
