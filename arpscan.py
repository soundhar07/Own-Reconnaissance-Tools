from scapy.all import Ether, ARP, srp
from ipaddress import ip_network, ip_address

def arp_scan(network):
    print(f"[+] ARP scanning {network}...")

    devices = []       
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # create Ethernet broadcast frame

    try:
        if "/" in network:
            hosts = list(ip_network(network, strict=False).hosts()) # parse all hosts in a subnet
            if len(hosts) > 1024:
                print(f"[!] Too many hosts ({len(hosts)}). Limit to a /22 or smaller.")
                return []
            targets = [str(ip) for ip in hosts] 
    except Exception as e:
        print(f"Invalid IP/network format: {e}")
        return []

    try:
        pkt = ether / ARP(pdst=targets) # create ARP request packet
        answered, _ = srp(pkt, timeout=2, verbose=False)    # send and receive packets
        for _, received in answered:
            devices.append({'ip': received.psrc, 'mac': received.hwsrc})    # collect IP and MAC
    except Exception as e :
        print(f" ARP scan interrupted by user: {e}")  
    return devices

if __name__ == "__main__":
    
    my_local_network = input("Enter the network to scan (e.g., 244.178.44.111/24) in CIDR format: ")
    discovered_devices = arp_scan(my_local_network)

    if discovered_devices:
        print("\n[+] Discovered Devices:")
        for device in discovered_devices:
            print(f"    IP: {device['ip']}, MAC: {device['mac']}")
    else:
        print("\n[!] No devices found or scan failed.")
