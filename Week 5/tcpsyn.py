import socket
from datetime import datetime
from scapy.all import IP, TCP, sr1, conf
import random

def syn_scan(target, port):
    try:
        src_port = random.randint(1025, 65534)
        conf.verb = 0 
        pkt = IP(dst=target)/TCP(sport=src_port, dport=port, flags="S")
        
        # sr1 is to send and waits for 1 response
        response = sr1(pkt, timeout=0.5,verbose=0)

        # If the response is None, it means the port is blocked by the firewall
        if response is None:
            return "Filtered"

        # Check if the response contains a TCP layer message
        elif response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:
                # Port is open (SYN-ACK received)
                rst_pkt = IP(dst=target)/TCP(sport=src_port, dport=port, flags="R")
                sr1(rst_pkt, timeout=0.5, verbose=0)
                return "Open"

            elif tcp_layer.flags == 0x14:
                # Port is closed (RST received)
                return "Closed"
                    
        return "Unknown"
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        return "Error"

if __name__ == '__main__':
    print("1. Full Port Scan \n2. Specific port range\n3. Single Port \n4. Most popular ports")
    choice = int(input("Enter your choice: "))
    
    if choice == 1:
        ports = list(range(1, 65536))
    elif choice == 2:
        start = int(input("Enter start port: "))
        end = int(input("Enter end port: "))
        ports = list(range(start, end + 1))
    elif choice == 3:
        port = int(input("Enter port: "))
        ports = [port]
    elif choice == 4:
        ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389]
    else:
        print("Invalid choice.")
        exit()

    open_ports = []
    filtered_ports = []

    t1 = datetime.now()
    host = input("Enter the host IP or URL: ")

    try:
        host_ip = socket.gethostbyname(host)
        print(f"[*] Scanning {host} [{host_ip}] ...")
        
        for port in ports:
            status = syn_scan(host_ip, port)
            if status == "Open":
                open_ports.append(port)
            elif status == "Filtered":
                filtered_ports.append(port)

    except socket.gaierror:
        print("Invalid host or hostname could not be resolved.")
        exit()

    t2 = datetime.now()
    total = t2 - t1

    print("\nScan Results:")
    if open_ports:
        print("Open ports:", open_ports)
    else:
        print("No open ports found.")

    if filtered_ports:
        print("Filtered ports:", filtered_ports)
    else:
        print("No filtered ports found.")

    print("Scanning completed in:", total)