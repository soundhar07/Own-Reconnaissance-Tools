import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import errno
from detectservices import detect_service_version


# Got these Files from Nmap
nmap_service_file = "nmap_default_ports.txt"
nmap_top_1000 = "top_tcp_ports.txt"

with open(nmap_service_file, "r") as f:
    nmap_lookup = f.read().splitlines()

with open(nmap_top_1000, "r") as f:
    top1000 = f.read().splitlines()

# Build lookup dictionaries
nmap_dict = {line.split()[1].split("/")[0]: line.split()[0] for line in nmap_lookup}
top1000_list = [int(line.split()[1].split("/")[0]) for line in top1000]

# For Getting service from the Port number
def lookup_port(port):
    return nmap_dict.get(str(port), "Unknown") 

# Obtaining port number list for different options
def getPortList(port_range):
    if port_range == "basic":
        return top1000_list
    elif port_range == "all":
        print("\n [*] Scanning all ports... might take a while")
        return list(range(1, 65536))
    elif port_range.isdigit():  # single port
        return [int(port_range)]
    else:
        start, end = port_range.split("-")
        return list(range(int(start), int(end) + 1))
# For Scanning the ports 
def scan_port(target, port, timeout=1.0):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                service = lookup_port(port)
                version_info = ""
                # For getting service version of services HTTP, Telnet, MySQL, Redis,HTTPS
                if port in [80,8080,443,22,3306,23,6379]:
                    version_info = detect_service_version(sock,target,port)
                return (port, service,version_info)
    except socket.timeout:
        return (port, "Filtered")
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
    return None

# Multithreaded Scanning
def threaded_scan(target, port_range, timeout, num_threads):
    open_ports = {}
    filtered_ports = []
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = {executor.submit(scan_port, target, port, timeout): port for port in port_range}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning"):
            result = future.result()
            if result:
                if len(result) == 2:
                    port, service = result
                    filtered_ports.append(port)
                elif len(result) == 3:
                    port, service, version_info = result
                    open_ports[port] = (service, version_info)
    if filtered_ports:
        print("\nFiltered Ports:")
        for port in sorted(filtered_ports):
            print(f"Port {port}: Filtered")
    return open_ports


def main():
    parser = argparse.ArgumentParser(description='TCP port scanner')
    parser.add_argument('-a', '--address', required=True, help='Target IP address or domain name (e.g. 127.0.0.1 or example.com)')
    parser.add_argument('-p', '--port-range', default='basic', help='Port range (e.g. 1-100, or all for all ports, or use "basic" for top 1000)')
    parser.add_argument('-T', '--timeout', default=1.0, type=float, help='Timeout in seconds (default: 1.0)')
    parser.add_argument('-n', '--num-threads', default=10, type=int, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', help='Output file to save results (optional)')
    args = parser.parse_args()

    target = args.address
    port_range = getPortList(args.port_range)
    timeout = args.timeout
    num_threads = min(args.num_threads, 100)  # Limit thread count to 100
    output_file = args.output


    try:
        print("[*] Resolving", target)
        host = socket.gethostbyname(target)
        print("[*] Scanning", host)
        if len(port_range) == 1: # Single port handling
            print(f"[*] Scanning port {port_range[0]}")
            result = scan_port(host, port_range[0], timeout)
            if result :
                port, service , version_info = result
                print(f"[*] Port {port_range[0]}/tcp\t{service}\t{version_info}")
            else:
                print(f"[*] Port{port_range[0]}closed")
            exit()
        results = threaded_scan(host, port_range, timeout, num_threads)

        results_output = []

        results_output.append("\n--- Scan Results ---")
        results_output.append(f"Target: {target}")
        results_output.append(f"Ports Scanned: {len(port_range)}")
        results_output.append(f"Timeout: {timeout}s")
        results_output.append(f"Threads: {num_threads}")
        results_output.append("-" * 20)

        if results:
            results_output.append("\n[*] Open Ports:")
            sorted_open_ports = sorted(results.items())
            for port, (service,version_info) in sorted_open_ports:
                line = f"[*] Port {port}/tcp\t{service}"
                if version_info:
                    line += f"\t{version_info}"
                results_output.append(line)
        else:
            results_output.append("\n[*] No open ports found.")

        for line in results_output:
            print(line)
        
        # Write the results to the output file
        if output_file:
            try:
                with open(output_file, 'w') as f:
                    f.write('\n'.join(results_output))
                print(f"\n[*] Scan results saved to '{output_file}'")
            except Exception as e:
                print(f"Error saving results to '{output_file}': {e}")

    except socket.gaierror:
        print("Invalid host or Hostname could not be resolved")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('\nProgram interrupted by user.')
    except Exception as e:
        print(f'\nAn error occurred: {e}')