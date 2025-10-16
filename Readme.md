# Own-Reconnaissance-Tools

An advanced toolkit for network reconnaissance and scanning, developed as part of my COMP6841 Project. This project features multiple Python utilities for port scanning, banner grabbing, vulnerability lookup, ARP scanning, and subdomain discovery. Designed for hands-on learning and practical use in network security assessments.

## Features \& Tools

### 1. TCP Full Connect Port Scanner (`portscan.py`)

- **Description:**
Scans open ports on a target system using standard TCP "full connect" logic.
- **Usage:**

```bash
python portscan.py
```

- **Notes:**
No root privileges required.


### 2. TCP SYN Port Scanner (`tcpsyn.py`)

- **Description:**
Performs stealthy TCP SYN scans by crafting packets using Scapy.
- **Usage:**

```bash
sudo python tcpsyn.py
```

- **Requirements:**
    - Scapy library
    - Root privileges


### 3. ARP Network Scanner (`arpscan.py`)

- **Description:**
Detects IP and MAC addresses of devices in your local network using ARP requests and Scapy.
- **Usage:**

```bash
sudo python arpscan.py
```

- **Requirements:**
    - Scapy library
    - Root privileges


### 4. Multithreaded Port Scanner (`multithreaded_port_scanner.py`)

- **Description:**
A multithreaded scanner supporting up to 100 threads for rapid scanning of port ranges or top N ports. Integrates banner grabbing for key protocols (HTTP, HTTPS, SSH, TELNET, MySQL, Redis) using the `detectservices` module.
- **Options:**
    - `-a`: Target IP address or domain name **(required)**
    - `-p`: Port range (e.g., `1-10000`), single port, `all` for top 1000 ports (optional)
    - `-T`: TCP timeout value
    - `-n`: Number of threads (default 10; up to 100)
    - `-o`: Output file to save scan results
- **Usage:**

```bash
python multithreaded_port_scanner.py -a [target] -p [all or 1-10000] -n [threads] -T [timeout] -o [output]
```


### 5. Banner Grabbing (`detectservices.py`)

- **Description:**
A supporting module for banner grabbing to identify services and versions on scanned ports, used by the multithreaded scanner.


### 6. CVE Lookup (`cvelookup.py`)

- **Description:**
Input a service name and its version to identify corresponding CVEs and fetch vulnerability details and CVE IDs.
- **Usage:**

```bash
python cvelookup.py
```


### 7. Subdomain Discovery (`subdomaindiscovery.py`)

- **Description:**
After service \& port enumeration, leverage this tool to discover subdomains of target systems.
- **Usage:**

```bash
python subdomaindiscovery.py
```


## Project Structure

```
Own-Reconnaissance-Tools/
├── Week 5/
│   ├── portscan.py
│   ├── tcpsyn.py
├── arpscan.py
├── cvelookup.py
├── detectservices.py
├── multithreaded_port_scanner.py
├── subdomaindiscovery.py
├── nmap_default_ports.txt
├── top_tcp_ports.txt
├── wordlist.txt
├── nvdcve-1.1-recent.json
├── Project Report.pdf
├── Readme.md
```


## Requirements

- Python 3.x
- Scapy
- Recommended: Run network and SYN scan tools with root privileges for packet crafting


## How to Run

See individual script usage above.
Install `Scapy` with:

```bash
pip install scapy
```

Run scripts from the command line per examples above.
