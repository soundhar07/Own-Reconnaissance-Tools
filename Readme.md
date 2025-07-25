Week 5:
    In Week 5 Folder, I have two programs one is a basic port scanner which works on TCP Full connect portscan.py and next one is TCP SYN connect based port 
    Scanner which uses the Scapy library to build IP packets and TCP segements. Scapy requires the usage of sudo along with your program.
    
    Usage: 
    python portscan.py , sudo tcpsyn.py

    Libraries required:
    Scapy

arpscan.py :
I have used the scapy module again and so it requires root user privileges. The intent of the program is to identify the IP addresses and the MAC addresses of the systems in your local network.

multithreaded_port_scanner.py :

    In this I have implemented the multi threading based port scanner with different options explained below. I have limited the threads to 100 and not more than that as it might be sudden huge burst of traffic and it will also miss many port connections.It also uses the detectservices module to does the banner grabbing for famous protocols like HTTP,HTTPS,SSH,TELNET,MySQL and Redis.

    Options:
    -a	Required. This is to give the Target IP address or domain name which will be later resolved.
    -p	Optional. This is to mention the port range or even single port. If nothing is given, it performs the basic port scanning of top 1000 most common ports. It takes port range as argument like 1-100, or all .
    -T	Timeout for the TCP packets.
    -n	Number of threads (default value is 10 and it can go up to 100)
    -o	To save the results to the output file.
    
    Usage:
    python multithreaded_port_scanner.py - a [hostname or IP address] - p [all or 1-10000 ] -n [NUMBER OF THREADS] -T[TCP_TIMEOUT] -o[OUTPUT_FILE]

cvelookup.py :
     I didn't parse any service versions in port scanner . So, after running the port scanner you can input the service and version and get the CVE  identified with description and CVE_ID.



















