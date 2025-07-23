import socket
from datetime import datetime

def portscan(target, port):
    try:
        #Initialize socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)  
        #Initialize TCP full connection
        sock.connect((target, port))
        return True
    except:
        return False
    finally:
        sock.close()



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
        ports = [21,22,23,25,53,80,443,3306,3389]
    else:
        print("Invalid choice")
        exit()
    openports = []
    t1 = datetime.now()
    host = input("Enter the host ip or url: ")
    try:
        #Resolve hostname
        host = socket.gethostbyname(host)
        print("[*] Scanning "+host)
        for port in ports:
            if portscan(host, port):
                openports.append(port)
        
        print("Open ports: ", openports)

    except:
        print("Invalid host or Hostname could not be resolved")

    t2 = datetime.now()
    total = t2 - t1
    print("Scanning completed in: ", total)
    