import socket
import ssl


def detect_service_version(sock, target, port):
    try:
        # HTTP
        if port == 80 or port == 8080:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            response = sock.recv(1024).decode(errors='ignore').strip()
            lines = response.split('\r\n')
            server_value = "Not Found" 
            for line in lines:
                if line.lower().startswith("server"):
                    server_value = line
                    break
            return server_value
        # Telnet
        elif port == 23:
            sock.sendall(b"\r\n")
            return sock.recv(1024).decode(errors='ignore').strip()
        # MySQL
        elif port == 3306:
            banner = sock.recv(1024)
            version = banner[5:].split(b'\x00')[0].decode(errors='ignore')
            return f"MySQL Version: {version}"
        # Redis
        elif port == 6379:
            sock.sendall(b"INFO\r\n")
            response = sock.recv(2048).decode(errors='ignore')
            for line in response.split('\r\n'):
                if line.lower().startswith("redis_version:"):
                    return f"Redis Version: {line.split(':', 1)[1].strip()}"
            return "Redis version not found in INFO output"
        # HTTPS
        elif port == 443:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:            
                    cert = ssock.getpeercert()

                    if cert:
                        print(f'[+] {host} SSL Certificate:')
                        for field, value in cert.items():
                            print(f'{field}: {value}')
                    else:
                        print('No SSL certificates returned')

                    print('HTTP header (if present):')
                    ssock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')
                    response = ssock.recv(1024).decode(errors='ignore').strip()
                    lines = response.split('\r\n')
                    server_value = "Not Found" 
                    for line in lines:
                        if line.lower().startswith("server:"):
                            server_value = line.split(':', 1)[1].strip()
                            break
                    return server_value
        #SSH PORT 22 
        else:
            return sock.recv(1024).decode(errors='ignore').strip()
    except Exception as e:
        return f"Version detection failed: {e}"