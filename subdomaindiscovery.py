import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

subdomain_list = "wordlist.txt"
with open(subdomain_list, "r") as f:
    wordlist = set(f.read().splitlines())


def check_subdomain(domain, subdomain):
    url = f"http://{subdomain}.{domain}"
    try:
        response = requests.get(url, timeout=3, verify=False)
        if response.status_code < 400:  # If the status code is less than 400, it means the subdomain is valid
            print(f"[*] Found subdomain: {subdomain}")
            return subdomain
    except requests.exceptions.RequestException:
        pass


def brute_force_subdomains(domain, wordlist, threads):
    discovered_subdomains = set()
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, domain, sub): sub for sub in wordlist}
        for future in tqdm(as_completed(futures), total=len(futures), desc=f"Scanning {domain}"):
            result = future.result()
            if result:
                discovered_subdomains.add(result)
    return discovered_subdomains

if __name__ == "__main__":
    domain = input("Enter the domain to scan: ")
    threads = int(input("Enter the number of threads to use: "))
    threads = min(threads, 20) # limiting to 20 threads
    discovered_subdomains = brute_force_subdomains(domain, wordlist, threads)
    print(f"[*] Discovered {len(discovered_subdomains)} subdomains:")
    for subdomain in discovered_subdomains:
        print(subdomain)