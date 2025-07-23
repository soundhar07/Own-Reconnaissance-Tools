import json

cve_file = "nvdcve-1.1-recent.json"

def find_cve(service_name, version=""):
    with open(cve_file, "r") as f:
        cve_data = json.load(f)

    matches = []

    for item in cve_data["CVE_Items"]:
        desc = item["cve"]["description"]["description_data"][0]["value"]
        if service_name.lower() in desc.lower():
            if version:
                if version.lower() in desc.lower():
                    cve_id = item["cve"]["CVE_data_meta"]["ID"]
                    matches.append((cve_id, desc))
            else:
                cve_id = item["cve"]["CVE_data_meta"]["ID"]
                matches.append((cve_id, desc))

    return matches

if __name__ == "__main__":
    service_name = input("Enter the service name: ")
    version = input("Enter the version (or leave blank): ")
    matches = find_cve(service_name, version)

    if matches:
        print(f"\nMatches found for {service_name} {version}:\n")
        for cve_id, desc in matches:
            print(f"CVE ID: {cve_id}")
            print(f"Description: {desc}\n")
    else:
        print("No matches found.")
