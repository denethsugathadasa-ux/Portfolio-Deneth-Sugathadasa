import requests
import json

API_KEY = "your API key"
BASE_URL = "https://www.virustotal.com/api/v3"

def print_banner():
    print("\n" + "=" * 60)
    print("   Threat Intelligence Module — Powered by VirusTotal")
    print("=" * 60)
    print("   Analyse URLs, IPs and file hashes for threats")
    print("=" * 60)

def analyse_url(url):
    print(f"\n  Analysing URL: {url}")
    print("  Please wait...")
    
    # Submit URL for analysis
    headers = {"x-apikey": API_KEY}
    response = requests.post(
        f"{BASE_URL}/urls",
        headers=headers,
        data={"url": url}
    )
    
    if response.status_code != 200:
        print(f"  [!] Error submitting URL: {response.status_code}")
        return
    
    analysis_id = response.json()["data"]["id"]
    
    # Get analysis results
    result = requests.get(
        f"{BASE_URL}/analyses/{analysis_id}",
        headers=headers
    ).json()
    
    stats = result["data"]["attributes"]["stats"]
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    print(f"\n  {'='*50}")
    print(f"  URL:         {url}")
    print(f"  {'='*50}")
    print(f"  Malicious:   {malicious}/{total} engines flagged")
    print(f"  Suspicious:  {suspicious}/{total} engines flagged")
    print(f"  Harmless:    {harmless}/{total} engines")
    print(f"  Undetected:  {undetected}/{total} engines")
    print(f"  {'='*50}")
    
    if malicious > 0:
        print(f"   THREAT DETECTED — {malicious} engines flagged this as malicious")
    elif suspicious > 0:
        print(f"   SUSPICIOUS — {suspicious} engines flagged this as suspicious")
    else:
        print(f"   CLEAN — no threats detected")

def analyse_ip(ip):
    print(f"\n  Analysing IP: {ip}")
    print("  Please wait...")
    
    headers = {"x-apikey": API_KEY}
    response = requests.get(
        f"{BASE_URL}/ip_addresses/{ip}",
        headers=headers
    ).json()
    
    try:
        attrs = response["data"]["attributes"]
        malicious = attrs["last_analysis_stats"].get("malicious", 0)
        suspicious = attrs["last_analysis_stats"].get("suspicious", 0)
        harmless = attrs["last_analysis_stats"].get("harmless", 0)
        undetected = attrs["last_analysis_stats"].get("undetected", 0)
        total = malicious + suspicious + harmless + undetected
        country = attrs.get("country", "Unknown")
        owner = attrs.get("as_owner", "Unknown")

        print(f"\n  {'='*50}")
        print(f"  IP Address:  {ip}")
        print(f"  Country:     {country}")
        print(f"  Owner:       {owner}")
        print(f"  {'='*50}")
        print(f"  Malicious:   {malicious}/{total} engines flagged")
        print(f"  Suspicious:  {suspicious}/{total} engines flagged")
        print(f"  Harmless:    {harmless}/{total} engines")
        print(f"  {'='*50}")

        if malicious > 0:
            print(f"   THREAT DETECTED — {malicious} engines flagged this IP")
        elif suspicious > 0:
            print(f"   SUSPICIOUS — {suspicious} engines flagged this IP")
        else:
            print(f"   CLEAN — no threats detected")
    except:
        print("  [!] Could not retrieve IP data")

def main():
    print_banner()
    
    while True:
        print("\n  What would you like to analyse?")
        print("  [1] URL")
        print("  [2] IP Address")
        print("  [3] Exit")
        print("")
        
        choice = input("  Enter choice (1/2/3): ").strip()
        
        if choice == "1":
            url = input("  Enter URL to analyse: ").strip()
            analyse_url(url)
        elif choice == "2":
            ip = input("  Enter IP address to analyse: ").strip()
            analyse_ip(ip)
        elif choice == "3":
            print("\n  Exiting Threat Intelligence Module. Goodbye.\n")
            break
        else:
            print("  [!] Invalid choice, please try again.")
        
        print("")
        again = input("  Analyse another? (y/n): ").strip().lower()
        if again != "y":
            print("\n  Session ended.\n")
            break

if __name__ == "__main__":
    main()