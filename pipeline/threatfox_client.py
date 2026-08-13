import os
import json
import requests
from dotenv import load_dotenv

load_dotenv()

CACHE_FILE = "pipeline/.state/threatfox_malicious_ips.json"
API_URL = "https://threatfox-api.abuse.ch/api/v1/"

def fetch_malicious_ips(days=7):
    """
    Pulls recent IP-based IOCs from ThreatFox and caches them locally.
    ThreatFox reports IPs in "ip:port" format (e.g. "1.2.3.4:443") -
    we only care about the IP part for matching against our own
    traffic's source.ip field.
    """
    auth_key = os.getenv("THREATFOX_AUTH_KEY")
    if not auth_key:
        raise ValueError("THREATFOX_AUTH_KEY not found - check your .env file")

    headers = {"Auth-Key": auth_key}
    payload = {"query": "get_iocs", "days": days}

    response = requests.post(API_URL, json=payload, headers=headers, timeout=10)
    data = response.json()

    if data.get("query_status") != "ok":
        raise RuntimeError(f"ThreatFox query failed: {data.get('query_status')}")

    malicious_ips = set()
    for ioc in data.get("data", []):
        if ioc.get("ioc_type") == "ip:port":
            ip = ioc["ioc"].split(":")[0]
            malicious_ips.add(ip)

    os.makedirs("pipeline/.state", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(list(malicious_ips), f, indent=2)

    return malicious_ips


def load_cached_ips():
    if not os.path.exists(CACHE_FILE):
        return set()
    with open(CACHE_FILE) as f:
        return set(json.load(f))


if __name__ == "__main__":
    print("Fetching malicious IPs from ThreatFox (abuse.ch)...")
    ips = fetch_malicious_ips()
    print(f"Cached {len(ips)} malicious IPs from ThreatFox.")
    if ips:
        print("Sample:", list(ips)[:5])