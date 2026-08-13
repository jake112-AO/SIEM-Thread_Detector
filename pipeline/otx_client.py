import os
import json
from dotenv import load_dotenv
from OTXv2 import OTXv2

load_dotenv()  # reads OTX_API_KEY from the .env file into the environment

CACHE_FILE = "pipeline/.state/otx_malicious_ips.json"

def fetch_malicious_ips(max_pulses=20):
    """
    Pulls IP indicators from OTX's subscribed pulses (by default, every
    new account is auto-subscribed to AlienVault's own general threat
    feed) and caches them locally as a flat list of IPs. Caching matters
    here - OTX's free tier has rate limits, and our rule runner checks
    every 60 seconds, so we don't want to hit the live API that often.
    """
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        raise ValueError("OTX_API_KEY not found - check your .env file")

    otx = OTXv2(api_key)
    malicious_ips = set()

    pulses = otx.getall(max_page=1)  # first page of subscribed pulses
    for pulse in pulses[:max_pulses]:
        for indicator in pulse.get("indicators", []):
            if indicator.get("type") in ("IPv4", "IPv6"):
                malicious_ips.add(indicator["indicator"])

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
    print("Fetching malicious IPs from AlienVault OTX...")
    ips = fetch_malicious_ips()
    print(f"Cached {len(ips)} malicious IPs from OTX pulses.")
    if ips:
        print("Sample:", list(ips)[:5])