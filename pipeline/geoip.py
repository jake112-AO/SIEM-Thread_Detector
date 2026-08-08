import requests

def lookup_ip(ip: str) -> dict | None:
    """
    Looks up geographic info for a public IP address using ip-api.com's
    free API. Returns None for private/reserved IPs (10.x, 192.168.x,
    etc.) since those have no real-world location - this is expected
    and correct behavior, not a bug.

    NOTE: In a real production SIEM, you'd typically use a local
    MaxMind GeoLite2 database file instead of a live API call - it's
    faster (no network round-trip per lookup), has no rate limits,
    and still works if your network is air-gapped. We're using the
    free API here for speed of setup; swapping to a local DB later
    would only require changing this one function.
    """
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
    except requests.RequestException:
        return None

    if data.get("status") != "success":
        return None

    return {
        "geo.country_name": data.get("country"),
        "geo.city_name": data.get("city"),
        "geo.location": {"lat": data.get("lat"), "lon": data.get("lon")},
        "geo.isp": data.get("isp"),
    }


if __name__ == "__main__":
    test_ips = [
        "8.8.8.8",        # Google DNS - real public IP
        "1.1.1.1",        # Cloudflare DNS - real public IP
        "10.0.0.5",       # our fake internal IP - should return None
    ]
    for ip in test_ips:
        result = lookup_ip(ip)
        print(f"{ip}: {result}")
