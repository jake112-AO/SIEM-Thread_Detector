import requests

_geo_cache = {}  # simple in-memory cache: ip -> result, avoids repeat API calls for the same IP

def lookup_ip(ip: str) -> dict | None:
    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = response.json()
    except requests.RequestException:
        _geo_cache[ip] = None
        return None

    if data.get("status") != "success":
        _geo_cache[ip] = None
        return None

    result = {
        "geo.country_name": data.get("country"),
        "geo.city_name": data.get("city"),
        "geo.location": {"lat": data.get("lat"), "lon": data.get("lon")},
        "geo.isp": data.get("isp"),
    }
    _geo_cache[ip] = result
    return result


if __name__ == "__main__":
    test_ips = [
        "8.8.8.8",        # Google DNS - real public IP
        "1.1.1.1",        # Cloudflare DNS - real public IP
        "10.0.0.5",       # our fake internal IP - should return None
    ]
    for ip in test_ips:
        result = lookup_ip(ip)
        print(f"{ip}: {result}")
