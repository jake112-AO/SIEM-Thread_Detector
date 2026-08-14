import sys
import time
import subprocess
sys.path.append("engine")
sys.path.append("pipeline")

from elasticsearch import Elasticsearch
from correlation_engine import find_bruteforce_then_success
from cross_source_correlation import find_cross_source_attacks
from malicious_ip_detector import find_malicious_ip_connections, get_combined_ioc_list

ES_HOST = "http://localhost:9200"
WATCHER_BUFFER_SECONDS = 15


def check_sigma_rule(client, rule_query, index):
    response = client.search(index=index, q=rule_query, size=1)
    return response["hits"]["total"]["value"] > 0


def inject_malicious_ip_test(ioc_ips):
    from datetime import datetime, timezone
    if not ioc_ips:
        print("  ⚠️  Skipping malicious IP test - no cached IOC data")
        return
    test_ip = list(ioc_ips)[0]
    now = datetime.now(timezone.utc).strftime('%b %e %H:%M:%S')
    line = (f"{now} firewall01 kernel: [999.0] IPTABLES-DROP: IN=eth0 OUT= "
            f"SRC={test_ip} DST=10.0.0.15 LEN=60 TTL=64 PROTO=TCP SPT=12345 DPT=22 SYN")
    with open("logs/iptables.log", "a") as f:
        f.write(line + "\n")


def main():
    client = Elasticsearch(ES_HOST)
    results = {}

    print("=" * 60)
    print("SPRINT 3 DETECTION VALIDATION")
    print("=" * 60)

    print("\n[1/4] Firing attack simulations...")
    subprocess.run(["python3", "generators/attack_sim.py", "chained"], check=True)

    ioc_ips = get_combined_ioc_list()
    inject_malicious_ip_test(ioc_ips)
    print(f"  Injected malicious IP test event")

    print(f"\n[2/4] Waiting {WATCHER_BUFFER_SECONDS}s for watcher to ingest...")
    time.sleep(WATCHER_BUFFER_SECONDS)

    # Time-sensitive checks run FIRST, immediately after the buffer -
    # these depend on a 60-300s sliding window, so every extra second
    # spent on other checks first eats directly into their margin.
    print("\n[3/4] Checking correlation and threat-intel engines (time-sensitive)...")
    bruteforce_alerts = find_bruteforce_then_success(client)
    results["Brute Force -> Successful Login (correlation)"] = len(bruteforce_alerts) > 0
    print(f"  {'✅' if bruteforce_alerts else '❌'} Brute Force -> Successful Login (correlation)")

    cross_source_alerts = find_cross_source_attacks(client)
    results["Port Scan + Brute Force (cross-source)"] = len(cross_source_alerts) > 0
    print(f"  {'✅' if cross_source_alerts else '❌'} Port Scan + Brute Force (cross-source)")

    malicious_ip_alerts = find_malicious_ip_connections(client)
    results["Connection to Known Malicious IP"] = len(malicious_ip_alerts) > 0
    print(f"  {'✅' if malicious_ip_alerts else '❌'} Connection to Known Malicious IP")

    # Single-event Sigma rules run LAST - these check "does this pattern
    # exist anywhere in history" with no time filter, so running them
    # after the time-sensitive checks costs nothing.
    print("\n[4/4] Checking single-event Sigma rules...")
    single_rules = [
        ("SSH Brute Force (failed logins)", "log_source:auth AND event.action:ssh_login AND event.outcome:failure", "siem-parsed-auth-*"),
        ("SSH Successful Login", "log_source:auth AND event.action:ssh_login AND event.outcome:success", "siem-parsed-auth-*"),
        ("New User Account Created", "log_source:auth AND event.action:user_account_created", "siem-parsed-auth-*"),
        ("Sudo Command Executed", "log_source:auth AND event.action:sudo_command", "siem-parsed-auth-*"),
        ("Port Scan (blocked connections)", "log_source:iptables AND event.outcome:failure AND rule.name:IPTABLES\\-DROP", "siem-parsed-iptables-*"),
        ("DNS Tunneling (long subdomains)", "log_source:zeek AND event.action:dns_query", "siem-parsed-zeek-*"),
        ("Web Attack Detected (CICIDS)", 'log_source:cicids AND label.keyword:*Web\\ Attack*', "siem-cicids-*"),
    ]
    for name, query, index in single_rules:
        passed = check_sigma_rule(client, query, index)
        results[name] = passed
        print(f"  {'✅' if passed else '❌'} {name}")

    print("\n" + "=" * 60)
    total = len(results)
    passed = sum(results.values())
    print(f"RESULT: {passed}/{total} detections fired successfully")
    print("=" * 60)

    if passed < total:
        print("\nFailed checks:")
        for name, ok in results.items():
            if not ok:
                print(f"  ❌ {name}")


if __name__ == "__main__":
    main()