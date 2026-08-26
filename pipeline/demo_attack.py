import subprocess
import time
import sys

sys.path.append(".")
sys.path.append("pipeline")
sys.path.append("engine")

from datetime import datetime, timezone
from elasticsearch import Elasticsearch
from pipeline.otx_client import load_cached_ips
from engine.correlation_engine import find_bruteforce_then_success
from engine.cross_source_correlation import find_cross_source_attacks
from engine.malicious_ip_detector import find_malicious_ip_connections

ES_HOST = "http://localhost:9200"


def banner(text):
    print("\n" + "=" * 70)
    print(text)
    print("=" * 70)


def wait_for_ingestion(seconds=15):
    print(f"\n⏳ Waiting {seconds}s for the pipeline to ingest and process...")
    time.sleep(seconds)


def scenario_1_recon_and_bruteforce():
    banner("SCENARIO 1: Reconnaissance → Credential Attack (Cross-Source Correlation)")
    print("Simulating an attacker who scans for open ports, then brute-forces SSH")
    print("from the same IP - this should trigger our cross-source correlation rule.")
    subprocess.run(["python3", "generators/attack_sim.py", "chained"], check=True)
    wait_for_ingestion()

    client = Elasticsearch(ES_HOST)
    alerts = find_cross_source_attacks(client)
    if alerts:
        print(f"\n✅ DETECTED: {len(alerts)} cross-source attack(s)")
        for a in alerts:
            print(f"   🚨 {a['source.ip']} — {a['distinct_ports_scanned']} ports scanned, "
                  f"{a['failed_login_attempts']} failed logins [CRITICAL]")
    else:
        print("\n❌ Not detected (may need timing adjustment)")

    bf_alerts = find_bruteforce_then_success(client)
    if bf_alerts:
        print(f"\n✅ ALSO DETECTED: brute-force-then-success correlation")
        for a in bf_alerts:
            print(f"   🚨 {a['source.ip']} — {a['failure_count']} failures, then login as '{a['successful_user']}' [HIGH]")


def scenario_2_known_threat_actor():
    banner("SCENARIO 2: Traffic from a Known Malicious IP (Threat Intel Match)")
    print("Simulating traffic from a real IP flagged by AlienVault OTX / ThreatFox -")
    print("this demonstrates live threat intelligence enrichment, not just pattern matching.")

    ips = load_cached_ips()
    if not ips:
        print("⚠️  No cached threat intel IPs - run pipeline/otx_client.py first")
        return
    test_ip = list(ips)[0]
    now = datetime.now(timezone.utc).strftime('%b %e %H:%M:%S')
    line = (f"{now} firewall01 kernel: [999.0] IPTABLES-DROP: IN=eth0 OUT= "
            f"SRC={test_ip} DST=10.0.0.15 LEN=60 TTL=64 PROTO=TCP SPT=12345 DPT=22 SYN")
    with open("logs/iptables.log", "a") as f:
        f.write(line + "\n")
    print(f"Injected traffic from real known-malicious IP: {test_ip}")
    wait_for_ingestion()

    client = Elasticsearch(ES_HOST)
    alerts = find_malicious_ip_connections(client)
    if alerts:
        print(f"\n✅ DETECTED: {len(alerts)} connection(s) from known-malicious IP(s)")
    else:
        print("\n❌ Not detected")


def scenario_3_insider_activity():
    banner("SCENARIO 3: Suspicious Insider Activity (Account Creation + Privilege Escalation)")
    print("Simulating a compromised account creating a new user and escalating")
    print("privileges via sudo - classic post-exploitation persistence behavior.")
    print("(These fire via the background generator's normal activity and get")
    print(" picked up by the single-event Sigma rules through rule_runner.py)")
    print("\nRun 'python3 pipeline/rule_runner.py' in a separate terminal to see")
    print("these detections fire live during the demo.")


if __name__ == "__main__":
    banner("SIEM ATTACK SIMULATION - FULL DETECTION DEMO")
    print("This script fires realistic attack patterns against the SIEM and")
    print("verifies each one gets detected by the live detection pipeline.")
    print("\nMake sure these are running in other terminals before starting:")
    print("  - generators/auth_sim.py (background noise)")
    print("  - pipeline/watcher.py (ingestion)")
    print("  - pipeline/rule_runner.py (single-event rule detection)")

    scenario_1_recon_and_bruteforce()
    scenario_2_known_threat_actor()
    scenario_3_insider_activity()

    banner("DEMO COMPLETE")
    print("Check the Kibana dashboard and Slack channel for real-time alerts.")