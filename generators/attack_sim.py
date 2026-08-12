import random
import time
import sys
from datetime import datetime, timezone

HOSTNAME = "webserver01"
AUTH_LOG = "logs/auth.log"
IPTABLES_LOG = "logs/iptables.log"


def simulate_ssh_bruteforce(target_user="jiahao", attacker_ip="203.0.113.66", attempts=12, pid_start=9000):
    """
    Simulates a real brute-force pattern: one attacker IP, hammering
    the same username with wrong passwords, then finally succeeding.
    This is the coherent sequence our T-036/T-039 Sigma rules need -
    unlike the background generator, which never produces this on its own.
    """
    print(f"Simulating SSH brute force: {attacker_ip} -> {target_user} ({attempts} attempts)")
    with open(AUTH_LOG, "a") as f:
        for i in range(attempts):
            now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
            pid = pid_start + i
            port = random.randint(40000, 60000)

            is_last = (i == attempts - 1)
            result = "Accepted" if is_last else "Failed"

            line = f"{now} {HOSTNAME} sshd[{pid}]: {result} password for {target_user} from {attacker_ip} port {port} ssh2"
            f.write(line + "\n")
            f.flush()
            print(line)
            time.sleep(0.5)  # fast, tight bursts - real attacker tools don't wait 1-3s like our office noise


def simulate_port_scan(attacker_ip="203.0.113.77", target_ip="10.0.0.15", num_ports=25, pid_start=1):
    """
    Simulates a real port scan: one attacker IP rapidly hitting many
    different destination ports on one target, in quick succession -
    the exact pattern T-037's Sigma rule needs to detect.
    """
    scan_ports = random.sample(range(1, 65535), num_ports)
    print(f"Simulating port scan: {attacker_ip} -> {target_ip} ({num_ports} ports)")
    with open(IPTABLES_LOG, "a") as f:
        for i, port in enumerate(scan_ports):
            now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
            uptime = (pid_start + i) * 0.15
            sport = random.randint(40000, 60000)

            line = (
                f"{now} firewall01 kernel: [{uptime:.6f}] IPTABLES-DROP: "
                f"IN=eth0 OUT= SRC={attacker_ip} DST={target_ip} LEN=60 TTL=64 "
                f"PROTO=TCP SPT={sport} DPT={port} SYN"
            )
            f.write(line + "\n")
            f.flush()
            print(line)
            time.sleep(0.15)  # fast - real port scanners hit many ports per second


if __name__ == "__main__":
    scenario = sys.argv[1] if len(sys.argv) > 1 else "both"

    if scenario == "chained":
        # Same attacker IP does recon (port scan) then credential attack
        # (brute force) - tests T-047's cross-source correlation.
        chained_ip = "203.0.113.88"
        simulate_port_scan(attacker_ip=chained_ip)
        simulate_ssh_bruteforce(attacker_ip=chained_ip)
    elif scenario in ("bruteforce", "both"):
        simulate_ssh_bruteforce()
        if scenario == "both":
            simulate_port_scan()
    elif scenario == "portscan":
        simulate_port_scan()

    print("Attack simulation complete.")
