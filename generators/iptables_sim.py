import random
import time
from datetime import datetime, timezone

LOG_FILE = "logs/iptables.log"
HOSTNAME = "firewall01"

def make_log_line(counter):
    now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
    src_ip = f"203.0.113.{random.randint(2, 254)}"   # pretend "internet" attacker range
    dst_ip = f"10.0.0.{random.randint(2, 50)}"
    dport = random.choice([22, 23, 3389, 445, 80, 443])  # common attacked ports
    sport = random.randint(40000, 60000)
    action = random.choices(["DROP", "ACCEPT"], weights=[0.7, 0.3])[0]

    uptime = counter * 1.37  # fake kernel uptime counter, always increasing

    return (
        f"{now} {HOSTNAME} kernel: [{uptime:.6f}] IPTABLES-{action}: "
        f"IN=eth0 OUT= SRC={src_ip} DST={dst_ip} LEN=60 TTL=64 "
        f"PROTO=TCP SPT={sport} DPT={dport} SYN"
    )

if __name__ == "__main__":
    print(f"Writing fake firewall events to {LOG_FILE} — press Ctrl+C to stop")
    counter = 0
    with open(LOG_FILE, "a") as f:
        while True:
            counter += 1
            line = make_log_line(counter)
            f.write(line + "\n")
            f.flush()
            print(line)
            time.sleep(random.uniform(0.5, 2))
