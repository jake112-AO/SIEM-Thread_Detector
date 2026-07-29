import json
import random
import time
from datetime import datetime, timezone

LOG_FILE = "logs/auth.log"
USERS = ["jiahao", "alice", "bob", "svc_backup"]

def make_login_event():
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user": random.choice(USERS),
        "src_ip": f"10.0.0.{random.randint(2, 50)}",
        "action": "login",
        "result": random.choice(["success", "success", "success", "failure"]),
    }
    return event

if __name__ == "__main__":
    print(f"Writing fake logins to {LOG_FILE} — press Ctrl+C to stop")
    with open(LOG_FILE, "a") as f:
        while True:
            event = make_login_event()
            line = json.dumps(event)
            f.write(line + "\n")
            f.flush()          # push it to disk immediately, don't wait
            print(line)        # also show it on your screen so you can watch it live
            time.sleep(random.uniform(1, 3))   # wait 1-3 seconds before the next one
