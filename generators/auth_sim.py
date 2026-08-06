import random
import time
from datetime import datetime, timezone

LOG_FILE = "logs/auth.log"
USERS = ["jiahao", "alice", "bob", "svc_backup"]
INVALID_USERS = ["admin", "root", "test", "guest", "oracle"]
HOSTNAME = "webserver01"

def make_log_line(pid):
    now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
    port = random.randint(40000, 60000)
    ip = f"10.0.0.{random.randint(2, 50)}"

    # Mostly real users logging in (success/fail), occasionally a bot
    # trying random invalid usernames (that's our "attack flavor" case).
    if random.random() < 0.2:
        user = random.choice(INVALID_USERS)
        return f"{now} {HOSTNAME} sshd[{pid}]: Failed password for invalid user {user} from {ip} port {port} ssh2"
    else:
        user = random.choice(USERS)
        if random.random() < 0.75:
            return f"{now} {HOSTNAME} sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
        else:
            return f"{now} {HOSTNAME} sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2"

if __name__ == "__main__":
    print(f"Writing fake SSH auth events to {LOG_FILE} — press Ctrl+C to stop")
    pid = 1000
    with open(LOG_FILE, "a") as f:
        while True:
            pid += 1
            line = make_log_line(pid)
            f.write(line + "\n")
            f.flush()
            print(line)
            time.sleep(random.uniform(1, 3))
