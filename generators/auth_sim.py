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
def make_useradd_line(pid):
    now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
    suspicious_names = ["backdoor", "svc_temp", "hacker", "sysupdate"]
    uid = random.randint(1000, 1999)
    name = random.choice(suspicious_names)
    return f"{now} {HOSTNAME} useradd[{pid}]: new user: name={name}, UID={uid}, GID={uid}, home=/home/{name}, shell=/bin/bash"


def make_sudo_line(pid):
    now = datetime.now(timezone.utc).strftime("%b %e %H:%M:%S")
    commands = ["/bin/bash", "/usr/bin/cat /etc/shadow", "/usr/bin/systemctl restart sshd", "/bin/su -"]
    user = random.choice(USERS)
    return f"{now} {HOSTNAME} sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={random.choice(commands)}"

if __name__ == "__main__":
    print(f"Writing fake SSH auth events to {LOG_FILE} — press Ctrl+C to stop")
    pid = 1000
    with open(LOG_FILE, "a") as f:
        while True:
            pid += 1
            roll = random.random()
            if roll < 0.05:
                line = make_useradd_line(pid)       # 5% chance: new account created
            elif roll < 0.10:
                line = make_sudo_line(pid)           # 5% chance: sudo command run
            else:
                line = make_log_line(pid)            # 90% chance: normal SSH login (existing behavior)
            f.write(line + "\n")
            f.flush()
            print(line)
            time.sleep(random.uniform(1, 3))
