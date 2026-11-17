"""
Placeholder agent. Tails the nginx JSON access log and prints each new line.
Tyler will replace this with the real detection pipeline.
"""
import time
import os

LOG_PATH = os.environ.get("LOG_PATH", "/var/log/nginx/access.log")

def tail(path: str):
    with open(path, "r") as f:
        while True:
            line = f.readline()
            if line:
                print(line.rstrip(), flush=True)
            else:
                time.sleep(0.5)

if __name__ == "__main__":
    print(f"[agent] watching {LOG_PATH}", flush=True)
    while not os.path.exists(LOG_PATH):
        print("[agent] waiting for log file...", flush=True)
        time.sleep(2)
    tail(LOG_PATH)
