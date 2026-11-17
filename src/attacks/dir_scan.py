"""
Directory / path scanning attack simulator.

Requests many URL paths from a wordlist, simulating a tool like Gobuster
probing for hidden admin pages, backups, and config files. Most responses
will be 404 (or Juice Shop's SPA fallback), from one spoofed attacker IP.

Only ever run this against your own local Juice Shop container.

Usage:
    python src/attacks/dir_scan.py
    python src/attacks/dir_scan.py --fake-ip 10.0.0.70 --delay 0.05
"""
import argparse
import json
import time
from datetime import datetime, timezone

import requests

DEFAULT_TARGET = "http://localhost:8080"

# A representative wordlist of paths an attacker/scanner would try.
WORDLIST = [
    "admin", "administrator", "backup", "backups", "config", "configuration",
    "dashboard", "login", "logout", "register", "api", "api/v1", "api/v2",
    "debug", "test", "staging", "dev", "old", "tmp", "temp", "upload",
    "uploads", "files", "static", "assets", "private", "secret", "secrets",
    "db", "database", "sql", "phpmyadmin", "wp-admin", "wp-login.php",
    "env", ".env", ".git", ".git/config", "server-status", "server-info",
    "robots.txt", "sitemap.xml", "swagger", "swagger-ui", "docs", "api-docs",
    "console", "actuator", "metrics", "health", "status", "version",
    "users", "accounts", "profile", "settings", "export", "import",
    "logs", "log", "error", "errors", "exception", "trace",
]


def probe_path(session: requests.Session, target: str, path: str, fake_ip: str) -> int:
    """Request one path with a spoofed attacker IP. Returns the status code."""
    resp = session.get(
        f"{target}/{path}",
        headers={"X-Forwarded-For": fake_ip},
        timeout=10,
    )
    return resp.status_code


def run_dir_scan(target: str, fake_ip: str, delay: float, ground_truth_path: str):
    session = requests.Session()
    start_ts = datetime.now(timezone.utc).isoformat()

    print(f"[dir_scan] scanning {target} with {len(WORDLIST)} paths from {fake_ip}")

    found = []
    for path in WORDLIST:
        status = probe_path(session, target, path, fake_ip)
        marker = " <-- interesting" if status not in (404,) else ""
        print(f"  /{path} -> {status}{marker}")
        if status not in (404,):
            found.append({"path": path, "status": status})
        time.sleep(delay)

    end_ts = datetime.now(timezone.utc).isoformat()

    record = {
        "attack_type": "dir_scan",
        "tool": "src/attacks/dir_scan.py",
        "ip": fake_ip,
        "target_endpoint": target,
        "start_ts": start_ts,
        "end_ts": end_ts,
        "paths_tried": len(WORDLIST),
        "non_404_paths": found,
    }
    with open(ground_truth_path, "a") as f:
        f.write(json.dumps(record) + "\n")
    print(f"[dir_scan] done, {len(WORDLIST)} paths tried, {len(found)} non-404 results.")
    print(f"[dir_scan] logged to {ground_truth_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simulate a directory/path scan.")
    parser.add_argument("--target", default=DEFAULT_TARGET,
                         help="Base URL of the proxied app (default: %(default)s)")
    parser.add_argument("--fake-ip", default="10.0.0.70",
                         help="Spoofed X-Forwarded-For IP for this run (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=0.1,
                         help="Seconds between requests (default: %(default)s)")
    parser.add_argument("--ground-truth", default="data/ground_truth.jsonl",
                         help="File to append this run's record to (default: %(default)s)")
    args = parser.parse_args()

    run_dir_scan(
        target=args.target,
        fake_ip=args.fake_ip,
        delay=args.delay,
        ground_truth_path=args.ground_truth,
    )