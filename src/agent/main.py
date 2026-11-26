"""
Agent (Tyler): the live pipeline.

    nginx access log -> detector -> knowledge graph -> CSP -> LLM advisor -> alert

Log lines are read in order on the main thread and fed to ONE Detector
(it keeps per-IP state). Each detection is put on a queue; a worker thread
does the slow part (graph, CSP, LLM, Telegram), so a slow LLM call never makes
the log reader fall behind. A failed alert is logged and never stops detection.

Alerts go to Telegram if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are set,
otherwise they are printed to the console.

    python src/agent/main.py                          # follow the live log (Docker)
    python src/replay.py data/brute_force_logs.jsonl --speed 0 | python src/agent/main.py --stdin
"""
import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))   # make src/ importable

from advisor import advise, ask_llm                    # noqa: E402
from detection.detector import Detector                 # noqa: E402
from feedback.store import FeedbackStore                # noqa: E402
from knowledge.enrich import get_graph                  # noqa: E402
from knowledge.feedback_facts import learn_from_feedback  # noqa: E402
from response.selector import make_incident, select_response  # noqa: E402

log = logging.getLogger("agent")
ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def load_env(path=ENV_FILE):
    """Read KEY=value lines from .env into the environment. Variables already set win."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip() and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip())


def follow(path, from_start=False):
    """Yield complete lines from a growing file, like `tail -f`."""
    while not os.path.exists(path):
        log.info("waiting for %s", path)
        time.sleep(2)
    with open(path) as f:
        if not from_start:
            f.seek(0, os.SEEK_END)          # don't re-alert old traffic after a restart
        partial = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(0.2)
                continue
            partial += chunk
            if partial.endswith("\n"):      # only whole lines
                yield partial
                partial = ""


def handle(event, send, llm=ask_llm):
    """One detection -> incident -> CSP plan -> alert -> send."""
    incident = make_incident(event)
    plan = select_response(incident)
    alert = advise(incident, plan, llm)
    send(event, plan, alert)


def print_alert(event, plan, alert):
    print(f"\n=== ALERT: {event['attack_type']} from {event['src_ip']} ({plan.severity}) ===")
    print("What happened: " + alert["what_happened"])
    print("How serious:   " + alert["how_serious"])
    for action_id, text in alert["actions"].items():
        label = plan.action_labels.get(action_id, action_id)
        print(f"  [{label}]" + (f" {text}" if text != label else ""))
    print("Why these actions:")
    for line in alert.get("why", []):
        print("  - " + line)
    print(f"({alert['source']})", flush=True)


def run(lines, send, llm=ask_llm, detector=None):
    """Feed lines to the detector and alert on each detection. Returns when lines run out."""
    det = detector or Detector.from_overrides()
    jobs = queue.Queue()

    def worker():
        while True:
            event = jobs.get()
            try:
                handle(event, send, llm)
            except Exception:
                log.exception("alert failed for event %s", event.get("event_id"))
            finally:
                jobs.task_done()

    threading.Thread(target=worker, daemon=True).start()
    for line in lines:
        for ev in det.process_line(line):
            event = ev.to_dict()
            log.warning("DETECTION %s", json.dumps(event))
            jobs.put(event)
    jobs.join()


def main():
    ap = argparse.ArgumentParser(description="KDAI incident advisor agent")
    ap.add_argument("--log", default=os.environ.get("LOG_PATH", "/var/log/nginx/access.log"))
    ap.add_argument("--stdin", action="store_true", help="read log lines from stdin (replays)")
    ap.add_argument("--from-start", action="store_true", help="read the log file from the beginning")
    args = ap.parse_args()

    load_env()                                           # tokens and keys from .env
    learn_from_feedback(get_graph(), FeedbackStore())   # confirmed attackers from earlier runs

    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
    bot = None
    if token and chat:
        from telegram_bot import TelegramBot
        bot = TelegramBot(token, chat)
        threading.Thread(target=bot.poll_forever, daemon=True).start()   # button presses
        send = bot.send_alert
        log.info("alerts go to Telegram")
    else:
        send = print_alert
        log.info("no TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID: alerts are printed")

    lines = sys.stdin if args.stdin else follow(args.log, args.from_start)
    run(lines, send)

    if bot:                       # replay finished: keep answering button presses
        log.info("input finished; still listening for Telegram buttons (Ctrl+C to stop)")
        while True:
            time.sleep(60)


if __name__ == "__main__":
    sys.stdout.reconfigure(errors="replace")   # a Windows console can't print every character
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    main()
