# Detection → Agent Integration Handoff

**From:** Cillian (Detection Engineer)
**To:** Tyler (AI Integration Engineer), and any AI assistant helping him
**Project:** KDAI Incident Advisor, The IT Stars
**Status:** Detector v1 is finished, tested (59 tests passing) and merged to `main`.

---

## 1. TL;DR

The detector is a single Python class. Create it **once**, feed it **every** access-log line **in order**, and it returns a list of `DetectionEvent`s. Usually the list is empty. When it isn't, each event is a **new incident** that should go to the knowledge graph, the LLM and the WhatsApp/Telegram alert.

```python
from detection.detector import Detector

det = Detector()                       # once, at startup (it keeps state)
for line in follow("access.log"):      # every new line, in order
    for event in det.process_line(line):
        handle(event.to_dict())        # → Ivan's knowledge graph → LLM → alert
```

The detector already handles parsing, bad lines, deduplication and cooldowns. **Don't re-implement any of them.**

---

## 2. What already exists (don't rebuild)

| File | What it does |
|---|---|
| `src/parser.py` | Illya's log parser. `parse_line(line)` raises `ParseError` on bad lines. `iter_events(lines)` skips them. |
| `src/detection/features.py` | URL decoding, path normalisation, static/sensitive path checks |
| `src/detection/rules.py` | Stateless SQLi and XSS regex rules (`check_request`) |
| `src/detection/stateful.py` | Per-IP 60s sliding windows for brute force and directory scans |
| `src/detection/events.py` | `DetectionEvent` dataclass, the output schema |
| `src/detection/detector.py` | **`Detector`, the only thing you need to import** |
| `src/detection/evaluate.py` | Metrics on the labelled dataset (Cillian's, not needed for integration) |
| `src/replay.py` | Illya's script: replays a recorded JSONL log to **stdout** with the original timing (`--speed`) |
| `src/agent/main.py` | Placeholder: waits for `access.log` and prints new lines. **This is what you replace.** |

**Import path:** all imports assume `src/` is on `PYTHONPATH`, using `from detection.detector import Detector` and `from parser import ...`. Locally, run with `PYTHONPATH=src`. In Docker, see section 6.

---

## 3. The interface contract

### `Detector(...)`
```python
Detector(
    sqli_threshold=0.7,   # SQLi/XSS rule confidence needed to fire
    use_tool_ua=False,    # True = also flag known attack-tool user agents (sqlmap etc.)
    cooldown_s=300,       # same IP + same attack within 5 min = same incident, no new alert
    # passed through to the sliding windows:
    window_s=60, bf_threshold=5, scan_sensitive=5, scan_distinct=45,
)
```
Use the defaults. They're tuned on the labelled dataset.

### `det.process_line(line: str) -> list[DetectionEvent]`
- Takes **one raw line** from `access.log`, with or without a trailing newline.
- Returns `[]` for normal traffic **and** for malformed lines, so it never raises on bad input.
- Use this in the live pipeline.

### `det.process(rec: dict) -> list[DetectionEvent]`
- The same thing, but for an already-parsed record (the output of `parser.parse_line`). Use it if you parse yourself.

### `event.to_dict() -> dict` / `event.to_json() -> str`
JSON-ready. Example of a real event from the dataset:
```json
{
  "event_id": "48207b18-37eb-49fb-85b3-3fbd4f1cacb4",
  "detected_at": "2026-11-18T21:56:11.921187+00:00",
  "attack_type": "brute_force",
  "severity": "high",
  "confidence": 0.75,
  "src_ip": "10.0.0.60",
  "window_start": "2026-11-18T00:51:28+00:00",
  "window_end": "2026-11-18T00:51:29+00:00",
  "request_count": 5,
  "rule_ids": ["BF-LOGIN-401"],
  "evidence": [
    {"ts": "2026-11-18T00:51:28+00:00", "method": "POST", "path": "/rest/user/login", "query": "", "status": 401}
  ],
  "possible_compromise": false,
  "owasp": "A07:2021-Identification and Authentication Failures",
  "mitre": "T1110.001"
}
```

### Field reference
| Field | Values / meaning |
|---|---|
| `attack_type` | `sqli`, `xss`, `brute_force`, `dir_scan` |
| `severity` | `low`, `medium`, `high`, `critical` |
| `confidence` | 0.0–1.0 |
| `src_ip` | attacker IP (first IP from `X-Forwarded-For`, already cleaned by the parser) |
| `window_start` / `window_end` | log timestamps of the first and last request that triggered the event |
| `request_count` | requests in the triggering window |
| `rule_ids` | which rules fired, e.g. `SQLI-UNION`, `SCAN-SENSITIVE-PATHS`, `BF-SUCCESS-AFTER-FAIL` |
| `evidence` | up to 5 example requests (`ts`, `method`, `path`, `query`, `status`). `query` is still URL-encoded |
| `possible_compromise` | `true` = a successful login straight after a brute-force burst. **Treat as the most urgent alert.** |
| `owasp` / `mitre` | standard IDs, filled in automatically, for linking into Ivan's knowledge graph |

### What severity means (suggested alert behaviour)
| Severity | When | Suggested action |
|---|---|---|
| `critical` | brute force followed by a successful login (`possible_compromise: true`) | Alert immediately, marked urgent |
| `high` | SQL injection, brute force in progress | Alert immediately |
| `medium` | directory scan, XSS | Alert, lower priority |
| `low` | (not used in v1) | Log only |

---

## 4. Behaviour you must know about

1. **One attack produces one event, not hundreds.** sqlmap sent 166 requests in the dataset, and the detector emits **1** SQLi event. Later hits from the same IP and attack type within `cooldown_s` (default 5 min) are folded into that incident silently. Every hit resets the timer. **Don't add extra deduplication.**
2. **Brute force produces two events by design:** first `high` (5 failures), then `critical` with `possible_compromise: true` if the attacker then logs in successfully. The second one is an escalation, not a duplicate. Both should alert.
3. **State lives inside the `Detector` instance.** Create it **once** for the lifetime of the agent. A new `Detector` per line breaks brute force and scan detection.
4. **Feed lines in order and don't skip any.** Brute force and scan detection count requests per IP over 60s. Skipping lines, sampling, or processing them in parallel threads breaks the counting.
5. **Time comes from the log's `ts`, not the system clock.** This is why `replay.py --speed 100` gives exactly the same detections as real time. `detected_at` is the only wall-clock field.
6. **`process_line` is fast and synchronous** (pure regex and deque operations). It's safe to call inline. Do the slow work (knowledge graph, LLM, WhatsApp/Telegram) **after** it returns, ideally in a queue or worker, so a slow LLM call never makes the log reader fall behind.
7. **Request bodies aren't logged** (nginx writes `"body": ""`), so XSS is only detected in query strings. That's a known limitation, not a bug.

---

## 5. What Tyler needs to build

### 5.1 Replace `src/agent/main.py`
Requirements:
- **Input modes:**
  - default: follow `/logs/access.log` (or whatever path `docker-compose.yml` mounts the shared `nginx_logs` volume at; check the compose file)
  - `--stdin`: read lines from stdin, so `replay.py` can be piped in for the demo fallback and for testing
- **Follow logic:**
  - wait for the file to exist (the current placeholder already does this)
  - start at the **end** of the file in live mode, so old traffic isn't re-alerted when the agent restarts
  - handle partial lines, i.e. only process complete `\n`-terminated lines
- Create one `Detector()` at startup.
- For each event: log it, then hand it to the knowledge graph, LLM and alert pipeline.

Reference sketch (adapt freely):
```python
import argparse, json, logging, os, sys, time
from detection.detector import Detector

log = logging.getLogger("agent")

def follow(path, from_start=False, poll=0.2):
    while not os.path.exists(path):
        time.sleep(1)
    with open(path, "r") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        buf = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(poll)
                continue
            buf += chunk
            if buf.endswith("\n"):
                yield buf
                buf = ""

def handle(event: dict):
    log.warning("DETECTION %s", json.dumps(event))
    # 1. knowledge graph enrichment (Ivan) e.g. kg.enrich(event)
    # 2. LLM incident summary / advice
    # 3. send WhatsApp/Telegram alert (urgent if possible_compromise)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=os.environ.get("ACCESS_LOG", "/logs/access.log"))
    ap.add_argument("--stdin", action="store_true")
    ap.add_argument("--from-start", action="store_true")
    args = ap.parse_args()

    det = Detector()
    lines = sys.stdin if args.stdin else follow(args.log, args.from_start)
    for line in lines:
        for ev in det.process_line(line):
            handle(ev.to_dict())

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    main()
```

### 5.2 Make the detector importable inside the agent container ⚠️
This is the most likely thing to break. The agent image currently builds from `src/agent/`, but it now needs `src/parser.py` and `src/detection/` too. A Docker build can't `COPY` files from outside its build context, so `COPY ../detection` won't work.

Recommended fix:
1. In `docker-compose.yml`, set the agent's build context to the **repo root** and point at the Dockerfile:
   ```yaml
   agent:
     build:
       context: .
       dockerfile: src/agent/Dockerfile
   ```
2. In `src/agent/Dockerfile`, copy `src/` and put it on the path:
   ```dockerfile
   WORKDIR /app
   COPY src/agent/requirements.txt .
   RUN pip install --no-cache-dir -r requirements.txt
   COPY src/ /app/src/
   ENV PYTHONPATH=/app/src
   CMD ["python", "/app/src/agent/main.py"]
   ```
3. The detector uses **only the Python standard library**, so it adds nothing to `requirements.txt`.

Check: `docker compose build agent && docker compose run --rm agent python -c "from detection.detector import Detector; print('ok')"`

### 5.3 Hand events to the knowledge graph (with Ivan)
- Ivan's side consumes `event.to_dict()` exactly as shown in section 3. Agree with him whether that's a function call (`kg.enrich(event)`), a queue or HTTP.
- Useful join keys for the graph: `attack_type`, `owasp`, `mitre` and `rule_ids`.

### 5.4 Alerts (WhatsApp/Telegram)
- Good things to put in the message: `attack_type`, `severity`, `src_ip`, `request_count`, the window times, the `possible_compromise` flag, and one or two `evidence` paths. For SQLi evidence, URL-decode `query` before showing it (`urllib.parse.unquote_plus`).
- Make `possible_compromise: true` visually distinct (e.g. 🚨 CRITICAL).
- If messaging fails, catch the error and keep processing logs. A failed alert must never stop detection.

### 5.5 Stretch: human feedback (roadmap day 13)
If the alert lets the user reply "false positive" or "confirmed":
- store `(event_id, attack_type, rule_ids, src_ip, verdict)`, e.g. in a JSONL file
- Cillian will use these to tune thresholds. The live detector's thresholds can also be changed at runtime:
  - `det.sqli_threshold`
  - `det.windows.bf_threshold`
  - `det.windows.scan_sensitive`
  - `det.windows.scan_distinct`
- Agree the feedback file format with Cillian before building it.

---

## 6. How to test the integration

**Unit tests (must stay green):**
```bash
PYTHONPATH=src pytest -q          # 59 passed
```

**Replay a recorded attack through the full pipeline (no Docker needed):**
```bash
PYTHONPATH=src python src/replay.py data/brute_force_logs.jsonl --speed 50 \
  | PYTHONPATH=src python src/agent/main.py --stdin
```
Check `replay.py --help` for its exact arguments. Expected results:
| Replayed file | Expected events |
|---|---|
| `data/brute_force_logs.jsonl` | 2: `brute_force` high, then `brute_force` critical with `possible_compromise: true` |
| `data/dir_scan_logs.jsonl` | 1: `dir_scan` medium |
| `data/sqlmap_logs.jsonl` | 1: `sqli` high |
| `data/locust_logs.jsonl` / `data/sample_logs.jsonl` | 0 |

**Live, end to end:**
```bash
docker compose up --build
python src/attacks/brute_force.py
python src/attacks/dir_scan.py
# sqlmap against /rest/products/search, as in the overview
```
Expect one alert per attack (two for brute force), and none from normal Locust traffic.

**Demo-day fallback:** if live traffic misbehaves, pipe `replay.py` into `main.py --stdin` as shown above.

---

## 7. Don'ts
- Don't create a new `Detector` per line or per request.
- Don't call `parser.parse_line` without catching `ParseError`. Prefer `det.process_line`, which already handles it.
- Don't feed lines out of order or from multiple threads into one detector.
- Don't add deduplication or cooldown logic. It's built in.
- Don't send the `label` field to the detector (it only exists in the labelled dataset).
- Don't edit files in `src/detection/` without telling Cillian. The evaluation metrics depend on them.

---

## 8. Measured performance (for context)
On `data/labelled_dataset.jsonl` (968 requests), with the default settings:

| Attack | Precision | Recall | Notes |
|---|---|---|---|
| SQLi | 1.00 | 0.976 (162/166) | 4 misses are sqlmap baseline requests (`q=test`) that look exactly like normal searches. 166/166 with `use_tool_ua=True` |
| Brute force | 1.00 | 1.00 (17/17) | |
| Dir scan | 1.00 | 1.00 (66/66) | |
| Benign | 0 of 719 flagged | | |

Every attack run was detected, producing 4 alerts in total.

**Questions:** ask Cillian.
