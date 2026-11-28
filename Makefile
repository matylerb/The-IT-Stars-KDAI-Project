.PHONY: help up down logs test \
        replay-brute replay-dirscan replay-sqli replay-benign \
        attack-brute attack-dirscan attack-chain \
        demo-brute demo-dirscan demo-sqli \
        benign-start benign-stop demo-live evaluate

PYTHON  = python
REPLAY  = $(PYTHON) src/replay.py
AGENT   = $(PYTHON) src/agent/main.py --stdin

# ── help ────────────────────────────────────────────────────────────────────

help:
	@echo ""
	@echo "  KDAI Incident Advisor — demo commands"
	@echo ""
	@echo "  Docker (live system):"
	@echo "    make up            start Juice Shop + nginx + agent"
	@echo "    make down          stop everything"
	@echo "    make logs          follow the agent's output"
	@echo ""
	@echo "  Replay (no Docker needed — alerts print to console):"
	@echo "    make replay-brute  brute-force login (critical, possible compromise)"
	@echo "    make replay-dirscan  directory scan (medium)"
	@echo "    make replay-sqli   SQL injection (high)"
	@echo "    make replay-benign benign traffic — no alerts expected"
	@echo ""
	@echo "  Live attacks (Docker must be running):"
	@echo "    make attack-brute  run the brute-force script against localhost:8080"
	@echo "    make attack-dirscan  run the directory scan script"
	@echo "    make attack-chain  dir scan then SQL injection (chain scenario)"
	@echo ""
	@echo "  Quick demo shortcuts (replay + nice header):"
	@echo "    make demo-brute    highlight the critical brute-force scenario"
	@echo "    make demo-dirscan  highlight the dir-scan scenario"
	@echo "    make demo-sqli     highlight the SQL injection scenario"
	@echo ""
	@echo "  Evaluation:"
	@echo "    make test          run the full test suite"
	@echo "    make evaluate      detector recall / false-positive rate / latency"
	@echo ""
	@echo "  Live demo with background traffic (Docker must be running):"
	@echo "    make benign-start  start Locust benign traffic in the background"
	@echo "    make benign-stop   stop Locust"
	@echo "    make demo-live     benign traffic + all attacks in sequence (one command)"
	@echo ""

# ── Docker ──────────────────────────────────────────────────────────────────

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f agent

# ── Replay (no Docker) ──────────────────────────────────────────────────────

replay-brute:
	$(REPLAY) data/brute_force_logs.jsonl --speed 0 | $(AGENT)

replay-dirscan:
	$(REPLAY) data/dir_scan_logs.jsonl --speed 0 | $(AGENT)

replay-sqli:
	$(REPLAY) data/sqlmap_logs.jsonl --speed 0 | $(AGENT)

replay-benign:
	$(REPLAY) data/locust_logs.jsonl --speed 0 | $(AGENT)

# ── Live attacks (Docker must be running) ───────────────────────────────────

attack-brute:
	$(PYTHON) src/attacks/brute_force.py

attack-dirscan:
	$(PYTHON) src/attacks/dir_scan.py

# Dir scan from one IP then SQL injection from the same IP — triggers R2/R3 chain rule
attack-chain:
	$(PYTHON) src/attacks/dir_scan.py --fake-ip 10.0.0.90
	$(PYTHON) src/attacks/brute_force.py --fake-ip 10.0.0.90

# ── Demo shortcuts ───────────────────────────────────────────────────────────

demo-brute:
	@echo ""
	@echo "=== DEMO: brute-force login (expect: critical, possible compromise) ==="
	@echo ""
	$(REPLAY) data/brute_force_logs.jsonl --speed 0 | $(AGENT)

demo-dirscan:
	@echo ""
	@echo "=== DEMO: directory scan (expect: medium) ==="
	@echo ""
	$(REPLAY) data/dir_scan_logs.jsonl --speed 0 | $(AGENT)

demo-sqli:
	@echo ""
	@echo "=== DEMO: SQL injection (expect: high) ==="
	@echo ""
	$(REPLAY) data/sqlmap_logs.jsonl --speed 0 | $(AGENT)

# ── Evaluation ───────────────────────────────────────────────────────────────

test:
	$(PYTHON) -m pytest -q

evaluate:
	PYTHONPATH=src $(PYTHON) -m evaluate

# ── Benign background traffic (Docker must be running) ───────────────────────

# Start Locust headless: 5 simulated shoppers, 1 spawned per second, runs until stopped.
# PID is saved so benign-stop can kill it cleanly.
benign-start:
	locust -f src/traffic/locust_benign.py \
	       --host http://localhost:8080 \
	       --headless -u 5 -r 1 \
	       --run-time 99999s \
	       &echo $$! > .locust.pid
	@echo "Locust started (PID $$(cat .locust.pid)). Run 'make benign-stop' to stop."

benign-stop:
	@if [ -f .locust.pid ]; then \
	    kill $$(cat .locust.pid) 2>/dev/null && echo "Locust stopped." || echo "Already stopped."; \
	    rm -f .locust.pid; \
	else \
	    echo "No .locust.pid found — nothing to stop."; \
	fi

# Full live demo: benign traffic in the background, all three attacks in sequence.
# Waits 5 s between attacks so the agent has time to alert before the next one.
demo-live:
	@echo ""
	@echo "=== Starting benign background traffic ==="
	locust -f src/traffic/locust_benign.py \
	       --host http://localhost:8080 \
	       --headless -u 5 -r 1 \
	       --run-time 99999s \
	       &echo $$! > .locust.pid
	@sleep 3
	@echo ""
	@echo "=== ATTACK 1: directory scan (expect: medium alert) ==="
	$(PYTHON) src/attacks/dir_scan.py
	@sleep 5
	@echo ""
	@echo "=== ATTACK 2: brute-force login (expect: critical alert) ==="
	$(PYTHON) src/attacks/brute_force.py
	@sleep 5
	@echo ""
	@echo "=== ATTACK 3: chain — dir scan then SQLi from same IP (expect: critical) ==="
	$(PYTHON) src/attacks/dir_scan.py --fake-ip 10.0.0.90
	$(PYTHON) src/attacks/brute_force.py --fake-ip 10.0.0.90
	@echo ""
	@echo "=== Stopping benign traffic ==="
	@kill $$(cat .locust.pid) 2>/dev/null; rm -f .locust.pid
	@echo "Done. Check 'make logs' for agent alerts."
