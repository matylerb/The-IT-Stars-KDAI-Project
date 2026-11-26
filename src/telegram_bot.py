"""
Telegram alerts with one-tap buttons (Tyler). Human in the loop.

send_alert() posts the alert with one button per CSP-approved action, plus two
"Ignore" buttons. When a button is pressed, handle_button():
  1. checks it came from our chat and the action is still one the CSP allowed
  2. carries out the action as a DRY RUN: "Block IP" appends a line to
     data/nginx_deny.dryrun.conf; nothing else changes on the server
  3. records the human's verdict in Illya's feedback store
       action button          -> confirmed       (the IP becomes a known attacker
                                                  in the knowledge graph straight away)
       "Ignore: normal"       -> false_positive  (feeds threshold tuning)
       "Ignore: not sure"     -> dismissed
  4. edits the message: removes the buttons (no double taps) and says who chose what

Uses the Telegram Bot HTTP API directly (standard library only).
"""
import html
import json
import logging
import os
import threading
import time
import urllib.request
from datetime import datetime, timezone

from feedback.store import FeedbackStore
from knowledge.enrich import get_graph
from knowledge.feedback_facts import learn_from_feedback

log = logging.getLogger("telegram")

API = "https://api.telegram.org/bot{token}/{method}"
DENY_FILE = "data/nginx_deny.dryrun.conf"
IGNORE = {"fp": ("Ignore: normal traffic", "false_positive"),
          "unsure": ("Ignore: not sure", "dismissed")}


def format_alert(event, plan, alert):
    """Alert text as Telegram HTML. Everything is escaped (evidence can contain HTML)."""
    e = html.escape
    icon = "🚨" if event.get("possible_compromise") else "⚠️"
    lines = [
        f"{icon} <b>{e(plan.severity.upper())}: {e(event['attack_type'])} from {e(event['src_ip'])}</b>",
        "",
        "<b>What happened</b>",
        e(alert["what_happened"]),
        "",
        "<b>How serious it is and why</b>",
        e(alert["how_serious"]),
        "",
        "<b>Safe actions</b>",
    ]
    for action_id, text in alert["actions"].items():
        label = plan.action_labels.get(action_id, action_id)
        lines.append(f"• <b>{e(label)}</b>" + (f": {e(text)}" if text != label else ""))
    if not alert["actions"]:
        lines.append("None available. Keep monitoring.")
    if alert.get("why"):
        lines += ["", "<b>Why these actions</b> (knowledge graph and safety rules)"]
        lines += [f"• {e(line)}" for line in alert["why"]]
    lines += ["", "<i>Dry run: nothing changes until you tap a button.</i>"]
    return "\n".join(lines)


def keyboard(event, plan):
    """One button per approved action, then the two Ignore buttons."""
    key = event["event_id"][:8]
    rows = [[{"text": plan.action_labels.get(a, a), "callback_data": f"{key}|{a}"}]
            for a in plan.allowed_actions]
    rows.append([{"text": label, "callback_data": f"{key}|{choice}"}
                 for choice, (label, _) in IGNORE.items()])
    return {"inline_keyboard": rows}


class TelegramBot:
    def __init__(self, token, chat_id, store=None, deny_file=DENY_FILE, kg=None):
        self.token = token
        self.chat_id = str(chat_id)
        self.store = store or FeedbackStore()
        self.kg = kg or get_graph()
        self.deny_file = deny_file
        self.pending = {}               # event key -> (event, plan, message html)
        self.lock = threading.Lock()

    def call(self, method, **params):
        req = urllib.request.Request(
            API.format(token=self.token, method=method),
            data=json.dumps(params).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=40) as resp:
            return json.load(resp)["result"]

    # --- sending -----------------------------------------------------------------

    def send_alert(self, event, plan, alert):
        text = format_alert(event, plan, alert)
        try:
            self.call("sendMessage", chat_id=self.chat_id, text=text, parse_mode="HTML",
                      reply_markup=keyboard(event, plan))
        except Exception:
            log.exception("could not send Telegram alert")   # never stop detection
            return
        with self.lock:
            self.pending[event["event_id"][:8]] = (event, plan, text)

    # --- button presses ----------------------------------------------------------

    def poll_forever(self):
        offset = None
        while True:
            try:
                updates = self.call("getUpdates", offset=offset, timeout=30,
                                    allowed_updates=["callback_query"])
            except Exception:
                log.exception("getUpdates failed; retrying")
                time.sleep(5)
                continue
            for update in updates:
                offset = update["update_id"] + 1
                if "callback_query" in update:
                    try:
                        self.handle_button(update["callback_query"])
                    except Exception:
                        log.exception("button handling failed")

    def handle_button(self, query):
        """Process one button press. Returns the reply shown to the user."""
        reply = self._decide(query)
        self.call("answerCallbackQuery", callback_query_id=query["id"], text=reply)
        return reply

    def _decide(self, query):
        message = query.get("message") or {}
        if str(message.get("chat", {}).get("id")) != self.chat_id:
            return "Not allowed from this chat."
        key, _, choice = query.get("data", "").partition("|")
        with self.lock:
            entry = self.pending.pop(key, None)
        if entry is None:
            return "This alert was already handled."
        event, plan, text = entry

        if choice in IGNORE:
            label, verdict = IGNORE[choice]
            done = label
        elif choice in plan.allowed_actions:       # never trust callback data blindly
            label, verdict = plan.action_labels.get(choice, choice), "confirmed"
            done = self.dry_run(choice, event)
        else:
            with self.lock:
                self.pending[key] = entry            # keep the alert open
            return "That action is not allowed for this alert."

        user = query.get("from", {})
        who = "@" + user["username"] if user.get("username") else user.get("first_name", "unknown")
        self.store.record(event, verdict=verdict, decided_by=who, note=choice)
        if verdict == "confirmed":
            learn_from_feedback(self.kg, self.store)   # next alert from this IP knows it
        when = datetime.now(timezone.utc).strftime("%H:%M UTC")
        self.call("editMessageText", chat_id=self.chat_id, message_id=message["message_id"],
                  parse_mode="HTML",
                  text=f"{text}\n\n✅ <b>{html.escape(label)}</b> chosen by {html.escape(who)} at {when}")
        return done

    def dry_run(self, action, event):
        """Carry out an approved action without touching the live server."""
        if action == "block_ip":
            os.makedirs(os.path.dirname(self.deny_file) or ".", exist_ok=True)
            with open(self.deny_file, "a") as f:
                f.write(f"deny {event['src_ip']};  # event {event['event_id']} (dry run)\n")
            return f"Dry run: {event['src_ip']} added to {self.deny_file}"
        return f"Dry run: would {action.replace('_', ' ')}"
