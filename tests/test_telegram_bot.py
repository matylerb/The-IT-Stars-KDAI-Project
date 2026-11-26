"""Tests for the Telegram bot. Telegram itself is never called: bot.call is replaced."""
from advisor import advise
from feedback.store import FeedbackStore
from knowledge.feedback_facts import known_attacks
from knowledge.graph import KnowledgeGraph
from response.selector import make_incident, parse_allowlist, select_response
from telegram_bot import TelegramBot, format_alert, keyboard

CHAT = "12345"


def setup(tmp_path, allow=""):
    event = {
        "event_id": "abcdef1234567890", "attack_type": "brute_force", "severity": "critical",
        "confidence": 0.9, "src_ip": "10.0.0.60", "request_count": 17,
        "rule_ids": ["BF-LOGIN-401"], "evidence": [], "possible_compromise": True,
    }
    incident = make_incident(event)
    plan = select_response(incident, parse_allowlist(allow))
    alert = advise(incident, plan, llm=lambda facts: None)

    bot = TelegramBot("token", CHAT, store=FeedbackStore(str(tmp_path / "feedback.jsonl")),
                      deny_file=str(tmp_path / "deny.conf"), kg=KnowledgeGraph.load())
    bot.sent = []
    bot.call = lambda method, **params: bot.sent.append((method, params)) or {}
    bot.send_alert(event, plan, alert)
    return bot, event, plan


def press(bot, choice, chat=CHAT, user=None):
    return bot.handle_button({
        "id": "q1", "data": f"abcdef12|{choice}", "from": user or {"username": "tyler"},
        "message": {"message_id": 7, "chat": {"id": int(chat)}},
    })


def test_alert_has_one_button_per_action_plus_ignore(tmp_path):
    bot, event, plan = setup(tmp_path)
    method, params = bot.sent[0]
    assert method == "sendMessage" and params["parse_mode"] == "HTML"
    buttons = [b["callback_data"] for row in params["reply_markup"]["inline_keyboard"] for b in row]
    assert buttons == [f"abcdef12|{a}" for a in plan.allowed_actions] + ["abcdef12|fp", "abcdef12|unsure"]
    assert all(len(b.encode()) <= 64 for b in buttons)     # Telegram's callback_data limit


def test_alert_text_is_escaped():
    event = {"attack_type": "xss", "src_ip": "10.0.0.9", "possible_compromise": False}

    class Plan:
        severity, action_labels, allowed_actions = "medium", {}, []

    alert = {"what_happened": "<script>alert(1)</script>", "how_serious": "medium", "actions": {}}
    text = format_alert(event, Plan, alert)
    assert "<script>" not in text and "&lt;script&gt;" in text


def test_block_button_is_dry_run_and_recorded(tmp_path):
    bot, event, _ = setup(tmp_path)
    reply = press(bot, "block_ip")
    assert "dry run" in reply.lower()
    assert "deny 10.0.0.60;" in (tmp_path / "deny.conf").read_text()
    assert bot.store.verdict_for(event["event_id"]) == "confirmed"
    edits = [p for m, p in bot.sent if m == "editMessageText"]
    assert "reply_markup" not in edits[0] and "chosen by @tyler" in edits[0]["text"]


def test_ignore_buttons_record_verdicts(tmp_path):
    for choice, verdict in (("fp", "false_positive"), ("unsure", "dismissed")):
        bot, event, _ = setup(tmp_path / choice)
        press(bot, choice)
        assert bot.store.verdict_for(event["event_id"]) == verdict
        assert not (tmp_path / choice / "deny.conf").exists()


def test_second_press_is_ignored(tmp_path):
    bot, event, _ = setup(tmp_path)
    press(bot, "fp")
    assert press(bot, "block_ip") == "This alert was already handled."
    assert len(list(bot.store.load())) == 1


def test_action_not_allowed_by_csp_is_refused(tmp_path):
    bot, event, _ = setup(tmp_path, allow="10.0.0.60")       # C1 removes block_ip
    assert press(bot, "block_ip") == "That action is not allowed for this alert."
    assert list(bot.store.load()) == []
    assert press(bot, "fp") == "Ignore: normal traffic"        # alert still open


def test_other_chat_is_refused(tmp_path):
    bot, event, _ = setup(tmp_path)
    assert press(bot, "block_ip", chat="999") == "Not allowed from this chat."
    assert list(bot.store.load()) == []


def test_send_failure_is_swallowed(tmp_path):
    bot, event, plan = setup(tmp_path)

    def down(method, **params):
        raise OSError("no network")

    bot.call = down
    bot.send_alert(event, plan, {"what_happened": "x", "how_serious": "critical", "actions": {}})


def test_user_without_username_is_named_by_first_name(tmp_path):
    bot, event, _ = setup(tmp_path)
    press(bot, "unsure", user={"first_name": "Tyler"})
    assert list(bot.store.load())[-1]["decided_by"] == "Tyler"


def test_confirmed_ip_becomes_a_known_attacker_straight_away(tmp_path):
    bot, event, _ = setup(tmp_path)
    assert known_attacks(bot.kg, "10.0.0.60") == []
    press(bot, "block_ip")
    assert known_attacks(bot.kg, "10.0.0.60") == [event["attack_type"]]


def test_ignored_ip_is_not_a_known_attacker(tmp_path):
    bot, _, _ = setup(tmp_path)
    press(bot, "fp")
    assert known_attacks(bot.kg, "10.0.0.60") == []
