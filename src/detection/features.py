"""
Per-request feature helpers

Used by rules.py (stateless regex) and stateful.py (per-IP windows)
Nothing here keeps state: each function looks at one request only
"""
import re
from urllib.parse import parse_qsl, unquote_plus

# Static assets: excluded from dir-scan path counting (browsers load lots of these)
STATIC_RE = re.compile(
    r"\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|map|webp)$", re.IGNORECASE
)

# Numeric path segments
ID_RE = re.compile(r"/\d+(?=/|$)")

# Wordlist style paths a scanner guesses anchored to the FIRST path segment so
# Juice Shop's real /rest/admin/application-version does NOT match
SENSITIVE_RE = re.compile(
    r"^/(?:admin|administrator|backup|backups|config|configuration|debug|test|"
    r"staging|dev|old|tmp|temp|\.git|\.env|\.htaccess|phpmyadmin|wp-admin|"
    r"server-status)(?:/|$)",
    re.IGNORECASE,
)

# Characters that show up in injection payloads
SPECIAL_CHARS = set("'\"<>;()=-#*/\\%")

def decode(s: str, rounds: int = 3) -> str:
    """URL decode repeatedly until it stops changing (handles double-encoding)."""
    for _ in range(rounds):
        decoded = unquote_plus(s)
        if decoded == s:
            break
        s = decoded
    return s


def query_values(query: str) -> str:
    """Return only the parameter VALUES of a query string, decoded, joined by spaces

    'q=test%27%20AND%201%3D1--' -> "test' AND 1=1--"
    We drop the 'q=' part so the '=' between name and value never triggers a rule.
    """
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:                       # not key=value shaped treat whole thing as a value
        return decode(query)
    return " ".join(decode(v) for _, v in pairs)

def normalise_path(path: str) -> str:
    """Collapse numeric IDs so /api/Products/1 and /api/Products/2 count as one path."""
    return ID_RE.sub("/{id}", path)


def is_static(path: str) -> bool:
    return bool(STATIC_RE.search(path))


def is_sensitive(path: str) -> bool:
    return bool(SENSITIVE_RE.match(path))


def request_features(rec: dict) -> dict:
    """Numeric features for one request (used for the report and the Isolation Forest stretch)"""
    values = query_values(rec.get("query", ""))
    n = len(values)
    return {
        "path_len": len(rec["path"]),
        "query_len": len(rec.get("query", "")),
        "value_len": n,
        "special_count": sum(c in SPECIAL_CHARS for c in values),
        "digit_ratio": (sum(c.isdigit() for c in values) / n) if n else 0.0,
        "status": rec["status"],
        "is_error": int(rec["status"] >= 500),
        "request_time": rec.get("request_time", 0.0),
        "is_sensitive_path": int(is_sensitive(rec["path"])),
    }


if __name__ == "__main__":
    tests = [
        ("q=test", "test"),
        ("q=test%27%20AND%208501%3D8501--%20OwUu", "test' AND 8501=8501-- OwUu"),
        ("q=%253Cscript%253E", "<script>"),          # double-encoded
        ("", ""),
    ]
    for raw, expected in tests:
        got = query_values(raw)
        print("OK " if got == expected else "BAD", repr(raw), "->", repr(got))

    print()
    print(normalise_path("/api/Products/42"), "(expect /api/Products/{id})")
    print(is_sensitive("/admin"), "(expect True)")
    print(is_sensitive("/rest/admin/application-version"), "(expect False)")
    print(is_static("/main.js"), "(expect True)")
    print(request_features({"path": "/rest/products/search",
                            "query": "q=test%27%20AND%201%3D1--",
                            "status": 500, "request_time": 0.01}))