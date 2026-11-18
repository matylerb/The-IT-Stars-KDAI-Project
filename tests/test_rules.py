"""Unit tests for the stateless SQLi / XSS rules."""
from urllib.parse import quote
 
import pytest
 
from detection.rules import check_request
 
 
def req(value, status=200):
    """Build a fake request whose search value is `value` (URL-encoded like nginx logs it)."""
    return {"path": "/rest/products/search", "query": "q=" + quote(value),
            "status": status, "user_agent": "test"}
 
 
# --- attacks that MUST be flagged as SQLi ---
@pytest.mark.parametrize("payload", [
    "test' AND 8975=9629-- XZaY",
    "test') AND 9396=4790 AND ('vDoM'='vDoM",
    "test'))) AND 8501=8501 AND ((('oZDI'='oZDI",
    "1 UNION ALL SELECT 1,NULL,table_name FROM information_schema.tables",
    "x' OR 1=1--",
    "1 ORDER BY 1--",
    "1; DROP TABLE users",
    "1 AND RANDOMBLOB(500000000)",
    "x' UNION SELECT sql FROM sqlite_master--",
])
def test_sqli_detected(payload):
    hit = check_request(req(payload))
    assert hit is not None and hit.attack_type == "sqli", payload
 
 
# --- sqlmap probes are only caught when the server errors ---
def test_probe_needs_server_error():
    probe = "test'fDEfiX<'\">)qHjgBo"
    assert check_request(req(probe, status=200)) is None
    assert check_request(req(probe, status=500)).attack_type == "sqli"
 
 
# --- XSS ---
@pytest.mark.parametrize("payload", [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
])
def test_xss_detected(payload):
    hit = check_request(req(payload))
    assert hit is not None and hit.attack_type == "xss", payload
 
 
def test_xss_stays_xss_on_server_error():
    assert check_request(req("<script>alert(1)</script>", status=500)).attack_type == "xss"
 
 
def test_sqli_with_embedded_script_is_sqli():
    p = "1 UNION ALL SELECT '<script>alert(\"XSS\")</script>',table_name FROM information_schema.tables"
    assert check_request(req(p)).attack_type == "sqli"
 
 
# --- normal searches that must NOT be flagged ---
@pytest.mark.parametrize("value", [
    "test", "6988", "apple", "o'neill", "t-shirt", "apple and banana",
    "juice (orange)", "50% off", "rock & roll",
])
def test_benign_not_flagged(value):
    assert check_request(req(value)) is None, value
 
 
def test_empty_query():
    assert check_request({"path": "/", "query": "", "status": 200}) is None
 
 
def test_tool_ua_only_when_enabled():
    r = req("test", status=200)
    r["user_agent"] = "sqlmap/1.10.11#pip (https://sqlmap.org)"
    assert check_request(r) is None
    assert check_request(r, use_tool_ua=True).attack_type == "sqli"
 