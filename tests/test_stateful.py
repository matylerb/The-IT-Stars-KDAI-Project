"""Unit tests for brute force and directory scan sliding windows"""
from datetime import datetime, timedelta, timezone
 
from detection.stateful import SlidingWindows
 
T0 = datetime(2026, 11, 18, 0, 0, 0, tzinfo=timezone.utc)
 
 
def rec(ip, path, status=200, method="GET"):
    return {"ip": ip, "method": method, "path": path, "query": "", "status": status}
 
 
def login(ip, status):
    return rec(ip, "/rest/user/login", status, "POST")
 
 
# ---------- brute force ----------
def test_brute_force_trips_at_threshold_and_covers_whole_window():
    sw = SlidingWindows(bf_threshold=5)
    hits = []
    for i in range(5):
        hits = sw.update(login("10.0.0.60", 401), T0 + timedelta(seconds=i))
    assert len(hits) == 1
    h = hits[0]
    assert h.attack_type == "brute_force" and h.is_new
    assert len(h.records) == 5          # the 4 earlier failures are included
 
 
def test_four_failures_is_not_brute_force():
    sw = SlidingWindows(bf_threshold=5)
    for i in range(4):
        assert sw.update(login("1.1.1.1", 401), T0 + timedelta(seconds=i)) == []
 
 
def test_failures_spread_beyond_window_do_not_trip():
    sw = SlidingWindows(bf_threshold=5, window_s=60)
    for i in range(10):
        assert sw.update(login("1.1.1.1", 401), T0 + timedelta(seconds=i * 61)) == []
 
 
def test_one_alert_per_attack_then_success_escalates():
    sw = SlidingWindows(bf_threshold=5)
    new_alerts = 0
    for i in range(16):
        for h in sw.update(login("10.0.0.60", 401), T0 + timedelta(seconds=i * 0.3)):
            new_alerts += h.is_new
    assert new_alerts == 1                       # cooldown suppresses repeats
    hits = sw.update(login("10.0.0.60", 200), T0 + timedelta(seconds=5))
    assert hits[0].possible_compromise and hits[0].severity == "critical" and hits[0].is_new
    assert len(hits[0].records) == 17
 
 
def test_ips_are_independent():
    sw = SlidingWindows(bf_threshold=5)
    for i in range(4):
        sw.update(login("a", 401), T0 + timedelta(seconds=i))
        sw.update(login("b", 401), T0 + timedelta(seconds=i))
    assert sw.update(login("a", 401), T0 + timedelta(seconds=5))   # a hits 5
    assert sw.update(login("b", 200), T0 + timedelta(seconds=5)) == []  # b only had 4
 
 
# ---------- directory scan ----------
SCAN_PATHS = ["/admin", "/backup", "/config", "/debug", "/staging", "/.git",
              "/old", "/tmp"]
 
 
def test_scan_trips_on_sensitive_paths():
    sw = SlidingWindows(scan_sensitive=5)
    hits = []
    for i, p in enumerate(SCAN_PATHS[:5]):
        hits = sw.update(rec("10.0.0.70", p), T0 + timedelta(seconds=i))
    assert hits and hits[0].attack_type == "dir_scan"
    assert "SCAN-SENSITIVE-PATHS" in hits[0].rule_ids
 
 
def test_scan_trips_on_many_distinct_paths():
    sw = SlidingWindows(scan_distinct=45)
    hits = []
    for i in range(45):
        hits = sw.update(rec("x", f"/random{i}"), T0 + timedelta(seconds=i))
    assert hits and "SCAN-DISTINCT-PATHS" in hits[0].rule_ids
 
 
def test_browser_like_traffic_is_not_a_scan():
    """34 distinct real routes + lots of static assets, like 192.168.65.1."""
    sw = SlidingWindows()
    t = T0
    for i in range(34):
        for path in (f"/api/Route{i}", f"/assets/img{i}.png", "/main.js"):
            assert sw.update(rec("192.168.65.1", path), t) == []
            t += timedelta(seconds=1)
 
 
def test_product_ids_collapse():
    sw = SlidingWindows(scan_distinct=45)
    for i in range(100):
        assert sw.update(rec("shopper", f"/api/Products/{i}"), T0 + timedelta(seconds=i * 0.5)) == []
 
 
def test_rest_admin_route_is_not_sensitive():
    sw = SlidingWindows(scan_sensitive=1)
    assert sw.update(rec("u", "/rest/admin/application-version"), T0) == []
 