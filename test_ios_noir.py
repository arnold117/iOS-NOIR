"""Checks for the 2026-11 fixes. Run: python test_ios_noir.py (or pytest)."""
import json
from pathlib import Path

import ios_noir as noir

HERE = Path(__file__).parent
SAMPLE_APPS = json.loads((HERE / "report/sample_apps.json").read_text(encoding="utf-8"))

# Scores produced by the pre-fix code on the synthetic sample; the fixes must not change any score.
BASELINE_SCORES = {
    "com.example.chat": 192, "com.example.pay": 159, "com.example.shop": 61, "com.example.wallet": 31,
    "com.example.tonpocket": 0, "com.example.safenotes": 15, "com.example.tunebox": 27, "com.example.teamdesk": 43,
    "com.example.tripgo": 30, "com.example.plainreader": 0, "com.example.stepup": 28, "com.example.tunnelx": 26,
}


def test_scores_unchanged():
    for bid, info in SAMPLE_APPS.items():
        assert noir.analyze_app(bid, info, [])["score"] == BASELINE_SCORES[bid], bid


def test_network_authentication_is_hotspot_helper_mode():
    r = noir.analyze_app("com.example.chat", SAMPLE_APPS["com.example.chat"], [])
    assert noir.NET_AUTH_BG_FINDING[0] in r["findings"]
    assert r["has_hotspot_bg"] and "has_net_auth" not in r
    # Layer 4 is carrier phone-number gateways only
    assert noir.is_carrier_auth_domain("open.e.189.cn") and noir.is_carrier_auth_domain("mdn.open.wo.cn")
    assert not noir.is_carrier_auth_domain("two.cn") and not noir.is_carrier_auth_domain("notcmpassport.com")


def test_scheme_collision_needs_two_different_apps():
    owners = {"paynow": ["PayNow (com.example.pay)"] * 2, "tc": ["A (a)", "B (b)"]}
    assert noir.find_scheme_collisions(owners) == {"tc": ["A (a)", "B (b)"]}


def test_disk_writes_ranked_by_times_over_own_limit():
    dw = noir.parse_ips_directory(HERE / "report/sample_ips")["disk_writes"]
    assert [d["process"] for d in dw] == ["PayNow", "ChatBox"]  # 12.0x beats 1.7x despite fewer GB
    pay = dw[0]
    assert pay["count"] == 2 and pay["worst"] == {"gb": 1.07, "hours": 2.0, "avg_kbps": 149.13, "limit_kbps": 12.43, "ratio": 12.0}


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok", name)
