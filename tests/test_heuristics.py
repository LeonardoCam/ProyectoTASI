from app import heuristics as h


def ids(factors):
    return {f["id"] for f in factors}


def test_clean_old_https_domain_is_low():
    score, f = h.evaluate("https://www.example.com/", hops=1, domain_age_days=4000)
    assert score == 0 and f == [] and h.risk_level(score) == "BAJO"


def test_very_new_domain_is_high_when_combined():
    score, f = h.evaluate("http://secure-login-bcp.xyz/verify", hops=4, domain_age_days=3)
    assert {"age_lt_30", "no_https", "bad_tld", "keywords", "hops_some"} <= ids(f)
    assert h.risk_level(score) == "ALTO"


def test_unknown_age_is_not_silently_low():
    score, f = h.evaluate("https://example.org/", hops=0, domain_age_days=None)
    assert "age_unknown" in ids(f) and score == 15


def test_ip_host_punycode_at_sign():
    _, f = h.evaluate("http://1.2.3.4/", 0, 1000)
    assert "ip_host" in ids(f)
    _, f = h.evaluate("https://xn--pypal-4ve.com/", 0, 1000)
    assert "punycode" in ids(f)
    _, f = h.evaluate("https://google.com@evil.com/", 0, 1000)
    assert "at_sign" in ids(f)


def test_reputation_flag_forces_high():
    score, _ = h.evaluate("https://example.com/", 0, 5000, reputation_flagged=True)
    assert h.risk_level(score) == "ALTO"


def test_score_capped_and_every_nonzero_has_factors():
    score, f = h.evaluate("http://a.b.c.d.evil.tk/login@x", 9, 1, reputation_flagged=True)
    assert score == 100 and all(x["points"] > 0 and x["description"] for x in f)


def test_levels_boundaries():
    assert [h.risk_level(s) for s in (0, 29, 30, 59, 60, 100)] == ["BAJO", "BAJO", "MEDIO", "MEDIO", "ALTO", "ALTO"]


def test_registrable_domain():
    assert h.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert h.registrable_domain("www.example.com") == "example.com"
