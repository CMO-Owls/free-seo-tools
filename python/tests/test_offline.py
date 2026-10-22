"""Offline tests (no network): robots.txt rules, URL normalising and the SSRF guard's address checks."""
import pytest

from cmoowls_seo_tools import core


def test_robots_most_specific_group_and_longest_rule():
    rules = core.parse_robots("User-agent: *\nDisallow: /private/\nAllow: /private/ok\n\nUser-agent: GPTBot\nDisallow: /\n")
    star = next(r for ua, r in rules["groups"] if "*" in ua)
    assert not core.is_allowed(star, "/private/x")
    assert core.is_allowed(star, "/private/ok")
    assert core.is_allowed(star, "/")


def test_robots_sitemap_lines():
    assert core.parse_robots("Sitemap: https://example.com/sitemap.xml\n")["sitemaps"] == ["https://example.com/sitemap.xml"]


@pytest.mark.parametrize("raw", ["example.com", "https://example.com", "http://example.com/"])
def test_normalize_site_url(raw):
    assert core.normalize_site_url(raw).startswith(("https://example.com", "http://example.com"))


@pytest.mark.parametrize("bad", ["ftp://example.com", "javascript:alert(1)", "http://user:pass@example.com"])
def test_rejects_unsafe_urls(bad):
    with pytest.raises(Exception):
        core.normalize_site_url(bad)


def test_pixel_width_truncation():
    s, cut = core.truncate_px("W" * 200, 600, 20)
    assert cut and core.text_px(s, 20) <= 600
