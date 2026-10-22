"""CMO Owls free SEO tools: the engine behind https://www.cmoowls.com/tools/, as an open-source library.

Pure code, no AI calls, nothing stored. Every check fetches public pages through `safe_get`, the single safety layer:
  - http/https only, ports 80/443 only, no credentials in the URL
  - the hostname is resolved once and EVERY resolved address must be public (no loopback, private, link-local/cloud-metadata,
    multicast or reserved ranges); the request is then pinned to that validated IP (Host header + TLS SNI keep the real
    hostname), so DNS rebinding can't swap in an internal address between the check and the connection
  - redirects are followed manually (max 5) and every hop is re-validated the same way
  - response bodies are streamed and cut off at a byte cap; every request has a hard timeout

Each public `check_*` / `generate_*` / `validate_*` / `analyze_*` coroutine takes a URL and returns a JSON-serialisable dict.
Hosted versions with a visual report: https://www.cmoowls.com/tools/
License: MIT. (c) 2026 CMO Owls.
"""


from __future__ import annotations

import asyncio
import html
import ipaddress
import json
import re
import socket
import time
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

USER_AGENT = "CMOOwlsSEOTools/1.0 (+https://github.com/CMO-Owls/free-seo-tools)"
TIMEOUT_S = 8.0
MAX_REDIRECTS = 5
SMALL_FILE_BYTES = 512 * 1024      # robots.txt, llms.txt, sitemaps
PAGE_BYTES = 1024 * 1024           # HTML pages
GENERATOR_MAX_PAGES = 25
GENERATOR_CONCURRENCY = 5
GENERATOR_BUDGET_S = 25.0
LINK_CHECK_MAX = 8


class FetchBlocked(Exception):
    """The URL is not allowed (scheme, port, non-public address) — a user-facing message."""


@dataclass
class FetchResult:
    url: str              # final URL after redirects
    status: int | None
    headers: dict
    body: bytes
    truncated: bool
    error: str | None = None

    @property
    def text(self) -> str:
        enc = "utf-8"
        m = re.search(r"charset=([\w-]+)", self.headers.get("content-type", ""), re.I)
        if m:
            enc = m.group(1)
        try:
            return self.body.decode(enc, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------------------------
# URL normalization + SSRF-safe fetching
# ---------------------------------------------------------------------------------------------

def normalize_site_url(raw: str) -> str:
    """Turn "example.com", "https://example.com/page?x" etc. into "https://example.com"."""
    raw = (raw or "").strip()
    if not raw:
        raise FetchBlocked("Please enter a website address.")
    if len(raw) > 2048:
        raise FetchBlocked("That address is too long.")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    p = urlparse(raw)
    if p.scheme not in ("http", "https"):
        raise FetchBlocked("Only http and https addresses are supported.")
    if p.username or p.password:
        raise FetchBlocked("Addresses with a username or password are not supported.")
    host = (p.hostname or "").lower().rstrip(".")
    if not host or "." not in host and not _is_ip_literal(host):
        raise FetchBlocked("Please enter a full domain, for example example.com.")
    try:
        port = p.port
    except ValueError:
        raise FetchBlocked("That address isn't valid.")
    if port not in (None, 80, 443):
        raise FetchBlocked("Only standard web ports (80 and 443) are supported.")
    host_part = f"[{host}]" if ":" in host else host   # keep IPv6 literals bracketed
    netloc = host_part if port is None else f"{host_part}:{port}"
    return urlunparse((p.scheme, netloc, "", "", "", ""))


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def _is_public_ip(ip: ipaddress._BaseAddress) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return ip.is_global and not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def _resolve_public(host: str, port: int) -> str:
    """Resolve `host`; every address must be public. Returns the first address to pin to."""
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise FetchBlocked(f"We couldn't find a website at {host}. Please check the address.")
    addrs = []
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not _is_public_ip(ip):
            raise FetchBlocked("That address points to a private or internal network and can't be checked.")
        addrs.append(ip)
    if not addrs:
        raise FetchBlocked(f"We couldn't find a website at {host}.")
    # Prefer IPv4: some servers have broken IPv6 routes.
    addrs.sort(key=lambda a: a.version)
    return str(addrs[0])


async def safe_get(client: httpx.AsyncClient, url: str, max_bytes: int, method: str = "GET",
                   follow_redirects: bool = True, user_agent: str | None = None) -> FetchResult:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        p = urlparse(current)
        if p.scheme not in ("http", "https"):
            raise FetchBlocked("The site redirected to an unsupported address.")
        if p.username or p.password:
            raise FetchBlocked("The site redirected to an unsupported address.")
        try:
            port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError:
            raise FetchBlocked("The site redirected to an invalid address.")
        if port not in (80, 443):
            raise FetchBlocked("The site redirected to a non-standard port, which isn't supported.")
        host = (p.hostname or "").lower()
        ip = await asyncio.to_thread(_resolve_public, host, port)
        ip_netloc = f"[{ip}]" if ":" in ip else ip
        if p.port:
            ip_netloc += f":{p.port}"
        pinned = urlunparse((p.scheme, ip_netloc, p.path or "/", "", p.query, ""))
        headers = {"Host": p.netloc, "User-Agent": user_agent or USER_AGENT, "Accept": "*/*"}
        extensions = {"sni_hostname": host} if p.scheme == "https" else {}
        try:
            req = client.build_request(method, pinned, headers=headers, extensions=extensions)
            resp = await client.send(req, stream=True)
        except httpx.TimeoutException:
            return FetchResult(current, None, {}, b"", False, "The site took too long to respond.")
        except httpx.HTTPError as exc:
            return FetchResult(current, None, {}, b"", False, f"Couldn't connect ({type(exc).__name__}).")
        try:
            if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("location"):
                if not follow_redirects:
                    return FetchResult(current, resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, b"", False)
                current = urljoin(current, resp.headers["location"])
                continue
            body = bytearray()
            truncated = False
            if method != "HEAD":
                async for chunk in resp.aiter_bytes():
                    body.extend(chunk)
                    if len(body) > max_bytes:
                        truncated = True
                        del body[max_bytes:]
                        break
            return FetchResult(current, resp.status_code, {k.lower(): v for k, v in resp.headers.items()}, bytes(body), truncated)
        finally:
            await resp.aclose()
    return FetchResult(current, None, {}, b"", False, "Too many redirects.")


def new_client() -> httpx.AsyncClient:
    # follow_redirects=False: safe_get re-validates each hop itself. trust_env=False: never route
    # through an environment proxy.
    return httpx.AsyncClient(timeout=TIMEOUT_S, follow_redirects=False, trust_env=False, verify=True)


# ---------------------------------------------------------------------------------------------
# robots.txt parsing (Google's documented semantics: most specific user-agent group wins,
# longest matching path rule wins, Allow wins a tie, * and $ wildcards)
# ---------------------------------------------------------------------------------------------

AI_CRAWLERS = [
    # (user-agent token, company, what it does, category)
    ("Googlebot", "Google", "Google Search, which also feeds AI Overviews and AI Mode", "search"),
    ("Bingbot", "Microsoft", "Bing Search, which ChatGPT search and Copilot rely on", "search"),
    ("OAI-SearchBot", "OpenAI", "Shows your site in ChatGPT search results", "ai_search"),
    ("ChatGPT-User", "OpenAI", "Fetches pages when a ChatGPT user asks about them", "ai_search"),
    ("Claude-SearchBot", "Anthropic", "Indexes pages for Claude's search results", "ai_search"),
    ("Claude-User", "Anthropic", "Fetches pages when a Claude user asks about them", "ai_search"),
    ("PerplexityBot", "Perplexity", "Indexes pages for Perplexity answers", "ai_search"),
    ("Perplexity-User", "Perplexity", "Fetches pages when a Perplexity user asks about them", "ai_search"),
    ("DuckAssistBot", "DuckDuckGo", "Powers DuckDuckGo's AI answers", "ai_search"),
    ("Applebot", "Apple", "Siri and Spotlight suggestions", "ai_search"),
    ("GPTBot", "OpenAI", "Collects content to train OpenAI models", "training"),
    ("ClaudeBot", "Anthropic", "Collects content to train Claude models", "training"),
    ("Google-Extended", "Google", "Controls use of your content for Gemini training", "training"),
    ("Applebot-Extended", "Apple", "Controls use of your content for Apple AI training", "training"),
    ("CCBot", "Common Crawl", "Open web archive widely used to train AI models", "training"),
    ("Meta-ExternalAgent", "Meta", "Collects content to train Meta AI models", "training"),
    ("Bytespider", "ByteDance", "Collects content to train ByteDance models", "training"),
    ("Amazonbot", "Amazon", "Alexa answers and Amazon AI models", "training"),
]


def parse_robots(text: str) -> dict:
    """Returns {"groups": [(user_agents[], rules[(allow: bool, path)])], "sitemaps": [..]}."""
    groups: list[tuple[list[str], list[tuple[bool, str]]]] = []
    raw_groups: list[tuple[list[str], list[str]]] = []
    sitemaps: list[str] = []
    current_agents: list[str] = []
    current_rules: list[tuple[bool, str]] = []
    current_raw: list[str] = []
    last_was_agent = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if key == "user-agent":
            if not last_was_agent and current_agents:
                groups.append((current_agents, current_rules))
                raw_groups.append((current_agents, current_raw))
                current_agents, current_rules, current_raw = [], [], []
            current_agents.append(value.lower())
            current_raw.append(f"User-agent: {value}")
            last_was_agent = True
        elif key in ("allow", "disallow"):
            if current_agents:
                current_rules.append((key == "allow", value))
                current_raw.append(f"{'Allow' if key == 'allow' else 'Disallow'}: {value}")
            last_was_agent = False
        elif key == "sitemap":
            if value:
                sitemaps.append(value)
        elif key == "crawl-delay" and current_agents:
            current_raw.append(f"Crawl-delay: {value}")
        # Any other field (host, ...) is ignored, as Google does.
    if current_agents:
        groups.append((current_agents, current_rules))
        raw_groups.append((current_agents, current_raw))
    return {"groups": groups, "raw_groups": raw_groups, "sitemaps": sitemaps}


def _rules_for(parsed: dict, token: str) -> tuple[list[tuple[bool, str]], str]:
    """Rules applying to `token`, and which user-agent line matched ("*" or the specific one)."""
    token = token.lower()
    best_len, best_agent, rules = -1, None, []
    for agents, group_rules in parsed["groups"]:
        for a in agents:
            if a != "*" and token.startswith(a) and len(a) > best_len:
                best_len, best_agent = len(a), a
    if best_agent is not None:
        for agents, group_rules in parsed["groups"]:   # Google merges groups with the same agent
            if best_agent in agents:
                rules.extend(group_rules)
        return rules, best_agent
    for agents, group_rules in parsed["groups"]:
        if "*" in agents:
            rules.extend(group_rules)
    return rules, "*" if rules or any("*" in a for a, _ in parsed["groups"]) else ""


def _pattern_matches(pattern: str, path: str) -> bool:
    regex = re.escape(pattern).replace(r"\*", ".*")
    if regex.endswith(r"\$"):
        regex = regex[:-2] + "$"
    return re.match(regex, path) is not None


def is_allowed(rules: list[tuple[bool, str]], path: str = "/") -> bool:
    best: tuple[int, bool] | None = None
    for allow, pattern in rules:
        if pattern == "":
            continue  # empty Disallow means "allow everything"; empty Allow means nothing
        if _pattern_matches(pattern, path):
            length = len(pattern)
            if best is None or length > best[0] or (length == best[0] and allow):
                best = (length, allow)
    return True if best is None else best[1]


# ---------------------------------------------------------------------------------------------
# HTML helpers
# ---------------------------------------------------------------------------------------------

def _attr(tag: str, name: str) -> str | None:
    """One attribute's value from an HTML tag, whether double-quoted, single-quoted or unquoted (all valid HTML:
    e.g. <meta name=viewport content="..."> on example.com). Doesn't match data-name= or og:name=."""
    m = re.search(rf"(?<![-\w:]){re.escape(name)}\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s\"'>]+))", tag, re.I)
    if not m:
        return None
    return html.unescape(m.group(2) if m.group(2) is not None else m.group(3) if m.group(3) is not None else m.group(4) or "").strip()


def _meta(doc: str, attr: str, name: str) -> str | None:
    for m in re.finditer(r"<meta\b[^>]*>", doc, re.I):
        tag = m.group(0)
        if (_attr(tag, attr) or "").lower() == name.lower():
            c = _attr(tag, "content")
            if c is not None:
                return c
    return None


def _title(doc: str) -> str | None:
    m = re.search(r"<title[^>]*>(.*?)</title>", doc, re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", m.group(1))).strip() if m else None


def _visible_word_count(doc: str) -> int:
    body = re.sub(r"<(script|style|noscript|template|svg)\b.*?</\1>", " ", doc, flags=re.I | re.S)
    body = re.sub(r"<[^>]+>", " ", body)
    return len(re.findall(r"[A-Za-zÀ-ɏ]{2,}", html.unescape(body)))


def _looks_like_html(text: str) -> bool:
    head = text.lstrip()[:500].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head" in head or "<body" in head


# ---------------------------------------------------------------------------------------------
# Tool 1: AI Visibility Checker
# ---------------------------------------------------------------------------------------------

def _read_robots(robots_r: FetchResult, site: str) -> tuple[dict, dict]:
    robots: dict = {"url": site + "/robots.txt", "status": robots_r.status}
    empty = {"groups": [], "raw_groups": [], "sitemaps": []}
    if robots_r.status is None or robots_r.status >= 500:
        robots["state"] = "unreachable"
        parsed = empty
    elif robots_r.status >= 400 or _looks_like_html(robots_r.text):
        # Google treats a 4xx robots.txt as "no restrictions". An HTML page served at
        # /robots.txt (common on single-page apps) is not a robots file either.
        robots["state"] = "missing"
        parsed = empty
    else:
        robots["state"] = "found"
        parsed = parse_robots(robots_r.text)
    robots["sitemaps"] = parsed["sitemaps"][:5]
    return robots, parsed


def _crawler_statuses(parsed: dict, state: str) -> list[dict]:
    crawlers = []
    for token, company, purpose, category in AI_CRAWLERS:
        if state == "unreachable":
            status, matched, restricted = "unknown", "", []
        else:
            rules, matched = _rules_for(parsed, token)
            allowed_home = is_allowed(rules, "/")
            restricted = [p for allow, p in rules if not allow and p and p != "/"][:5]
            status = "allowed" if allowed_home and not restricted else "partial" if allowed_home else "blocked"
        crawlers.append({
            "name": token, "company": company, "purpose": purpose, "category": category,
            "status": status, "matched_rule": matched or None, "restricted_paths": restricted,
        })
    return crawlers


def _analyze_llms_txt(text: str, base: str) -> dict:
    lines = [l.rstrip() for l in text.splitlines()]
    non_empty = [l for l in lines if l.strip()]
    links = re.findall(r"\[([^\]]+)\]\(([^)\s]+)\)", text)
    checks = {
        "has_title": bool(non_empty) and non_empty[0].startswith("# "),
        "has_summary": any(l.startswith(">") for l in non_empty),
        "section_count": sum(1 for l in non_empty if l.startswith("## ")),
        "link_count": len(links),
    }
    abs_links = []
    for _, href in links:
        u = urljoin(base + "/", href)
        if u.startswith(("http://", "https://")) and u not in abs_links:
            abs_links.append(u)
    return {"checks": checks, "title": non_empty[0][2:].strip() if checks["has_title"] else None, "links": abs_links}


async def check_ai_visibility(raw_url: str) -> dict:
    site = normalize_site_url(raw_url)
    async with new_client() as client:
        robots_r, llms_r, full_r, home_r = await asyncio.gather(
            safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES),
            safe_get(client, site + "/llms.txt", SMALL_FILE_BYTES),
            safe_get(client, site + "/llms-full.txt", 4096),
            safe_get(client, site + "/", PAGE_BYTES),
        )
        if home_r.status is None and robots_r.status is None:
            raise FetchBlocked(f"We couldn't reach {site}. {home_r.error or ''}".strip())

        robots, parsed = _read_robots(robots_r, site)
        crawlers = _crawler_statuses(parsed, robots["state"])

        # ---- llms.txt
        llms: dict = {"url": site + "/llms.txt", "status": llms_r.status}
        if llms_r.status == 200 and llms_r.body.strip() and not _looks_like_html(llms_r.text):
            info = _analyze_llms_txt(llms_r.text, site)
            llms.update(state="found", **info["checks"], title=info["title"], size_bytes=len(llms_r.body))
            sample = info["links"][:LINK_CHECK_MAX]
            results = await asyncio.gather(*[safe_get(client, u, 1024) for u in sample], return_exceptions=True)
            broken = []
            for u, r in zip(sample, results):
                if isinstance(r, Exception) or r.status is None or r.status >= 400:
                    broken.append(u)
            llms["links_checked"] = len(sample)
            llms["broken_links"] = broken
        elif llms_r.status == 200 and _looks_like_html(llms_r.text):
            llms["state"] = "html_instead"
        else:
            llms["state"] = "missing"
        llms["full_present"] = full_r.status == 200 and not _looks_like_html(full_r.text)

        # ---- homepage signals AI crawlers care about
        home: dict = {"status": home_r.status}
        if home_r.status and home_r.status < 400:
            doc = home_r.text
            meta_robots = (_meta(doc, "name", "robots") or "").lower()
            x_robots = home_r.headers.get("x-robots-tag", "").lower()
            home.update(
                title=_title(doc),
                noindex="noindex" in meta_robots or "noindex" in x_robots,
                noai=any(t in meta_robots + " " + x_robots for t in ("noai", "noimageai")),
                words_without_js=_visible_word_count(doc),
            )

    return {"site": site, "robots": robots, "crawlers": crawlers, "llms": llms, "homepage": home,
            "summary": _summarize(robots, crawlers, llms, home)}


def _summarize(robots: dict, crawlers: list, llms: dict, home: dict) -> dict:
    issues: list[dict] = []
    def add(level, title, detail):
        issues.append({"level": level, "title": title, "detail": detail})

    by_cat = defaultdict(list)
    for c in crawlers:
        by_cat[c["category"]].append(c)
    blocked_search = [c["name"] for c in by_cat["search"] if c["status"] == "blocked"]
    blocked_ai = [c["name"] for c in by_cat["ai_search"] if c["status"] == "blocked"]
    blocked_train = [c["name"] for c in by_cat["training"] if c["status"] == "blocked"]

    if robots["state"] == "unreachable":
        add("high", "Your robots.txt could not be read",
            "When robots.txt returns a server error or times out, many crawlers treat the whole site as off limits until it loads again.")
    if blocked_search:
        add("high", f"Search engines are blocked: {', '.join(blocked_search)}",
            "Google and Bing indexes feed AI Overviews, ChatGPT search and Copilot. Blocking them removes you from most AI answers.")
    if blocked_ai:
        add("high", f"AI search crawlers are blocked: {', '.join(blocked_ai)}",
            "These crawlers decide whether your pages can appear and be cited in AI answers. Allow them in robots.txt.")
    if home.get("noindex"):
        add("high", "Your homepage is marked noindex",
            "A noindex tag tells search engines and AI tools not to show this page. Remove it if you want to be found.")
    if llms["state"] == "missing":
        add("medium", "No llms.txt file found",
            "llms.txt gives AI tools a clear summary of your site and its most important pages. Our free generator can create one in seconds.")
    elif llms["state"] == "html_instead":
        add("medium", "Your /llms.txt address returns a web page, not a file",
            "Your server returns its normal HTML page for /llms.txt, so AI tools find no usable file. Upload a plain text llms.txt.")
    elif llms["state"] == "found":
        if not llms.get("has_title"):
            add("low", "Your llms.txt is missing a title line",
                "The llms.txt format expects the first line to be your site name, written as \"# Site name\".")
        if not llms.get("link_count"):
            add("low", "Your llms.txt doesn't link to any pages",
                "List your key pages as Markdown links so AI tools know what to read first.")
        if llms.get("broken_links"):
            add("medium", f"{len(llms['broken_links'])} link(s) in your llms.txt are broken",
                "Update or remove links that no longer load.")
    if home.get("words_without_js") is not None and home["words_without_js"] < 150:
        add("medium", "Very little text is visible without JavaScript",
            f"Only about {home['words_without_js']} words appear in your raw HTML. Most AI crawlers do not run JavaScript, so content loaded by scripts may be invisible to them.")
    if robots["state"] == "found" and not robots["sitemaps"]:
        add("low", "robots.txt doesn't list a sitemap",
            "Adding a Sitemap: line helps crawlers find all of your pages.")
    if blocked_train:
        add("info", f"AI training crawlers are blocked: {', '.join(blocked_train)}",
            "This is a business choice, not an error. It stops model training on your content and does not, on its own, remove you from AI search results.")

    high = sum(1 for i in issues if i["level"] == "high")
    medium = sum(1 for i in issues if i["level"] == "medium")
    if high:
        verdict, headline = "action_needed", "AI tools may not be able to find or cite your site"
    elif medium:
        verdict, headline = "improve", "AI tools can reach your site, with room to improve"
    else:
        verdict, headline = "good", "Your site is open to AI search tools"
    return {"verdict": verdict, "headline": headline, "issues": issues}


# ---------------------------------------------------------------------------------------------
# Tool 2: llms.txt Generator
# ---------------------------------------------------------------------------------------------

def _sitemap_locs(xml: str) -> tuple[list[str], list[str]]:
    """Returns (page URLs, child sitemap URLs)."""
    locs = [html.unescape(m.strip()) for m in re.findall(r"<loc>\s*(.*?)\s*</loc>", xml, re.I | re.S)]
    if re.search(r"<sitemapindex\b", xml, re.I):
        return [], locs
    return locs, []


async def _collect_sitemap_urls(client: httpx.AsyncClient, site: str, sitemap_urls: list[str],
                                deadline: float) -> tuple[list[str], str | None]:
    """Page URLs from the site's sitemaps (robots.txt Sitemap: lines, else /sitemap.xml), following
    one level of sitemap index (max 3 sitemaps x 3 children). Returns (urls, first working sitemap)."""
    pages: list[str] = []
    found = None
    for sm in (sitemap_urls or [site + "/sitemap.xml"])[:3]:
        if time.monotonic() > deadline:
            break
        try:
            r = await safe_get(client, sm, SMALL_FILE_BYTES * 4)
        except FetchBlocked:
            continue
        if r.status != 200 or "<loc>" not in r.text.lower():
            continue
        locs, children = _sitemap_locs(r.text)
        for child in children[:3]:
            if time.monotonic() > deadline:
                break
            try:
                cr = await safe_get(client, child, SMALL_FILE_BYTES * 4)
            except FetchBlocked:
                continue
            if cr.status == 200:
                locs.extend(_sitemap_locs(cr.text)[0])
        if locs:
            found = found or sm
            pages.extend(locs)
    return pages, found


def _section_for(path: str) -> str:
    seg = path.strip("/").split("/")[0] if path.strip("/") else ""
    if not seg:
        return "Main pages"
    return seg.replace("-", " ").replace("_", " ").title()


def _clean_title(title: str | None, site_name: str) -> str:
    if not title:
        return ""
    for sep in (" | ", " - ", " – ", " — ", " · ", " :: "):
        if sep in title:
            parts = [p.strip() for p in title.split(sep)]
            parts = [p for p in parts if p.lower() != site_name.lower()] or parts
            return parts[0]
    return title.strip()


async def generate_llms_txt(raw_url: str) -> dict:
    site = normalize_site_url(raw_url)
    host = urlparse(site).hostname
    started = time.monotonic()
    async with new_client() as client:
        home_r, robots_r = await asyncio.gather(
            safe_get(client, site + "/", PAGE_BYTES), safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES))
        if not home_r.status or home_r.status >= 400:
            raise FetchBlocked(f"We couldn't load {site}. {home_r.error or f'It returned HTTP {home_r.status}.'}")
        # Use the address the site actually settled on (e.g. example.com -> www.example.com), so
        # every generated link points at the canonical host.
        fp = urlparse(home_r.url)
        site = urlunparse((fp.scheme, fp.netloc, "", "", "", "")) or site
        host = fp.hostname or host
        doc = home_r.text
        site_name = (_meta(doc, "property", "og:site_name") or "").strip()
        home_title = _title(doc) or host
        if not site_name:
            site_name = re.split(r"\s[|\-–—·:]\s", home_title)[0].strip() or host
        description = _meta(doc, "name", "description") or _meta(doc, "property", "og:description") or ""

        # Candidate URLs: sitemap first, homepage links as a fallback.
        sitemap_urls = []
        if robots_r.status == 200 and not _looks_like_html(robots_r.text):
            sitemap_urls = parse_robots(robots_r.text)["sitemaps"]
        pages, _ = await _collect_sitemap_urls(client, site, sitemap_urls, started + GENERATOR_BUDGET_S / 2)
        used_sitemap = bool(pages)
        if not pages:
            for href in re.findall(r'<a\b[^>]*href\s*=\s*["\']([^"\'#]+)', doc, re.I):
                u = urljoin(site + "/", html.unescape(href))
                if urlparse(u).hostname == host:
                    pages.append(u.split("?")[0])

        seen, ordered = set(), []
        for u in pages:
            p = urlparse(u)
            if p.hostname not in (host, f"www.{host}", host.removeprefix("www.")):
                continue
            if re.search(r"\.(jpg|jpeg|png|gif|webp|svg|pdf|zip|xml|css|js)$", p.path, re.I):
                continue
            key = p.path.rstrip("/") or "/"
            if key in seen:
                continue
            seen.add(key)
            ordered.append(urlunparse((p.scheme, p.netloc, p.path or "/", "", "", "")))
        ordered.sort(key=lambda u: (urlparse(u).path.strip("/").count("/"), len(urlparse(u).path)))
        candidates = [u for u in ordered if urlparse(u).path.strip("/")][:GENERATOR_MAX_PAGES]

        sem = asyncio.Semaphore(GENERATOR_CONCURRENCY)

        async def describe(u: str) -> dict | None:
            if time.monotonic() - started > GENERATOR_BUDGET_S:
                return None
            async with sem:
                try:
                    r = await safe_get(client, u, PAGE_BYTES)
                except FetchBlocked:
                    return None
            if not r.status or r.status >= 400 or "html" not in r.headers.get("content-type", "html"):
                return None
            d = r.text
            if "noindex" in (_meta(d, "name", "robots") or "").lower():
                return None
            title = _clean_title(_title(d), site_name) or urlparse(u).path.strip("/").split("/")[-1].replace("-", " ").title()
            desc = _meta(d, "name", "description") or _meta(d, "property", "og:description") or ""
            return {"url": u, "title": title, "description": re.sub(r"\s+", " ", desc).strip()}

        described = [d for d in await asyncio.gather(*[describe(u) for u in candidates]) if d]

    sections: dict[str, list[dict]] = defaultdict(list)
    for d in described:
        sections[_section_for(urlparse(d["url"]).path)].append(d)
    order = sorted(sections, key=lambda s: (s != "Main pages", -len(sections[s]) if s != "Main pages" else 0, s))

    def esc(t: str) -> str:
        return t.replace("[", "(").replace("]", ")").replace("\n", " ").strip()

    out = [f"# {esc(site_name)}", ""]
    if description:
        out += [f"> {esc(description)}", ""]
    out += [f"- [Homepage]({site}/)" + (f": {esc(home_title)}" if home_title else ""), ""]
    for s in order:
        out.append(f"## {s}")
        out.append("")
        for d in sections[s]:
            line = f"- [{esc(d['title'])}]({d['url']})"
            if d["description"]:
                line += f": {esc(d['description'])[:200]}"
            out.append(line)
        out.append("")
    return {
        "site": site, "site_name": site_name, "llms_txt": "\n".join(out).rstrip() + "\n",
        "pages_included": len(described), "used_sitemap": used_sitemap,
        "pages_considered": len(ordered),
    }


# ---------------------------------------------------------------------------------------------
# Tool 3: Robots.txt analysis (feeds the Robots.txt Generator with the visitor's real site)
# ---------------------------------------------------------------------------------------------

# Common private areas worth keeping out of search: (robots path, label, recommended by default).
# Page-like areas use a bare prefix ("/checkout" also covers "/checkout/step-2"); directories keep
# their trailing slash so "/api/" can't swallow a public "/api-documentation" page. Sign-up pages
# are suggested but not pre-selected: for many businesses they are landing pages that should rank.
PRIVATE_CANDIDATES = [
    ("/wp-admin/", "WordPress admin", True), ("/admin/", "Admin area", True), ("/administrator/", "Admin area", True),
    ("/dashboard", "Dashboard", True), ("/account", "Customer account", True), ("/my-account", "Customer account", True),
    ("/login", "Login page", True), ("/signin", "Sign in page", True), ("/sign-in", "Sign in page", True),
    ("/user/", "User area", True), ("/profile", "User profile", True), ("/settings", "Account settings", True),
    ("/cart", "Shopping cart", True), ("/checkout", "Checkout", True), ("/orders", "Order history", True),
    ("/api/", "API", True), ("/search", "Internal search results", True), ("/cgi-bin/", "Server scripts", True),
    ("/staging/", "Staging copy", True), ("/signup", "Sign up page", False), ("/register", "Registration page", False),
]
SUBDOMAIN_CANDIDATES = ["app", "dashboard", "admin", "portal", "staging", "dev", "beta", "test"]
RESOURCE_PATTERNS = ["/wp-content/", "/wp-includes/", "/assets/", "/static/", "/_next/", "/css/", "/js/", "*.css", "*.js"]
KNOWN_ROBOTS_KEYS = {"user-agent", "allow", "disallow", "sitemap", "crawl-delay", "host", "clean-param"}
ANALYZE_PROBE_BYTES = 64 * 1024
ANALYZE_BUDGET_S = 20.0


def _lint_robots(text: str) -> list[dict]:
    """Lines search engines will silently ignore: typos in field names, rules before any User-agent."""
    out, seen_agent = [], False
    for n, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if ":" not in line:
            out.append({"line": n, "text": raw.strip()[:200], "problem": "Not a valid rule (missing a colon)."})
            continue
        key = line.split(":", 1)[0].strip().lower()
        if key not in KNOWN_ROBOTS_KEYS:
            out.append({"line": n, "text": raw.strip()[:200], "problem": f'"{key}" is not a recognized field, so crawlers ignore this line.'})
        elif key == "user-agent":
            seen_agent = True
        elif key in ("allow", "disallow") and not seen_agent:
            out.append({"line": n, "text": raw.strip()[:200], "problem": "This rule appears before any User-agent line, so crawlers ignore it."})
    return out[:20]


def _similar(a: bytes, b: bytes) -> bool:
    if not a or not b:
        return False
    return abs(len(a) - len(b)) <= max(len(a), len(b)) * 0.03


async def _probe_private(client: httpx.AsyncClient, site: str, homepage_links: set[str], deadline: float) -> list[dict]:
    rand = "cmo-owls-check-" + str(int(time.time() * 1000))[-9:]
    baseline = await safe_get(client, f"{site}/{rand}", ANALYZE_PROBE_BYTES, follow_redirects=False)
    catch_all = baseline.status == 200
    sem = asyncio.Semaphore(4)

    async def probe(path: str, label: str, recommended: bool) -> dict | None:
        bare = path.rstrip("/")
        linked = any(l == bare or l.startswith(bare + "/") or l.startswith(bare + "?") for l in homepage_links)
        evidence = None
        if time.monotonic() < deadline:
            async with sem:
                try:
                    r = await safe_get(client, site + bare, ANALYZE_PROBE_BYTES, follow_redirects=False)
                    if r.status in (301, 302, 303, 307, 308):
                        loc = r.headers.get("location", "")
                        target = urlparse(urljoin(site + bare, loc)).path.rstrip("/")
                        if re.search(r"log-?in|sign-?in|auth|sso|wp-login", loc, re.I):
                            evidence = "redirects to a login page"
                        elif target == bare:  # /admin -> /admin/
                            r = await safe_get(client, site + bare + "/", ANALYZE_PROBE_BYTES, follow_redirects=False)
                    if evidence is None and r.status in (401, 403):
                        evidence = "requires a login"
                    elif evidence is None and r.status == 200 and not (catch_all and _similar(r.body, baseline.body)):
                        evidence = "found on your site"
                except FetchBlocked:
                    pass
        if evidence is None and linked:
            evidence = "linked from your homepage"
        if evidence is None:
            return None
        return {"path": path, "label": label, "recommended": recommended, "evidence": evidence}

    found = await asyncio.gather(*[probe(*c) for c in PRIVATE_CANDIDATES])
    return [f for f in found if f]


async def _check_subdomains(client: httpx.AsyncClient, host: str) -> tuple[list[dict], bool]:
    base = host[4:] if host.startswith("www.") else host
    if _is_ip_literal(base) or base.count(".") < 1:
        return [], False

    async def resolves(name: str) -> bool:
        try:
            await asyncio.wait_for(asyncio.to_thread(socket.getaddrinfo, name, 443, 0, socket.SOCK_STREAM), 3)
            return True
        except Exception:
            return False

    if await resolves(f"cmo-owls-check-{int(time.time())}.{base}"):
        return [], True  # wildcard DNS: every subdomain "exists", so nothing meaningful to report
    names = [f"{label}.{base}" for label in SUBDOMAIN_CANDIDATES]
    hits = [n for n, ok in zip(names, await asyncio.gather(*[resolves(n) for n in names])) if ok]
    out = []
    for name in hits[:6]:
        state, blocks_all = "unreachable", False
        try:
            r = await safe_get(client, f"https://{name}/robots.txt", SMALL_FILE_BYTES)
            if r.status == 200 and not _looks_like_html(r.text):
                rules, _ = _rules_for(parse_robots(r.text), "Googlebot")
                state, blocks_all = "found", not is_allowed(rules, "/")
            elif r.status is not None:
                state = "missing"
        except FetchBlocked:
            state = "private"
        out.append({"host": name, "robots_state": state, "blocks_all": blocks_all})
    return out, False


async def analyze_robots(raw_url: str) -> dict:
    site = normalize_site_url(raw_url)
    started = time.monotonic()
    async with new_client() as client:
        robots_r, home_r = await asyncio.gather(
            safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES), safe_get(client, site + "/", PAGE_BYTES))
        if home_r.status is None and robots_r.status is None:
            raise FetchBlocked(f"We couldn't reach {site}. {home_r.error or ''}".strip())
        # Work against the address the site settled on (example.com -> www.example.com).
        if home_r.status and home_r.status < 400:
            fp = urlparse(home_r.url)
            site = urlunparse((fp.scheme, fp.netloc, "", "", "", "")) or site
            if fp.netloc != urlparse(robots_r.url).netloc:
                robots_r = await safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES)
        host = urlparse(site).hostname or ""
        robots, parsed = _read_robots(robots_r, site)
        robots["text"] = robots_r.text[:20000] if robots["state"] == "found" else ""
        crawlers = _crawler_statuses(parsed, robots["state"])
        known = {c[0].lower() for c in AI_CRAWLERS}

        star_rules = [r for agents, rules in parsed["groups"] if "*" in agents for r in rules]
        star = {"disallow": sorted({p for a, p in star_rules if not a and p}),
                "allow": sorted({p for a, p in star_rules if a and p and p != "/"})}
        other_groups = []
        for agents, lines in parsed["raw_groups"]:
            keep_agents = [a for a in agents if a != "*" and a not in known]
            if not keep_agents:
                continue
            body = [l for l in lines if not l.lower().startswith("user-agent:")]
            orig_case = [l.split(":", 1)[1].strip() for l in lines if l.lower().startswith("user-agent:")
                         and l.split(":", 1)[1].strip().lower() in keep_agents]
            other_groups.append({"agents": orig_case, "lines": body})
        # Crawlers with their own group whose rules genuinely differ from the general (*) rules, so
        # the generator can preserve them instead of silently dropping them.
        star_set = {(a, p) for a, p in star_rules}
        bot_custom = []
        for c in crawlers:
            if c["status"] != "partial" or c["matched_rule"] in (None, "*"):
                continue
            own, _ = _rules_for(parsed, c["name"])
            extra = [{"allow": a, "path": p} for a, p in dict.fromkeys(own) if p and (a, p) not in star_set]
            if extra:
                bot_custom.append({"name": c["name"], "rules": extra[:50]})

        doc = home_r.text if home_r.status and home_r.status < 400 else ""
        links = set()
        for href in re.findall(r'<a\b[^>]*href\s*=\s*["\']([^"\'#]+)', doc, re.I):
            u = urlparse(urljoin(site + "/", html.unescape(href)))
            if u.hostname in (host, None):
                links.add((u.path or "/").rstrip("/") + ("?" + u.query if u.query else ""))

        deadline = started + ANALYZE_BUDGET_S
        (private, (subdomains, wildcard), (sitemap_pages, sitemap_found)) = await asyncio.gather(
            _probe_private(client, site, links, deadline),
            _check_subdomains(client, host),
            _collect_sitemap_urls(client, site, robots["sitemaps"], deadline),
        )
        star_rule_list = [(False, p) for p in star["disallow"]] + [(True, p) for p in star["allow"]]
        for f in private:
            f["already_blocked"] = not is_allowed(star_rule_list, f["path"].rstrip("/") + "/x" if f["path"].endswith("/") else f["path"])

        public_paths = []
        for u in sitemap_pages:
            p = urlparse(u)
            if p.hostname in (host, f"www.{host}", host.removeprefix("www.")):
                public_paths.append((p.path or "/") + ("?" + p.query if p.query else ""))
        public_paths = list(dict.fromkeys(public_paths))[:500]

    issues = []
    def add(level, title, detail):
        issues.append({"level": level, "title": title, "detail": detail})
    by = {c["name"]: c for c in crawlers}
    if robots["state"] == "unreachable":
        add("high", "Your robots.txt could not be read",
            "It returned a server error or timed out. Until it loads, many crawlers treat the whole site as off limits.")
    if robots["state"] == "found" and not is_allowed(_rules_for(parsed, "SomeCrawler")[0], "/") and not star["allow"]:
        add("high", "Your robots.txt blocks every crawler from the whole site",
            "A \"Disallow: /\" rule for all crawlers hides your entire website from search engines and AI tools.")
    blocked_search = [n for n in ("Googlebot", "Bingbot") if by[n]["status"] == "blocked"]
    if blocked_search:
        add("high", f"Search engines are blocked: {', '.join(blocked_search)}",
            "This removes you from search results and from the AI answers built on them.")
    blocked_ai = [c["name"] for c in crawlers if c["category"] == "ai_search" and c["status"] == "blocked"]
    if blocked_ai:
        add("high", f"AI search crawlers are blocked: {', '.join(blocked_ai)}",
            "These decide whether you can appear and be cited in AI answers. The settings below allow them by default.")
    resource_blocks = [p for p in star["disallow"] if any(_pattern_matches(p, probe) for probe in
                       ("/wp-content/x.css", "/wp-includes/x.js", "/assets/x.js", "/static/x.css", "/_next/x.js", "/css/x.css", "/js/x.js", "/x.css", "/x.js"))]
    if resource_blocks and "/" not in star["disallow"]:
        add("medium", f"CSS or JavaScript files are blocked: {', '.join(resource_blocks[:4])}",
            "Google needs these files to render your pages correctly. Blocking them can hurt how your pages are understood and ranked.")
    if robots["state"] == "found" and not robots["sitemaps"]:
        add("low", "No sitemap is listed", "Adding a Sitemap line helps crawlers find every public page." +
            (" We found your sitemap and added it below." if sitemap_found else ""))
    unprotected = [f for f in private if f["recommended"] and not f["already_blocked"]]
    if unprotected:
        add("medium", f"{len(unprotected)} private area{'s are' if len(unprotected) != 1 else ' is'} open to crawlers",
            "We found areas that have no value in search results. They are selected below so the new file keeps crawlers out of them.")

    return {
        "site": site, "robots": robots, "crawlers": crawlers, "star": star,
        "other_groups": other_groups[:30], "bot_custom_rules": bot_custom,
        "private_areas": private, "subdomains": subdomains, "wildcard_dns": wildcard,
        "public_paths": public_paths, "sitemap": robots["sitemaps"][0] if robots["sitemaps"] else sitemap_found,
        "lint": _lint_robots(robots_r.text) if robots["state"] == "found" else [], "issues": issues,
    }


# =============================================================================================
# AI Crawler Access Test, Schema Checker,
# Broken Link Checker. Same guardrails: every request goes through safe_get, zero LLM calls,
# nothing stored.
# =============================================================================================

def normalize_page_url(raw: str) -> str:
    """Like normalize_site_url, but keeps the path and query (drops the #fragment)."""
    site = normalize_site_url(raw)          # all validation (scheme, host, port, credentials)
    s = (raw or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", s):
        s = "https://" + s
    p = urlparse(s)
    path = p.path or "/"
    return site + path + (("?" + p.query) if p.query else "")


def _visible_text(doc: str) -> str:
    body = re.sub(r"<(script|style|noscript|template|svg)\b.*?</\1>", " ", doc, flags=re.I | re.S)
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", body)))


# ---------------------------------------------------------------------------------------------
# Tool 4: AI Crawler Access Test. Fetches the homepage as each crawler's real user-agent string
# and compares the response with a normal browser visit. Catches firewall / bot-protection
# blocks (Cloudflare "Block AI bots", WAF rules) that robots.txt checkers can't see.
# Limitation (shown in the UI): this tests user-agent rules. Firewalls that verify real crawler
# IP addresses may treat genuine crawlers differently from our test.
# ---------------------------------------------------------------------------------------------

BROWSER_UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
CRAWLER_UAS = {
    "Googlebot": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Bingbot": "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "OAI-SearchBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot",
    "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
    "Claude-SearchBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +Claude-SearchBot@anthropic.com)",
    "Claude-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +Claude-User@anthropic.com)",
    "PerplexityBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
    "Perplexity-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Perplexity-User/1.0; +https://perplexity.ai/perplexity-user)",
    "Applebot": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)",
    "GPTBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; GPTBot/1.2; +https://openai.com/gptbot",
    "ClaudeBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)",
    "CCBot": "CCBot/2.0 (https://commoncrawl.org/faq/)",
    "Meta-ExternalAgent": "meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)",
    "Bytespider": "Mozilla/5.0 (Linux; Android 5.0) AppleWebKit/537.36 (KHTML, like Gecko) Mobile Safari/537.36 (compatible; Bytespider; spider-feedback@bytedance.com)",
    "Amazonbot": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)",
}
ACCESS_PAGE_BYTES = 400 * 1024
ACCESS_CONCURRENCY = 4
_CHALLENGE_MARKERS = ("just a moment", "cf-chl", "challenge-platform", "attention required", "captcha",
                      "verify you are human", "checking your browser", "ddos protection", "access denied")
_IP_VERIFIED_BOTS = {"Googlebot", "Bingbot", "Applebot"}   # commonly verified by IP: a block on a fake UA is expected


def _classify_access(r: FetchResult, baseline_words: int) -> tuple[str, str]:
    """Returns (status, detail). status: allowed | blocked | challenged | different | error."""
    if r.status is None:
        return "error", r.error or "No response."
    text = r.text[:20000].lower() if r.body else ""
    challenged = r.headers.get("cf-mitigated", "").lower() == "challenge" or any(m in text for m in _CHALLENGE_MARKERS)
    if r.status in (401, 403, 406, 429, 451, 503) or (r.status >= 400 and challenged):
        if challenged:
            return "challenged", f"HTTP {r.status}: a bot-protection challenge page was returned instead of your site."
        return "blocked", f"HTTP {r.status}: the server refused this crawler."
    if r.status >= 400:
        return "error", f"HTTP {r.status}."
    words = _visible_word_count(r.text)
    if challenged and words < 200:
        return "challenged", "A bot-protection challenge page was returned instead of your site."
    if baseline_words >= 150 and words < baseline_words * 0.3:
        return "different", f"This crawler got about {words} words; a normal visitor gets about {baseline_words}."
    return "allowed", f"HTTP {r.status}, about {words} words of content."


async def check_crawler_access(raw_url: str) -> dict:
    site = normalize_site_url(raw_url)
    sem = asyncio.Semaphore(ACCESS_CONCURRENCY)
    async with new_client() as client:
        async def fetch(ua: str) -> FetchResult:
            async with sem:
                return await safe_get(client, site + "/", ACCESS_PAGE_BYTES, user_agent=ua)
        base_r, robots_r = await asyncio.gather(fetch(BROWSER_UA), safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES))
        if base_r.status is None:
            raise FetchBlocked(f"We couldn't reach {site}. {base_r.error or ''}".strip())
        baseline_words = _visible_word_count(base_r.text) if base_r.status < 400 else 0
        names = list(CRAWLER_UAS)
        results = await asyncio.gather(*[fetch(CRAWLER_UAS[n]) for n in names])

    robots, parsed = _read_robots(robots_r, site)
    robots_by_bot = {c["name"]: c["status"] for c in _crawler_statuses(parsed, robots["state"])}
    meta = {t: (co, purpose, cat) for t, co, purpose, cat in AI_CRAWLERS}
    meta.setdefault("Claude-SearchBot", ("Anthropic", "Indexes pages for Claude's search results", "ai_search"))
    bots = []
    for n, r in zip(names, results):
        status, detail = _classify_access(r, baseline_words)
        co, purpose, cat = meta.get(n, ("", "", "training"))
        bots.append({"name": n, "company": co, "purpose": purpose, "category": cat, "status": status,
                     "http_status": r.status, "detail": detail, "robots": robots_by_bot.get(n, "unknown")})

    base_status, _ = _classify_access(base_r, 0)
    baseline = {"status": base_r.status, "words": baseline_words, "state": base_status}
    return {"site": site, "baseline": baseline, "robots": {"state": robots["state"]}, "bots": bots,
            "summary": _summarize_access(baseline, bots)}


def _summarize_access(baseline: dict, bots: list[dict]) -> dict:
    issues: list[dict] = []
    def add(level, title, detail):
        issues.append({"level": level, "title": title, "detail": detail})

    if baseline["state"] != "allowed":
        add("high", "Your site blocked our normal browser visit too",
            "Your firewall or bot protection refused even an ordinary browser request from our server, so every result "
            "below may reflect that general block rather than AI-specific rules. Check your firewall's bot settings.")
    bad = lambda b: b["status"] in ("blocked", "challenged", "different")
    ai_bad = [b for b in bots if b["category"] == "ai_search" and bad(b)]
    search_bad = [b for b in bots if b["category"] == "search" and bad(b)]
    train_bad = [b for b in bots if b["category"] == "training" and bad(b)]
    robots_conflict = [b["name"] for b in bots if bad(b) and b["robots"] == "allowed"]

    if ai_bad and baseline["state"] == "allowed":
        add("high", f"AI search crawlers are blocked at your server: {', '.join(b['name'] for b in ai_bad)}",
            "These crawlers decide whether ChatGPT, Claude and Perplexity can show and cite your pages. They were refused "
            "or challenged even though a normal visitor got through. Look for a 'Block AI bots' or bot-fight setting in "
            "your firewall or CDN (for example Cloudflare) and allow them.")
    if search_bad and baseline["state"] == "allowed":
        names = ", ".join(b["name"] for b in search_bad)
        verified = all(b["name"] in _IP_VERIFIED_BOTS for b in search_bad)
        add("medium" if verified else "high", f"Search crawlers were refused in our test: {names}",
            "Many firewalls verify Google and Bing crawlers by IP address and correctly block anyone faking their name, "
            "which is what our test does. Confirm with Google Search Console's URL Inspection and Bing Webmaster Tools; "
            "if they can fetch your pages, you're fine." if verified else
            "Search engines feed AI Overviews, ChatGPT search and Copilot. Check your firewall rules for these crawlers.")
    if robots_conflict and baseline["state"] == "allowed":
        add("medium", "Your robots.txt says yes, but your server says no",
            f"robots.txt allows {', '.join(robots_conflict[:6])}, but the server refused or challenged them. "
            "The firewall wins, so these crawlers can't read your site.")
    if train_bad and baseline["state"] == "allowed":
        add("info", f"AI training crawlers are blocked: {', '.join(b['name'] for b in train_bad)}",
            "This is a business choice, not an error. It stops model training on your content and does not, on its own, "
            "remove you from AI search answers.")

    high = sum(1 for i in issues if i["level"] == "high")
    medium = sum(1 for i in issues if i["level"] == "medium")
    if high:
        verdict, headline = "action_needed", "Some AI crawlers can't get into your site"
    elif medium:
        verdict, headline = "improve", "Most crawlers get in, with something to check"
    else:
        verdict, headline = "good", "AI crawlers can access your site"
    return {"verdict": verdict, "headline": headline, "issues": issues}


# ---------------------------------------------------------------------------------------------
# Tool 5: Schema Checker. Reads a page's JSON-LD, checks the fields Google documents as required
# or recommended for the common types, and catches the mistakes that confuse search engines and
# AI: invalid JSON, the wrong type (Product on a software page), and prices in the code that the
# page doesn't show.
# ---------------------------------------------------------------------------------------------

SCHEMA_MAX_BLOCKS = 40
_SAAS_HINTS = re.compile(r"\b(per month|/mo\b|/month|subscription|free trial|sign up|signup|saas|software|"
                         r"billed (annually|monthly)|start free|platform)\b", re.I)


def _types_of(item: dict) -> list[str]:
    t = item.get("@type")
    if isinstance(t, str):
        return [t]
    return [x for x in t if isinstance(x, str)] if isinstance(t, list) else []


def _as_list(v) -> list:
    return v if isinstance(v, list) else ([] if v is None else [v])


def _has(item: dict, key: str) -> bool:
    v = item.get(key)
    if v is None:
        return False
    if isinstance(v, str):
        return bool(v.strip())
    if isinstance(v, (list, dict)):
        return bool(v)
    return True


def _offers(item: dict) -> list[dict]:
    out = []
    for o in _as_list(item.get("offers")):
        if isinstance(o, dict):
            out.append(o)
            out.extend(x for x in _as_list(o.get("offers")) if isinstance(x, dict))   # AggregateOffer.offers
    return out


def _offer_price(o: dict):
    if _has(o, "price"):
        return o["price"]
    if _has(o, "lowPrice"):
        return o["lowPrice"]
    ps = o.get("priceSpecification")
    for p in _as_list(ps):
        if isinstance(p, dict) and _has(p, "price"):
            return p["price"]
    return None


# schema.org LocalBusiness subtypes whose names don't end in "Business" (the common ones).
_LOCAL_TYPES = {
    "LocalBusiness", "Dentist", "Physician", "MedicalClinic", "Hospital", "Pharmacy", "Optician", "VeterinaryCare",
    "Restaurant", "CafeOrCoffeeShop", "BarOrPub", "Bakery", "FastFoodRestaurant", "Winery", "Brewery",
    "Store", "ClothingStore", "ElectronicsStore", "FurnitureStore", "GroceryStore", "HardwareStore", "JewelryStore",
    "Florist", "BookStore", "PetStore", "AutoDealer", "AutoRepair", "GasStation",
    "Hotel", "Motel", "BedAndBreakfast", "Resort", "LodgingBusiness",
    "Attorney", "LegalService", "Notary", "AccountingService", "InsuranceAgency", "RealEstateAgent", "TravelAgency",
    "Plumber", "Electrician", "Locksmith", "RoofingContractor", "GeneralContractor", "HousePainter", "MovingCompany",
    "HVACBusiness", "BeautySalon", "HairSalon", "NailSalon", "DaySpa", "ExerciseGym", "HealthClub", "ChildCare",
    "DryCleaningOrLaundry", "SelfStorage", "Library", "School", "Preschool",
}


def _check_item(item: dict, is_saas_page: bool) -> list[dict]:
    """Field checks per type. Each issue: level, title, detail."""
    issues = []
    def add(level, title, detail):
        issues.append({"level": level, "title": title, "detail": detail})
    types = set(_types_of(item))
    missing = lambda keys: [k for k in keys if not _has(item, k)]

    if types & {"Product", "ProductGroup"}:
        if not _has(item, "name"):
            add("high", "Product is missing its name", "Google requires a name for product results.")
        if not (_offers(item) or _has(item, "review") or _has(item, "aggregateRating")):
            add("high", "Product needs offers, a review or a rating",
                "Google requires at least one of offers, review or aggregateRating for product snippets.")
        if not _has(item, "image"):
            add("medium", "Product is missing an image", "Google's merchant listings treat a missing image as a critical error.")
        for o in _offers(item):
            if _offer_price(o) is None:
                add("medium", "An offer has no price", "Add price (or priceSpecification.price) and priceCurrency to every offer.")
                break
        if _offers(item) and not any(_has(o, "availability") for o in _offers(item)):
            add("low", "Offers are missing availability", "Google recommends availability, for example https://schema.org/InStock.")
        if is_saas_page:
            add("medium", "Product markup on a software or subscription page",
                "Google treats Product as something physical for sale and starts asking for shipping, returns and a barcode. "
                "For software use SoftwareApplication (or WebApplication); for services use Service.")
    if types & {"SoftwareApplication", "WebApplication", "MobileApplication", "VideoGame"}:
        if not _has(item, "name"):
            add("high", "Software is missing its name", "Add name.")
        offers = _offers(item)
        if not offers or all(_offer_price(o) is None for o in offers):
            add("medium", "Software has no offer price", "Google's software app results need offers.price (use 0 for free).")
        if not (_has(item, "aggregateRating") or _has(item, "review")):
            add("info", "No rating or review markup",
                "Google only shows software rich results with a rating or review. Only add them if they come from real customers.")
        for k in missing(["applicationCategory", "operatingSystem"]):
            add("low", f"Software is missing {k}", f"Google recommends {k}.")
    local = any(t in _LOCAL_TYPES or (t.endswith("Business") and t != "OnlineBusiness") for t in types)
    if types & {"Organization", "Corporation", "OnlineBusiness", "NGO"} or local:
        for k in missing(["name", "url"]):
            add("medium", f"{sorted(types)[0]} is missing {k}", f"Add {k} so search engines and AI can identify your brand.")
        if not _has(item, "logo") and not local:
            add("low", "Organization has no logo", "A logo helps Google show your brand in results and knowledge panels.")
        if not _has(item, "sameAs"):
            add("medium", "No sameAs links to your profiles",
                "sameAs links your site to your LinkedIn, YouTube, Instagram and other profiles, so AI knows they're one brand.")
        if not _has(item, "alternateName"):
            add("low", "No alternateName",
                "If people write your brand differently (one word, abbreviations), list those spellings in alternateName.")
    if local:
        if not _has(item, "address"):
            add("high", "Local business is missing its address", "Google requires address for local business results.")
        if not _has(item, "telephone"):
            add("low", "Local business has no telephone", "Google recommends telephone.")
    if types & {"Article", "BlogPosting", "NewsArticle", "TechArticle"}:
        for k in missing(["headline", "image", "datePublished"]):
            add("medium" if k == "headline" else "low", f"Article is missing {k}", f"Google recommends {k} for article results.")
        authors = [a for a in _as_list(item.get("author")) if isinstance(a, dict)]
        if not item.get("author"):
            add("low", "Article has no author", "Author markup (a Person with a name and url) supports trust signals.")
        elif authors and not all(_has(a, "name") for a in authors):
            add("low", "Article author has no name", "Give every author a name.")
    if "FAQPage" in types:
        qs = [q for q in _as_list(item.get("mainEntity")) if isinstance(q, dict)]
        if not qs:
            add("high", "FAQPage has no questions", "Add mainEntity with Question items.")
        elif any(not (isinstance(q.get("acceptedAnswer"), dict) and _has(q["acceptedAnswer"], "text")) for q in qs):
            add("medium", "Some FAQ questions have no answer text", "Every Question needs acceptedAnswer.text.")
        add("info", "FAQ rich results are limited",
            "Since 2023 Google shows FAQ rich results only for well-known government and health sites. "
            "The markup can still help AI tools read your questions and answers. Use real questions only.")
    if "BreadcrumbList" in types:
        els = [e for e in _as_list(item.get("itemListElement")) if isinstance(e, dict)]
        if not els:
            add("high", "BreadcrumbList is empty", "Add itemListElement entries.")
        else:
            if any(not _has(e, "position") for e in els):
                add("medium", "Breadcrumb items are missing position", "Every ListItem needs a position number.")
            if any(not (_has(e, "name") or (isinstance(e.get("item"), dict) and _has(e["item"], "name"))) for e in els):
                add("medium", "Breadcrumb items are missing names", "Every ListItem needs a name.")
    if "Event" in types or any(t.endswith("Event") for t in types):
        for k in missing(["name", "startDate", "location"]):
            add("high" if k != "name" else "medium", f"Event is missing {k}", f"Google requires {k} for event results.")
    if "HowTo" in types:
        add("info", "HowTo rich results were retired", "Google stopped showing HowTo rich results in 2023. The markup is harmless.")
    return issues


def _price_tokens(text: str) -> set[str]:
    toks = set()
    for m in re.finditer(r"(?<![\d.])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?(?![\d])", text):
        whole = m.group(1).replace(",", "")
        toks.add(whole.lstrip("0") or "0")
        if m.group(2):
            toks.add(f"{whole.lstrip('0') or '0'}.{m.group(2)}")
    return toks


def _norm_price(v) -> str | None:
    try:
        f = float(str(v).replace(",", "").strip())
    except ValueError:
        return None
    return str(int(f)) if f == int(f) else f"{f:.2f}".rstrip("0").rstrip(".")


async def check_schema(raw_url: str) -> dict:
    url = normalize_page_url(raw_url)
    async with new_client() as client:
        r = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
    if r.status is None:
        raise FetchBlocked(f"We couldn't reach {url}. {r.error or ''}".strip())
    if r.status >= 400:
        raise FetchBlocked(f"That page returned HTTP {r.status}, so there's nothing to check. Try another URL.")
    doc = r.text
    visible = _visible_text(doc)
    is_saas = bool(_SAAS_HINTS.search(visible))

    blocks, items = [], []
    for i, m in enumerate(re.finditer(r"<script\b[^>]*type\s*=\s*[\"']?application/ld\+json[\"']?[^>]*>(.*?)</script>",
                                      doc, re.I | re.S)):
        if i >= SCHEMA_MAX_BLOCKS:
            break
        raw = m.group(1).strip()
        raw = re.sub(r"^\s*(<!--|<!\[CDATA\[)|(-->|\]\]>)\s*$", "", raw).strip()   # old-style wrappers
        try:
            data = json.loads(raw)
        except ValueError as exc:
            blocks.append({"index": i + 1, "valid": False, "error": str(exc)[:160], "snippet": raw[:120], "types": []})
            continue
        found = []
        def collect(node):
            if isinstance(node, list):
                for n in node:
                    collect(n)
            elif isinstance(node, dict):
                if "@graph" in node:
                    collect(node["@graph"])
                if node.get("@type"):
                    found.append(node)
        collect(data)
        blocks.append({"index": i + 1, "valid": True, "error": None, "snippet": None,
                       "types": [t for n in found for t in _types_of(n)]})
        items.extend(found)

    microdata = len(re.findall(r"\bitemscope\b", doc, re.I))
    rdfa = len(re.findall(r"\btypeof\s*=", doc, re.I))
    vis_prices = _price_tokens(visible)
    checked = []
    for it in items[:60]:
        types = _types_of(it)
        issues = _check_item(it, is_saas)
        for o in _offers(it):
            p = _norm_price(_offer_price(o))
            if p and p != "0" and p not in vis_prices:
                issues.append({"level": "medium", "title": f"Price {p} isn't shown on the page",
                               "detail": "The price in your structured data doesn't appear in the visible page text. Search engines "
                                         "and AI can repeat it, so it must match what customers see."})
        name = it.get("name") if isinstance(it.get("name"), str) else (it.get("headline") if isinstance(it.get("headline"), str) else None)
        checked.append({"types": types, "name": (name or "")[:120], "issues": issues,
                        "fields": sorted(k for k in it.keys() if not k.startswith("@"))[:40]})

    path = urlparse(r.url).path or "/"
    return {"url": url, "final_url": r.url, "blocks": blocks, "items": checked,
            "microdata": microdata, "rdfa": rdfa, "is_homepage": path in ("", "/"),
            "summary": _summarize_schema(blocks, checked, microdata + rdfa, path in ("", "/"))}


def _summarize_schema(blocks: list, items: list, other_formats: int, is_home: bool) -> dict:
    issues: list[dict] = []
    def add(level, title, detail):
        issues.append({"level": level, "title": title, "detail": detail})
    bad_blocks = [b for b in blocks if not b["valid"]]
    if not blocks:
        if other_formats:
            add("medium", "No JSON-LD found (microdata or RDFa only)",
                "Google recommends JSON-LD. It's also the format AI tools read most reliably.")
        else:
            add("high", "No structured data found",
                "This page has no schema markup, so search engines and AI have to guess what it's about. Use the generator below.")
    if bad_blocks:
        add("high", f"{len(bad_blocks)} schema block{'s are' if len(bad_blocks) != 1 else ' is'} broken JSON",
            "Search engines ignore a block they can't parse. Fix the syntax error shown below.")
    all_types = {t for it in items for t in it["types"]}
    if is_home and blocks and not (all_types & {"Organization", "Corporation", "OnlineBusiness"} or any(t.endswith("Business") for t in all_types)):
        add("medium", "No Organization schema on your homepage",
            "Organization markup tells search engines and AI your official name, logo and profiles.")
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    for it in items:
        for i in it["issues"]:
            if i["level"] in ("high", "medium"):
                issues.append({"level": i["level"], "title": f"{'/'.join(it['types'])}: {i['title']}", "detail": i["detail"]})
    issues.sort(key=lambda i: order.get(i["level"], 9))
    high = sum(1 for i in issues if i["level"] == "high")
    medium = sum(1 for i in issues if i["level"] == "medium")
    if high:
        verdict, headline = "action_needed", "Your structured data needs fixing"
    elif medium:
        verdict, headline = "improve", "Your structured data works, with room to improve"
    else:
        verdict, headline = "good", "Your structured data looks good"
    return {"verdict": verdict, "headline": headline, "issues": issues[:25]}


# ---------------------------------------------------------------------------------------------
# Tool 6: Broken Link Checker (one page). Every link, image, script and stylesheet on the page,
# checked with HEAD (GET fallback). Sites that refuse automated checks are reported as
# "couldn't verify", never as broken. Whole-site checks are Watch Owl's job (free plan).
# ---------------------------------------------------------------------------------------------

LINKS_MAX = 120
LINKS_CONCURRENCY = 8
LINKS_BUDGET_S = 30.0
_UNVERIFIABLE = {401, 403, 405, 406, 429, 999}


def _extract_links(doc: str, page_url: str) -> list[dict]:
    base = page_url
    bm = re.search(r"<base\b[^>]*href\s*=\s*[\"']([^\"']+)", doc, re.I)
    if bm:
        base = urljoin(page_url, html.unescape(bm.group(1)))
    found, seen = [], set()
    body = re.sub(r"<!--.*?-->", " ", doc, flags=re.S)
    patterns = [
        ("link", r"<a\b([^>]*)>(.*?)</a>", "href"),
        ("image", r"<img\b([^>]*)>()", "src"),
        ("script", r"<script\b([^>]*)>()", "src"),
        ("stylesheet", r"<link\b([^>]*)>()", "href"),
        ("frame", r"<iframe\b([^>]*)>()", "src"),
    ]
    for kind, pat, attr in patterns:
        for m in re.finditer(pat, body, re.I | re.S):
            attrs = m.group(1)
            if kind == "stylesheet" and not re.search(r"rel\s*=\s*[\"']?[^\"'>]*\b(stylesheet|icon|preload)\b", attrs, re.I):
                continue
            am = re.search(rf"\b{attr}\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s>]+))", attrs, re.I)
            if not am:
                continue
            href = html.unescape((am.group(2) if am.group(2) is not None else am.group(3) if am.group(3) is not None else am.group(4)) or "").strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:", "data:", "sms:", "blob:")):
                continue
            u = urljoin(base, href).split("#")[0]
            if not u.startswith(("http://", "https://")) or u in seen:
                continue
            if "/cdn-cgi/l/email-protection" in u:   # Cloudflare-obfuscated mailto: link, decoded by JS in browsers
                continue
            seen.add(u)
            text = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", m.group(2) or ""))).strip()[:80]
            found.append({"url": u, "type": kind, "text": text})
    return found


async def check_links(raw_url: str) -> dict:
    url = normalize_page_url(raw_url)
    page_host = urlparse(url).hostname
    async with new_client() as client:
        page = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
        if page.status is None:
            raise FetchBlocked(f"We couldn't reach {url}. {page.error or ''}".strip())
        if page.status >= 400:
            raise FetchBlocked(f"That page returned HTTP {page.status}. Check the address and try again.")
        links = _extract_links(page.text, page.url)
        total_found = len(links)
        # Internal pages first, then everything else, capped.
        links.sort(key=lambda l: (urlparse(l["url"]).hostname != page_host, l["type"] != "link"))
        links = links[:LINKS_MAX]
        sem = asyncio.Semaphore(LINKS_CONCURRENCY)
        deadline = time.monotonic() + LINKS_BUDGET_S

        async def probe(l: dict) -> dict:
            out = dict(l, internal=urlparse(l["url"]).hostname == page_host, http_status=None, final_url=None)
            async with sem:
                if time.monotonic() > deadline:
                    return dict(out, status="unchecked", detail="Not checked: time limit reached.")
                try:
                    r = await safe_get(client, l["url"], 1, method="HEAD", user_agent=BROWSER_UA)
                    if r.status is None or r.status in (400, 403, 404, 405, 501) or r.status >= 500:
                        r2 = await safe_get(client, l["url"], 2048, user_agent=BROWSER_UA)
                        if r2.status is not None or r.status is None:
                            r = r2
                except FetchBlocked as exc:
                    msg = str(exc)
                    if "couldn't find" in msg.lower():
                        return dict(out, status="broken", detail="The domain doesn't exist.")
                    return dict(out, status="skipped", detail=msg)
            out.update(http_status=r.status, final_url=r.url if r.url != l["url"] else None)
            if r.status is None:
                return dict(out, status="unverified", detail=r.error or "No response.")
            if r.status in _UNVERIFIABLE:
                return dict(out, status="unverified", detail=f"HTTP {r.status}: the site refuses automated checks, so we couldn't confirm this link.")
            if r.status >= 400:
                return dict(out, status="broken", detail=f"HTTP {r.status}" + (" (not found)" if r.status in (404, 410) else ""))
            if out["final_url"] and out["internal"]:
                return dict(out, status="redirect", detail=f"Redirects to {out['final_url']}")
            return dict(out, status="ok", detail=f"HTTP {r.status}")

        results = await asyncio.gather(*[probe(l) for l in links])

    counts = defaultdict(int)
    for x in results:
        counts[x["status"]] += 1
    return {"url": url, "final_url": page.url, "total_found": total_found, "checked": len(results),
            "capped": total_found > LINKS_MAX, "counts": dict(counts), "links": results,
            "summary": _summarize_links(results, total_found)}


def _summarize_links(results: list, total_found: int) -> dict:
    issues: list[dict] = []
    broken = [x for x in results if x["status"] == "broken"]
    internal_broken = [x for x in broken if x["internal"]]
    redirects = [x for x in results if x["status"] == "redirect"]
    unverified = [x for x in results if x["status"] == "unverified"]
    if internal_broken:
        issues.append({"level": "high", "title": f"{len(internal_broken)} broken link{'s' if len(internal_broken) != 1 else ''} to your own site",
                       "detail": "Visitors and crawlers hit dead ends. Fix the address or remove the link."})
    ext = len(broken) - len(internal_broken)
    if ext:
        issues.append({"level": "medium", "title": f"{ext} broken link{'s' if ext != 1 else ''} to other sites",
                       "detail": "The pages you link to no longer load. Update or remove them."})
    if redirects:
        issues.append({"level": "low", "title": f"{len(redirects)} internal link{'s' if len(redirects) != 1 else ''} go through a redirect",
                       "detail": "Point them straight at the final address to save a hop for visitors and crawlers."})
    if unverified:
        issues.append({"level": "info", "title": f"{len(unverified)} link{'s' if len(unverified) != 1 else ''} couldn't be verified",
                       "detail": "Some sites (LinkedIn, for example) refuse automated checks. Open these yourself to be sure."})
    if not total_found:
        issues.append({"level": "info", "title": "No links found on this page",
                       "detail": "If your links are added by JavaScript, they aren't in the page's HTML, and crawlers that don't run scripts can't see them either."})
    if broken:
        verdict, headline = "action_needed", f"Found {len(broken)} broken link{'s' if len(broken) != 1 else ''}"
    elif redirects:
        verdict, headline = "improve", "No broken links, a few redirects to tidy"
    else:
        verdict, headline = "good", "No broken links on this page"
    return {"verdict": verdict, "headline": headline, "issues": issues}


# ---------------------------------------------------------------------------------------------
# Indexability Checker, Redirect Checker,
# Mobile-Ready Checker. Same guardrails as every tool above: all fetching goes through safe_get (public IPs only,
# every redirect hop re-validated, byte caps, timeouts); zero LLM calls; nothing stored.
# ---------------------------------------------------------------------------------------------

INDEX_PAGE_BYTES = 600 * 1024
INDEX_BUDGET_S = 20.0
_NOINDEX_RE = re.compile(r"\b(noindex|none)\b", re.I)


def _robots_meta_values(doc: str) -> list[dict]:
    """Every <meta name="robots|googlebot|googlebot-news"> on the page: [{"name", "content"}] (quoted or unquoted attributes)."""
    out = []
    for m in re.finditer(r"<meta\b[^>]*>", doc, re.I):
        tag = m.group(0)
        n, c = (_attr(tag, "name") or "").lower(), _attr(tag, "content")
        if n in ("robots", "googlebot", "googlebot-news") and c is not None:
            out.append({"name": n, "content": c})
    return out


def _x_robots_noindex(header: str) -> str | None:
    """Returns the matching X-Robots-Tag directive if it blocks Google from indexing, else None.
    Handles 'noindex', 'none' and user-agent scoped values like 'googlebot: noindex' (other bots' scopes are ignored)."""
    for part in re.split(r",(?=\s*[a-z-]+\s*:)|\n", header or "", flags=re.I):
        part = part.strip()
        scope = re.match(r"^([a-z0-9_-]+)\s*:\s*(.*)$", part, re.I)
        if scope and scope.group(1).lower() not in ("unavailable_after",):
            if scope.group(1).lower() not in ("googlebot", "googlebot-news"):
                continue
            part = scope.group(2)
        if _NOINDEX_RE.search(part):
            return part
    return None


def _canonical(doc: str, base: str) -> str | None:
    for m in re.finditer(r"<link\b[^>]*>", doc, re.I):
        tag = m.group(0)
        if "canonical" in (_attr(tag, "rel") or "").lower().split():
            h = _attr(tag, "href")
            if h:
                return urljoin(base, h)
    return None


def _same_url(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    norm = lambda p: ((p.hostname or "").lower(), (p.path or "/").rstrip("/") or "/", p.query)
    return norm(pa) == norm(pb)


async def trace_redirects(client: httpx.AsyncClient, url: str, max_hops: int = 10,
                          user_agent: str | None = None) -> dict:
    """Follows a URL hop by hop (each hop validated by safe_get). Returns {"start", "hops": [{url, status, location}],
    "final_url", "final_status", "loop", "error"}. The final hop's body is read (capped) so callers can inspect it."""
    hops, seen, current = [], set(), url
    for _ in range(max_hops + 1):
        if current in seen:
            return {"start": url, "hops": hops, "final_url": current, "final_status": None, "loop": True, "error": "Redirect loop."}
        seen.add(current)
        r = await safe_get(client, current, 64 * 1024, follow_redirects=False, user_agent=user_agent)
        if r.status is None:
            return {"start": url, "hops": hops, "final_url": current, "final_status": None, "loop": False, "error": r.error}
        loc = r.headers.get("location")
        if r.status in (301, 302, 303, 307, 308) and loc:
            nxt = urljoin(current, loc)
            hops.append({"url": current, "status": r.status, "location": nxt})
            current = nxt
            continue
        hops.append({"url": current, "status": r.status, "location": None})
        return {"start": url, "hops": hops, "final_url": current, "final_status": r.status, "loop": False, "error": None,
                "final_headers": r.headers}
    return {"start": url, "hops": hops, "final_url": current, "final_status": None, "loop": False, "error": f"More than {max_hops} redirects."}


async def check_indexability(raw_url: str) -> dict:
    """Tool 7: "Can Google index this page?" One verdict from every signal that can stop indexing: HTTP status (after
    redirects), robots.txt for Googlebot, noindex in the robots meta tag or the X-Robots-Tag header, the canonical tag,
    and whether the page is listed in the site's sitemap."""
    page = normalize_page_url(raw_url)
    deadline = time.monotonic() + INDEX_BUDGET_S
    async with new_client() as client:
        trace = await trace_redirects(client, page, max_hops=8, user_agent=CRAWLER_UAS["Googlebot"])
        ua_refused = None
        if trace["final_status"] in (401, 403, 406, 429, 451, 503):
            # Many firewalls verify Googlebot by IP and refuse anyone else using its name (that's us). Re-check as a
            # normal browser so a correct firewall isn't reported as "Google can't index this page".
            btrace = await trace_redirects(client, page, max_hops=8, user_agent=BROWSER_UA)
            if btrace["final_status"] and btrace["final_status"] < 400:
                ua_refused, trace = trace["final_status"], btrace
        final = trace["final_url"]
        p = urlparse(final)
        site = f"{p.scheme}://{p.netloc}"
        page_r, robots_r = await asyncio.gather(
            safe_get(client, final, INDEX_PAGE_BYTES, user_agent=BROWSER_UA if ua_refused else CRAWLER_UAS["Googlebot"]) if trace["final_status"] else asyncio.sleep(0, None),
            safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES))
        if trace["final_status"] is None and trace["error"] and not trace["hops"]:
            raise FetchBlocked(f"We couldn't reach {page}. {trace['error']}".strip())
        robots, parsed = _read_robots(robots_r, site)
        sitemap_urls, sitemap_found = ([], None)
        if time.monotonic() < deadline:
            sitemap_urls, sitemap_found = await _collect_sitemap_urls(client, site, robots["sitemaps"], deadline)

    checks = []
    def add(key, state, title, detail):
        checks.append({"key": key, "state": state, "title": title, "detail": detail})

    st = trace["final_status"]
    redirected = len(trace["hops"]) > 1
    if st is None:
        add("status", "fail", "The page didn't load", trace["error"] or "No response from the server.")
    elif st in (401, 403, 406, 429, 451, 503) and not ua_refused:
        add("status", "warn", f"The server refused our check (HTTP {st})",
            "Your server or firewall turned away our test visit, both as Googlebot and as a normal browser. That doesn't prove Google is "
            "blocked (Google crawls from its own verified addresses), but we couldn't read the page. Use URL Inspection in Google Search Console to confirm.")
    elif st >= 400:
        add("status", "fail", f"The page returns HTTP {st}", "Google only indexes pages that load (HTTP 200). Fix the page or redirect it with a 301 to its replacement.")
    elif st >= 300:
        add("status", "warn", f"HTTP {st} without a redirect target", "The server answered with a redirect code but no address to go to.")
    elif redirected and _same_url(re.sub(r"^https?://(www\.)?", "https://", page), re.sub(r"^https?://(www\.)?", "https://", final)):
        add("status", "pass", f"Loads at the main address ({final})", "Your address redirects once to your preferred https/www version, which is correct.")
    elif redirected:
        add("status", "warn", f"Redirects to {final}", f"The address you entered redirects ({len(trace['hops']) - 1} hop{'s' if len(trace['hops']) > 2 else ''}). Google indexes the final page, not this address. Link to the final address directly.")
    else:
        add("status", "pass", "The page loads (HTTP 200)", "Google can fetch it.")

    if ua_refused:
        add("firewall", "warn", f"Your server refused our test visit as Googlebot (HTTP {ua_refused})",
            "A normal browser got the page, so this is usually a firewall verifying the real Googlebot by IP address and blocking "
            "anyone else using its name, which is correct. Confirm with URL Inspection in Google Search Console.")
    path = (p.path or "/") + (("?" + p.query) if p.query else "")
    if robots["state"] == "unreachable":
        add("robots", "warn", "robots.txt couldn't be read", "When robots.txt returns a server error, Google may pause crawling the whole site. Make sure /robots.txt loads.")
    elif robots["state"] == "missing":
        add("robots", "pass", "No robots.txt rules block this page", "There's no robots.txt file, so nothing is blocked.")
    else:
        rules, agent = _rules_for(parsed, "googlebot")
        if is_allowed(rules, path):
            add("robots", "pass", "robots.txt allows Googlebot here", f"Checked the rules for user-agent: {agent or '(none)'}.")
        else:
            add("robots", "fail", "robots.txt blocks Googlebot from this page",
                f"A Disallow rule for user-agent: {agent} matches {path}. Google can't crawl the page, so it can't read its content. "
                "It may still show the bare address in results if other sites link to it.")

    doc = page_r.text if (page_r and page_r.body) else ""
    xrt = _x_robots_noindex((page_r.headers if page_r else {}).get("x-robots-tag", "")) if page_r else None
    metas = _robots_meta_values(doc)
    meta_noindex = [m for m in metas if _NOINDEX_RE.search(m["content"])]
    if xrt:
        add("x_robots", "fail", "The X-Robots-Tag header says noindex", f"The server sends \"X-Robots-Tag: {xrt}\", which tells Google not to index this page. Remove it from your server or CDN settings.")
    else:
        add("x_robots", "pass", "No noindex in the X-Robots-Tag header", "The server isn't telling Google to skip this page.")
    if meta_noindex:
        m = meta_noindex[0]
        add("meta_robots", "fail", f"The page has a {m['name']} meta tag with noindex",
            f"<meta name=\"{m['name']}\" content=\"{m['content']}\"> tells Google not to index this page. This often stays behind after a redesign "
            "or from a staging site. Remove it (in WordPress: Settings → Reading → uncheck \"Discourage search engines\").")
    else:
        add("meta_robots", "pass", "No noindex meta tag", "The page doesn't ask Google to stay out.")

    canon = _canonical(doc, final) if doc else None
    if not doc:
        add("canonical", "warn", "Couldn't read the page's HTML", "We couldn't check the canonical tag.")
    elif not canon:
        add("canonical", "warn", "No canonical tag", "Not a blocker, but a self-referencing canonical tells Google which address is the main one, especially when the same page is reachable through several URLs.")
    elif _same_url(canon, final):
        add("canonical", "pass", "The canonical points to this page", canon)
    else:
        add("canonical", "warn", "The canonical points to a different page",
            f"The canonical is {canon}. Google will usually index that page instead of this one. That's right for duplicates, wrong if this page should rank.")

    if not sitemap_found:
        add("sitemap", "warn", "No sitemap found", "We couldn't find a sitemap in robots.txt or at /sitemap.xml. A sitemap helps Google discover your pages.")
    elif any(_same_url(u, final) for u in sitemap_urls):
        add("sitemap", "pass", "Listed in your sitemap", sitemap_found)
    else:
        add("sitemap", "warn", "Not listed in your sitemap",
            f"We read {len(sitemap_urls)} URLs from {sitemap_found} and didn't find this page. Add it so Google discovers it faster. "
            "(Large sites split their sitemap into many files and we read only the first few, so check the rest in Search Console.)")

    blockers = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    refused = st in (401, 403, 406, 429, 451, 503) and not ua_refused
    if refused and not blockers:
        verdict, headline = "improve", "We couldn't check this page fully"
    elif blockers:
        verdict, headline = "action_needed", "Google can't index this page"
    elif warns:
        verdict, headline = "improve", "Google can index this page, with things to fix"
    else:
        verdict, headline = "good", "Google can index this page"
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in blockers] + \
             [{"level": "medium" if c["key"] in ("canonical", "status") else "low", "title": c["title"], "detail": c["detail"]} for c in warns]
    issues.append({"level": "info", "title": "Indexable isn't the same as indexed",
                   "detail": "This shows whether Google is allowed to index the page. Google still decides whether to. For the final word, use URL Inspection in Google Search Console."})
    return {"url": page, "final_url": final, "status": st, "redirect_hops": max(0, len(trace["hops"]) - 1), "checks": checks,
            "robots_state": robots["state"], "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


REDIRECT_MAX_URLS = 10


def _redirect_inputs(raw: str) -> tuple[list[str], bool]:
    """One URL -> it plus its http/https x www/non-www variants. Several URLs (spaces, commas or new lines) -> each as given."""
    parts = [x for x in re.split(r"[\s,]+", (raw or "").strip()) if x]
    if not parts:
        raise FetchBlocked("Please enter a website or page address.")
    if len(parts) > 1:
        return [normalize_page_url(x) for x in parts[:REDIRECT_MAX_URLS]], False
    u = normalize_page_url(parts[0])
    pu = urlparse(u)
    host = pu.hostname or ""
    bare = host[4:] if host.startswith("www.") else host
    rest = (pu.path or "/") + (("?" + pu.query) if pu.query else "")
    variants = [u] + [f"{s}://{h}{rest}" for s in ("http", "https") for h in (bare, "www." + bare)]
    out = []
    for v in variants:
        if v not in out:
            out.append(v)
    return out, True


async def check_redirects(raw_url: str) -> dict:
    """Tool 8: Redirect Checker. Follows every hop for the URL (plus its http/https and www variants), or for a list of
    old URLs. Flags 302s used for permanent moves, chains, loops, mixed http hops, variants that end on different
    pages, and old URLs that end on an error instead of redirecting."""
    urls, with_variants = _redirect_inputs(raw_url)
    sem = asyncio.Semaphore(4)
    async with new_client() as client:
        async def one(u):
            async with sem:
                try:
                    return await trace_redirects(client, u, max_hops=10)
                except FetchBlocked as exc:
                    return {"start": u, "hops": [], "final_url": u, "final_status": None, "loop": False, "error": str(exc)}
        traces = await asyncio.gather(*[one(u) for u in urls])
    if all(t["final_status"] is None and not t["hops"] for t in traces):
        raise FetchBlocked(f"We couldn't reach {urls[0]}. {traces[0]['error'] or ''}".strip())

    results = []
    for t in traces:
        flags = []
        hops = t["hops"]
        redirect_hops = [h for h in hops if h["location"]]
        if t["loop"]:
            flags.append(("high", "Redirect loop", "The address redirects back to itself, so it never loads."))
        elif t["final_status"] is None:
            flags.append(("high", "Didn't finish loading", t["error"] or "No response."))
        elif t["final_status"] >= 400:
            flags.append(("high", f"Ends on an error (HTTP {t['final_status']})",
                          "This address doesn't reach a working page. If it's an old URL, add a 301 redirect to its new page so visitors and rankings follow."))
        temp = [h for h in redirect_hops if h["status"] in (302, 303, 307)]
        if temp:
            flags.append(("medium", f"Uses a temporary redirect ({', '.join(str(h['status']) for h in temp)})",
                          "302/307 tell Google the move is temporary. For a permanent move (new site, new URL, http to https), use a 301 or 308."))
        if len(redirect_hops) > 1:
            flags.append(("medium" if len(redirect_hops) > 2 else "low", f"Redirect chain: {len(redirect_hops)} hops",
                          "Each hop adds delay for visitors and crawlers. Point the first address straight at the final one."))
        if any(h["location"] and h["location"].startswith("http://") for h in redirect_hops[:-1] or []) or \
           (t["final_url"].startswith("http://") and t["final_status"] and t["final_status"] < 400):
            flags.append(("medium", "Ends on or passes through http://", "Visitors should land on https. Redirect http to https in one step."))
        state = "error" if any(f[0] == "high" for f in flags) else ("redirect" if redirect_hops else "ok")
        results.append({"start": t["start"], "final_url": t["final_url"], "final_status": t["final_status"], "hops": hops,
                        "state": state, "flags": [{"level": l, "title": a, "detail": b} for l, a, b in flags]})

    issues = []
    errs = [r for r in results if r["state"] == "error"]
    if errs:
        issues.append({"level": "high", "title": f"{len(errs)} address{'es don' if len(errs) != 1 else ' doesn'}'t reach a working page",
                       "detail": "Old links that end on an error throw away the visitors and rankings they earned. Add 301 redirects to the matching new pages."})
    temp = [r for r in results if any("temporary" in f["title"] for f in r["flags"])]
    if temp:
        issues.append({"level": "medium", "title": "Temporary redirects where a permanent one is expected",
                       "detail": "Switch 302/307 to 301 for permanent moves so Google transfers the old address's signals to the new one."})
    chains = [r for r in results if any(f["title"].startswith("Redirect chain") for f in r["flags"])]
    if chains:
        issues.append({"level": "low", "title": f"{len(chains)} redirect chain{'s' if len(chains) != 1 else ''}",
                       "detail": "Collapse chains into a single hop: the first address should redirect straight to the final page."})
    if with_variants:
        finals = {(urlparse(r["final_url"]).hostname, urlparse(r["final_url"]).scheme, (urlparse(r["final_url"]).path or "/").rstrip("/"))
                  for r in results if r["final_status"] and r["final_status"] < 400}
        if len(finals) > 1:
            issues.append({"level": "medium", "title": "Your http/https and www versions end on different pages",
                           "detail": "Pick one main version (for example https://www.) and 301-redirect every other version to it, so links and rankings aren't split."})
    if errs:
        verdict, headline = "action_needed", "Some addresses don't reach a working page"
    elif any(i["level"] in ("high", "medium") for i in issues):
        verdict, headline = "improve", "Redirects work, with things to fix"
    else:
        verdict, headline = "good", "Your redirects look healthy"
    return {"input_count": len(urls), "variants": with_variants, "results": results,
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


MOBILE_UA = ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
             "Version/18.0 Mobile/15E148 Safari/604.1")
MOBILE_PAGE_BYTES = 1024 * 1024
_PSI_CACHE: dict[str, tuple[float, dict]] = {}
_PSI_CACHE_S = 6 * 3600



async def _mobile_speed(url: str) -> dict:
    """Google PageSpeed Insights (mobile) with YOUR OWN API key (env PAGESPEED_API_KEY; create one in Google Cloud Console
    after enabling the PageSpeed Insights API). Cached 6 h per URL. Never raises: returns {"state": "ok"|"unavailable", ...}."""
    import os
    hit = _PSI_CACHE.get(url)
    if hit and time.time() - hit[0] < _PSI_CACHE_S:
        return hit[1]
    key = os.environ.get("PAGESPEED_API_KEY")
    if not key:
        return {"state": "unavailable", "reason": "Set PAGESPEED_API_KEY to include Google's mobile speed test. Every other check still ran."}
    try:
        async with httpx.AsyncClient(timeout=100.0) as c:
            r = await c.get("https://www.googleapis.com/pagespeedonline/v5/runPagespeed",
                            params={"url": url, "strategy": "MOBILE", "category": "PERFORMANCE"}, headers={"X-Goog-Api-Key": key})
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return {"state": "unavailable", "reason": f"Google's speed test didn't finish ({type(exc).__name__}). Try again in a minute."}
    lh = data.get("lighthouseResult", {})
    audits, perf = lh.get("audits", {}), (lh.get("categories", {}).get("performance") or {}).get("score")
    lab = {k: (audits.get(a) or {}).get("displayValue") for k, a in (("LCP", "largest-contentful-paint"), ("CLS", "cumulative-layout-shift"),
                                                                     ("TBT", "total-blocking-time"), ("FCP", "first-contentful-paint"))}
    le = data.get("loadingExperience", {}).get("metrics", {})
    field = {k: {"percentile": (le.get(m) or {}).get("percentile"), "category": (le.get(m) or {}).get("category")}
             for k, m in (("LCP", "LARGEST_CONTENTFUL_PAINT_MS"), ("INP", "INTERACTION_TO_NEXT_PAINT"), ("CLS", "CUMULATIVE_LAYOUT_SHIFT_SCORE")) if m in le}
    rt = lh.get("runtimeError") or {}
    out = {"state": "ok", "performance": round(perf * 100) if perf is not None else None, "lab": lab, "field_available": bool(field),
           "field": field, "runtime_error": rt if rt.get("code") not in (None, "NO_ERROR") else None}
    _PSI_CACHE[url] = (time.time(), out)
    return out


def _viewport_checks(doc: str) -> list[dict]:
    vp = _meta(doc, "name", "viewport")
    checks = []
    if vp is None:
        checks.append({"key": "viewport", "state": "fail", "title": "No viewport tag",
                       "detail": "Without <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">, phones show the desktop layout zoomed out, with tiny text."})
        return checks
    v = vp.lower().replace(" ", "")
    if "width=device-width" not in v:
        checks.append({"key": "viewport", "state": "fail", "title": "The viewport doesn't use the device width",
                       "detail": f"The tag is \"{vp}\". Use width=device-width so the page fits each phone's screen."})
    else:
        checks.append({"key": "viewport", "state": "pass", "title": "Viewport set for phones", "detail": vp})
    ms = re.search(r"maximum-scale=([\d.]+)", v)
    if "user-scalable=no" in v or "user-scalable=0" in v or (ms and float(ms.group(1)) < 2):
        checks.append({"key": "zoom", "state": "warn", "title": "Pinch-to-zoom is disabled",
                       "detail": "user-scalable=no or a low maximum-scale stops visitors zooming in, which is an accessibility problem (WCAG 1.4.4). Remove it."})
    return checks


async def check_mobile(raw_url: str) -> dict:
    """Tool 9: Mobile-Ready Checker. Loads the page as an iPhone and as a desktop browser and compares them (Google
    indexes the mobile version), checks the viewport and zoom settings, image sizes that cause layout shift, and runs
    Google's mobile PageSpeed test for Core Web Vitals (lab + real-visitor data when Google has it)."""
    page = normalize_page_url(raw_url)
    async with new_client() as client:
        mob, desk = await asyncio.gather(safe_get(client, page, MOBILE_PAGE_BYTES, user_agent=MOBILE_UA),
                                         safe_get(client, page, MOBILE_PAGE_BYTES, user_agent=BROWSER_UA))
    if mob.status is None and desk.status is None:
        raise FetchBlocked(f"We couldn't reach {page}. {mob.error or ''}".strip())
    speed = await _mobile_speed(mob.url if mob.status and mob.status < 400 else page)

    checks: list[dict] = []
    def add(key, state, title, detail):
        checks.append({"key": key, "state": state, "title": title, "detail": detail})

    if mob.status is None or mob.status >= 400:
        add("loads", "fail", f"Phones can't load the page (HTTP {mob.status or 'no response'})",
            f"A desktop browser got HTTP {desk.status or 'no response'}. If phones are blocked or broken, Google, which indexes the mobile version, sees the same.")
    else:
        add("loads", "pass", f"The page loads on phones (HTTP {mob.status})", "")
    if mob.status and desk.status and urlparse(mob.url).hostname != urlparse(desk.url).hostname:
        add("separate", "warn", f"Phones are sent to a separate site ({urlparse(mob.url).hostname})",
            "Separate mobile sites (m.example.com) are harder to keep in sync. Google recommends one responsive site.")

    doc = mob.text if mob.status and mob.status < 400 else ""
    if doc:
        checks.extend(_viewport_checks(doc))
        mw = _visible_word_count(doc)
        dw = _visible_word_count(desk.text) if desk.status and desk.status < 400 else 0
        if dw >= 150 and mw < dw * 0.6:
            add("parity", "warn", "Phones get much less content than desktop",
                f"Phones get about {mw} words, desktop about {dw}. Google indexes the mobile version, so content missing on phones can't rank.")
        elif dw:
            add("parity", "pass", "Phones get the same content as desktop", f"About {mw} words on mobile, {dw} on desktop.")
        imgs = re.findall(r"<img\b[^>]*>", doc, re.I)
        nosize = [i for i in imgs if not (re.search(r"\bwidth\s*=", i, re.I) and re.search(r"\bheight\s*=", i, re.I))
                  and not re.search(r"\.svg\b", i, re.I)]
        if len(nosize) >= 3:
            add("img_size", "warn", f"{len(nosize)} of {len(imgs)} images have no width and height",
                "Without them the page jumps as images load (layout shift), which is worse on small screens. Add width and height attributes.")
        elif imgs:
            add("img_size", "pass", "Images declare their size", f"{len(imgs) - len(nosize)} of {len(imgs)} images have width and height.")
        head = doc.split("</head>", 1)[0] if "</head>" in doc.lower() else doc[:20000]
        blocking = [s for s in re.findall(r"<script\b[^>]*\bsrc=[^>]*>", head, re.I) if not re.search(r"\b(async|defer)\b|type\s*=\s*[\"']?module", s, re.I)]
        if len(blocking) >= 3:
            add("blocking", "warn", f"{len(blocking)} scripts block the page from showing",
                "Scripts in the <head> without async or defer must download before anything appears, which hurts most on mobile networks.")

    # speed (Google PageSpeed Insights, mobile)
    LCP_GOOD, CLS_GOOD, INP_GOOD = 2500, 0.1, 200
    if speed["state"] == "ok":
        f = speed["field"] or {}
        def fm(k):
            m = f.get(k) or {}
            return m.get("percentile"), (m.get("category") or "").upper()
        lcp_p, lcp_c = fm("largest_contentful_paint")
        cls_p, cls_c = fm("cumulative_layout_shift")
        inp_p, inp_c = fm("interaction_to_next_paint")
        if speed["field_available"] and lcp_p is not None:
            add("lcp", "pass" if lcp_p <= LCP_GOOD else "warn", f"Real phones: main content shows in {lcp_p / 1000:.1f}s (LCP)",
                "Good is 2.5 seconds or less, measured on real Chrome visitors over the last 28 days.")
            if cls_p is not None:
                cls_v = cls_p / 100          # CrUX reports CLS percentiles x100 (5 = 0.05)
                add("cls", "pass" if cls_v <= CLS_GOOD else "warn", f"Real phones: layout shift {cls_v:.2f} (CLS)", "Good is 0.1 or less.")
            if inp_p is not None:
                add("inp", "pass" if inp_p <= INP_GOOD else "warn", f"Real phones: responds to taps in {inp_p} ms (INP)", "Good is 200 ms or less.")
        lab = speed["lab"] or {}
        perf = speed["performance"]
        if perf is not None:
            score = round(perf if perf > 1 else perf * 100)   # _mobile_speed already returns 0-100
            add("speed", "pass" if score >= 90 else ("warn" if score >= 50 else "fail"), f"Mobile speed score: {score}/100",
                "Google's lab test on a mid-range phone and a slow 4G connection. 90+ is good, 50 to 89 needs work."
                + (f" Main content in {lab.get('largest_contentful_paint', {}).get('display_value')}." if lab.get("largest_contentful_paint") else ""))
    checks_order = {"fail": 0, "warn": 1, "pass": 2}
    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in fails] + \
             [{"level": "medium", "title": c["title"], "detail": c["detail"]} for c in warns]
    if speed["state"] != "ok":
        issues.append({"level": "info", "title": "Speed test not included", "detail": speed.get("reason", "")})
    if fails:
        verdict, headline = "action_needed", "Your page isn't ready for phones"
    elif warns:
        verdict, headline = "improve", "Your page works on phones, with things to fix"
    else:
        verdict, headline = "good", "Your page is ready for phones"
    return {"url": page, "final_url": mob.url, "status": mob.status, "checks": sorted(checks, key=lambda c: checks_order[c["state"]]),
            "speed": {k: v for k, v in speed.items() if k in ("state", "performance", "field_available", "reason")},
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---------------------------------------------------------------------------------------------
# Meta Tag Checker (with Google snippet preview),
# Open Graph Checker, Image Size Checker, Sitemap Checker. Same guardrails as every tool above: all fetching goes
# through safe_get (public IPs only, every redirect hop re-validated, byte caps, timeouts); zero LLM calls; nothing stored.
# ---------------------------------------------------------------------------------------------

import base64
import io
import zlib

# Approximate Arial advance widths (units per 1000 em). Google shows titles in ~20px Arial on desktop and cuts them at
# roughly 600px; descriptions in ~14px Arial at roughly 920px. Character counts alone mislead (W is 4x wider than i).
_ARIAL = {**{c: 556 for c in "abdeghnopqu0123456789#$_?"}, **{c: 500 for c in "ckszvxyJ"}, **{c: 222 for c in "ijl"},
          **{c: 278 for c in "ft .,:;!/I"}, **{c: 333 for c in "r-()"}, "m": 833, "w": 722, "'": 191, '"': 355, "|": 260,
          **{c: 667 for c in "ABEKPSVXY&"}, **{c: 722 for c in "CDHNRUw"}, **{c: 611 for c in "FTZ"}, **{c: 778 for c in "GOQ"},
          "L": 556, "M": 833, "W": 944, "@": 1015, "%": 889, "+": 584, "=": 584, "–": 556, "—": 1000, "…": 1000}
TITLE_PX, TITLE_FONT = 600, 20
DESC_PX, DESC_FONT = 920, 14


def text_px(s: str, font_px: int) -> int:
    return round(sum(_ARIAL.get(c, 600 if ord(c) > 127 else 556) for c in s or "") * font_px / 1000)


def truncate_px(s: str, limit: int, font_px: int) -> tuple[str, bool]:
    """Cut at a word boundary so the text plus an ellipsis fits `limit` pixels, like Google's snippet."""
    s = re.sub(r"\s+", " ", s or "").strip()
    if text_px(s, font_px) <= limit:
        return s, False
    out = ""
    for w in s.split(" "):
        cand = (out + " " + w).strip()
        if text_px(cand + " ...", font_px) > limit:
            break
        out = cand
    return (out or s[:20]).rstrip(" ,;:-|") + " ...", True


def _fetch_page_or_raise(r: FetchResult, url: str) -> None:
    if r.status is None:
        raise FetchBlocked(f"We couldn't reach {url}. {r.error or ''}".strip())
    if r.status >= 400:
        raise FetchBlocked(f"That page returned HTTP {r.status}. Check the address and try again.")


def _strip_noise(doc: str) -> str:
    return re.sub(r"<!--.*?-->|<(script|style|noscript|template)\b.*?</\1>", " ", doc, flags=re.I | re.S)


# ---- Tool 10: Meta Tag Checker ---------------------------------------------------------------

def _headings(doc: str) -> list[dict]:
    out = []
    for m in re.finditer(r"<h([1-6])\b[^>]*>(.*?)</h\1>", _strip_noise(doc), re.I | re.S):
        t = re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]+>", " ", m.group(2)))).strip()
        out.append({"level": int(m.group(1)), "text": t[:140]})
    return out


def _serp_breadcrumb(url: str) -> str:
    p = urlparse(url)
    segs = [s for s in (p.path or "/").split("/") if s][:3]
    return f"{p.scheme}://{p.hostname}" + "".join(f" › {s}" for s in segs)


async def check_meta_tags(raw_url: str) -> dict:
    """Title + meta description (length and pixel width, Google snippet preview), H1 and heading outline, image alt text,
    html lang, canonical presence and a noindex warning."""
    url = normalize_page_url(raw_url)
    async with new_client() as client:
        r = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
    _fetch_page_or_raise(r, url)
    doc = r.text
    title = _title(doc) or ""
    desc = _meta(doc, "name", "description") or ""
    heads = _headings(doc)
    h1s = [h["text"] for h in heads if h["level"] == 1]
    imgs = re.findall(r"<img\b[^>]*>", _strip_noise(doc), re.I)
    no_alt = [i for i in imgs if _attr(i, "alt") is None]
    lang = _attr((re.search(r"<html\b[^>]*>", doc, re.I) or re.match("", "")).group(0) or "", "lang")
    canon = _canonical(doc, r.url)
    noindex = [m for m in _robots_meta_values(doc) if _NOINDEX_RE.search(m["content"])]
    words = _visible_word_count(doc)
    t_disp, t_cut = truncate_px(title, TITLE_PX, TITLE_FONT)
    d_disp, d_cut = truncate_px(desc, DESC_PX, DESC_FONT)
    t_px, d_px = text_px(title, TITLE_FONT), text_px(desc, DESC_FONT)

    checks = []
    def add(key, state, t, d):
        checks.append({"key": key, "state": state, "title": t, "detail": d})

    if not title:
        add("title", "fail", "No title tag", "Google writes its own title for your result, usually from a heading. Add a <title> that says what the page is and who it's for.")
    elif t_cut:
        add("title", "warn", f"Title is cut off in Google ({len(title)} characters, about {t_px}px)",
            f"Google shows roughly {TITLE_PX}px of a title on desktop. Put the words that matter first, or shorten it to about 50–60 characters.")
    elif len(title) < 30:
        add("title", "warn", f"Title is short ({len(title)} characters)", "There's room to say more: what the page offers and for whom, in about 50–60 characters.")
    else:
        add("title", "pass", f"Title fits ({len(title)} characters, about {t_px}px)", title)
    if not desc:
        add("description", "warn", "No meta description", "Google picks a snippet from your page text instead, which may not sell the click. Write 120–155 characters that answer the searcher's question.")
    elif d_cut:
        add("description", "warn", f"Description is cut off ({len(desc)} characters, about {d_px}px)",
            "Google usually shows about 920px (roughly 150–160 characters) on desktop and less on phones. Lead with the key point.")
    elif len(desc) < 70:
        add("description", "warn", f"Description is short ({len(desc)} characters)", "Short descriptions waste space in the result. Aim for 120–155 characters.")
    else:
        add("description", "pass", f"Description fits ({len(desc)} characters)", desc)
    if title and desc and title.strip().lower() == desc.strip().lower():
        add("dup", "warn", "Title and description are the same", "Use the description to add what the title can't: a benefit, a detail, a reason to click.")
    if not h1s:
        add("h1", "fail", "No H1 heading", "Every page should have one main heading that says what it's about. Google and screen readers use it to understand the page.")
    elif len(h1s) > 1:
        add("h1", "warn", f"{len(h1s)} H1 headings", "One H1 per page is clearest. Turn the others into H2s. First H1: " + h1s[0][:80])
    else:
        add("h1", "pass", "One H1 heading", h1s[0])
    skips = [f"H{a['level']} → H{b['level']}" for a, b in zip(heads, heads[1:]) if b["level"] > a["level"] + 1]
    if skips:
        add("outline", "warn", "Heading levels skip", f"Headings jump a level ({', '.join(skips[:3])}). Use them in order (H2 under H1, H3 under H2) so the structure reads clearly.")
    elif len(heads) > 1:
        add("outline", "pass", f"Heading structure is in order ({len(heads)} headings)", "No skipped levels.")
    if imgs and no_alt:
        add("alt", "warn", f"{len(no_alt)} of {len(imgs)} images have no alt attribute",
            "Alt text describes images for screen readers and image search. Use alt=\"\" for purely decorative images.")
    elif imgs:
        add("alt", "pass", f"All {len(imgs)} images have an alt attribute", "")
    if not lang:
        add("lang", "warn", "No language set on the page", "Add lang=\"en\" (or your language) to the <html> tag. Browsers, translators and screen readers use it.")
    else:
        add("lang", "pass", f"Language set ({lang})", "")
    if canon:
        add("canonical", "pass" if _same_url(canon, r.url) else "warn", "Canonical tag found" if _same_url(canon, r.url) else "Canonical points to another page",
            canon + ("" if _same_url(canon, r.url) else ". Check it with the Indexability Checker."))
    else:
        add("canonical", "warn", "No canonical tag", "A self-referencing canonical tells Google which address is the main one.")
    if noindex:
        add("noindex", "fail", "This page has a noindex tag", f"<meta name=\"{noindex[0]['name']}\" content=\"{noindex[0]['content']}\"> keeps it out of Google, so none of these tags will show. See the Indexability Checker.")
    if words < 300:
        add("words", "warn", f"Thin page text (about {words} words in the HTML)",
            "Short pages can rank, but they need to answer the question fully. If your content loads with JavaScript, crawlers that don't run scripts see less.")

    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in fails] + \
             [{"level": "medium" if c["key"] in ("title", "description", "h1") else "low", "title": c["title"], "detail": c["detail"]} for c in warns]
    if fails:
        verdict, headline = "action_needed", "Fix these tags before anything else"
    elif warns:
        verdict, headline = "improve", "Your tags work, with things to improve"
    else:
        verdict, headline = "good", "Your meta tags look good"
    issues.append({"level": "info", "title": "Google may rewrite your snippet",
                   "detail": "Google sometimes shows different text when it thinks another part of the page answers the search better. Clear, specific tags make that less likely."})
    order = {"fail": 0, "warn": 1, "pass": 2}
    return {"url": url, "final_url": r.url,
            "title": {"text": title, "chars": len(title), "px": t_px, "limit_px": TITLE_PX, "truncated": t_cut},
            "description": {"text": desc, "chars": len(desc), "px": d_px, "limit_px": DESC_PX, "truncated": d_cut},
            "serp": {"breadcrumb": _serp_breadcrumb(r.url), "site": urlparse(r.url).hostname, "title": t_disp or "(no title)", "description": d_disp},
            "headings": heads[:60], "images": len(imgs), "images_no_alt": len(no_alt), "lang": lang, "canonical": canon, "words": words,
            "checks": sorted(checks, key=lambda c: order[c["state"]]),
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Tool 11: Open Graph Checker ---------------------------------------------------------------

OG_IMAGE_BYTES = 6 * 1024 * 1024    # X and LinkedIn reject images over 5 MB; Facebook allows 8 MB
_THUMB_W = 600


def _social_meta(doc: str) -> dict:
    out: dict = {}
    for m in re.finditer(r"<meta\b[^>]*>", doc, re.I):
        tag = m.group(0)
        key = (_attr(tag, "property") or _attr(tag, "name") or "").lower()
        if key.startswith(("og:", "twitter:")) and key not in out:
            c = _attr(tag, "content")
            if c is not None:
                out[key] = c
    return out


def _image_info(data: bytes) -> dict:
    """Format, width, height and a small JPEG thumbnail (data: URI) from image bytes. Pillow, bomb-limited."""
    from PIL import Image
    Image.MAX_IMAGE_PIXELS = 40_000_000
    try:
        im = Image.open(io.BytesIO(data))
        fmt, (w, h) = (im.format or "").upper(), im.size
    except Exception:
        return {}
    info = {"format": fmt, "width": w, "height": h}
    try:
        im.draft("RGB", (_THUMB_W * 2, _THUMB_W * 2))
        im = im.convert("RGB")
        im.thumbnail((_THUMB_W, _THUMB_W))
        buf = io.BytesIO()
        im.save(buf, "JPEG", quality=72, optimize=True)
        info["thumb"] = "data:image/jpeg;base64," + base64.b64encode(buf.getvalue()).decode()
    except Exception:
        pass
    return info


async def check_open_graph(raw_url: str) -> dict:
    """How a link to this page looks when shared on X, LinkedIn, Facebook and messaging apps: og: and twitter: tags,
    the share image (loads? size? dimensions? ratio?) and per-platform previews built from each platform's fallbacks."""
    url = normalize_page_url(raw_url)
    async with new_client() as client:
        r = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
        _fetch_page_or_raise(r, url)
        doc = r.text
        tags = _social_meta(doc)
        img_raw = tags.get("og:image") or tags.get("og:image:url") or tags.get("og:image:secure_url") or tags.get("twitter:image") or ""
        img_url = urljoin(r.url, img_raw) if img_raw else ""
        img = {"url": img_url, "relative": bool(img_raw) and not re.match(r"^https?://", img_raw, re.I)}
        if img_url:
            try:
                ir = await safe_get(client, img_url, OG_IMAGE_BYTES, user_agent=BROWSER_UA)
                img.update(status=ir.status, type=ir.headers.get("content-type", "").split(";")[0], bytes=len(ir.body),
                           too_big=ir.truncated, error=ir.error)
                if ir.status == 200 and ir.body and not ir.truncated:
                    img.update(_image_info(ir.body))
            except FetchBlocked as exc:
                img.update(status=None, error=str(exc))
    title = _title(doc) or ""
    desc = _meta(doc, "name", "description") or ""
    host = urlparse(r.url).hostname or ""
    og_t, og_d = tags.get("og:title", ""), tags.get("og:description", "")
    tw_card = tags.get("twitter:card", "")
    thumb = img.get("thumb")
    cut = lambda s, n: (s[: n - 1].rstrip() + "…") if len(s) > n else s
    previews = {
        "x": {"card": tw_card or ("summary" if (og_t or title) else "none"), "title": cut(tags.get("twitter:title") or og_t or title, 70),
              "description": cut(tags.get("twitter:description") or og_d or desc, 120), "image": thumb, "domain": host},
        "linkedin": {"title": cut(og_t or title, 110), "image": thumb, "domain": host},
        "facebook": {"title": cut(og_t or title, 88), "description": cut(og_d or desc, 110), "image": thumb, "domain": host.upper()},
        "message": {"title": cut(og_t or title, 65), "description": cut(og_d or desc, 90), "image": thumb, "domain": host},
    }

    checks = []
    def add(key, state, t, d):
        checks.append({"key": key, "state": state, "title": t, "detail": d})

    add("og_title", "pass" if og_t else ("warn" if title else "fail"), "og:title set" if og_t else "No og:title",
        og_t or ("Platforms fall back to your page title: " + title if title else "Shared links will have no title."))
    add("og_description", "pass" if og_d else "warn", "og:description set" if og_d else "No og:description",
        og_d or "Facebook, LinkedIn and messaging apps show a line of text under the title. Without og:description they guess or show nothing.")
    w, h = img.get("width"), img.get("height")
    if not img_url:
        add("og_image", "fail", "No share image (og:image)", "Shared links show as a plain text card, which gets far fewer clicks. Add a 1200 × 630 image.")
    elif img.get("status") != 200:
        add("og_image", "fail", "The share image doesn't load", f"{img_url} returned {img.get('status') or img.get('error') or 'no response'}. Platforms skip images they can't fetch.")
    elif img.get("too_big"):
        add("og_image", "fail", "The share image is over 5 MB", "X and LinkedIn reject images over 5 MB. Export it as a compressed JPG or WebP.")
    elif not w:
        fmt = img.get("type") or "unknown"
        add("og_image", "fail" if "svg" in fmt else "warn", "The share image can't be read" if "svg" not in fmt else "SVG share images aren't supported",
            "Use a JPG, PNG or WebP. Most platforms don't render SVG previews." if "svg" in fmt else f"We couldn't read the image ({fmt}). Use a standard JPG, PNG or WebP.")
    else:
        size_kb = round(img["bytes"] / 1024)
        if w < 200 or h < 200:
            add("og_image", "fail", f"Share image is too small ({w} × {h})", "Facebook needs at least 200 × 200, and small images show as a tiny thumbnail on X and LinkedIn. Use 1200 × 630.")
        elif w < 1200 or h < 600:
            add("og_image", "warn", f"Share image is smaller than recommended ({w} × {h}, {size_kb} KB)", "1200 × 630 looks sharp everywhere. Smaller images can look blurry or show as a small card.")
        else:
            add("og_image", "pass", f"Share image looks right ({w} × {h}, {size_kb} KB, {img.get('format', '')})", img_url)
        ratio = w / h if h else 0
        if ratio and not 1.6 <= ratio <= 2.1:
            add("ratio", "warn", f"Image shape is {ratio:.2f}:1, not 1.91:1", "X, LinkedIn and Facebook crop share images to about 1.91:1 (1200 × 630). Keep important text away from the edges, or resize.")
    if img.get("relative"):
        add("absolute", "warn", "og:image uses a relative address", "Use the full address (https://…). Some platforms can't resolve relative image paths.")
    if img_url and not tags.get("og:image:alt") and not tags.get("twitter:image:alt"):
        add("alt", "warn", "No alt text for the share image", "Add og:image:alt (and twitter:image:alt) so people using screen readers know what the image shows.")
    if tw_card in ("summary_large_image",):
        add("twitter_card", "pass", "twitter:card is summary_large_image", "X shows your image full width.")
    elif tw_card:
        add("twitter_card", "warn", f"twitter:card is {tw_card}", "summary_large_image shows the image full width on X and usually gets more clicks than the small summary card.")
    else:
        add("twitter_card", "warn", "No twitter:card tag", "Add <meta name=\"twitter:card\" content=\"summary_large_image\"> so X shows the large image card.")
    if not tags.get("og:url"):
        add("og_url", "warn", "No og:url", "og:url tells platforms the main address of the page, so shares of different versions of the link count together.")
    if not tags.get("og:type"):
        add("og_type", "warn", "No og:type", "Use website for most pages and article for blog posts.")

    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in fails] + \
             [{"level": "medium" if c["key"] in ("og_image", "og_description", "twitter_card", "og_title") else "low", "title": c["title"], "detail": c["detail"]} for c in warns]
    issues.append({"level": "info", "title": "Platforms cache link previews",
                   "detail": "After fixing your tags, refresh the cached preview with LinkedIn's Post Inspector and Facebook's Sharing Debugger before sharing again."})
    if fails:
        verdict, headline = "action_needed", "Your link previews need fixing"
    elif warns:
        verdict, headline = "improve", "Your link previews work, with things to improve"
    else:
        verdict, headline = "good", "Your link previews look great"
    order = {"fail": 0, "warn": 1, "pass": 2}
    return {"url": url, "final_url": r.url, "tags": tags, "image": {k: v for k, v in img.items() if k != "thumb"},
            "previews": previews, "checks": sorted(checks, key=lambda c: order[c["state"]]),
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Tool 12: Image Size Checker ---------------------------------------------------------------

IMAGES_MAX = 60
IMAGES_CONCURRENCY = 6
IMAGES_BUDGET_S = 28.0
IMG_HEAD_BYTES = 96 * 1024
IMG_MEASURE_BYTES = 4 * 1024 * 1024
_OLD_FORMATS = {"JPEG", "PNG", "GIF", "BMP", "TIFF"}


def _extract_images(doc: str, base: str) -> list[dict]:
    body = _strip_noise(doc)
    found, seen = [], set()

    def add(u, tag, kind):
        u = urljoin(base, u.strip()).split("#")[0]
        if not u.startswith(("http://", "https://")) or u in seen:
            return
        seen.add(u)
        wa = _attr(tag, "width") if tag else None
        found.append({"url": u, "kind": kind, "width_attr": int(wa) if wa and wa.isdigit() and not (tag and _attr(tag, "srcset")) else None,
                      "lazy": bool(tag) and (_attr(tag, "loading") or "").lower() == "lazy", "order": len(found)})

    for m in re.finditer(r"<img\b[^>]*>", body, re.I):
        tag = m.group(0)
        src = _attr(tag, "src") or ""
        if not src or src.startswith("data:"):
            src = _attr(tag, "data-src") or _attr(tag, "data-lazy-src") or ""
        srcset = _attr(tag, "srcset") or _attr(tag, "data-srcset") or ""
        if srcset:   # the largest candidate is what big screens download
            cands = []
            for part in srcset.split(","):
                bits = part.strip().split()
                if bits and not bits[0].startswith("data:"):
                    w = re.match(r"(\d+)w", bits[1]) if len(bits) > 1 else None
                    cands.append((int(w.group(1)) if w else 0, bits[0]))
            if cands:   # what a typical desktop screen downloads: the smallest candidate at least 1200px wide, else the largest
                wide = sorted(c for c in cands if c[0] >= 1200)
                src = wide[0][1] if wide else (max(cands)[1] if max(cands)[0] else (src or cands[0][1]))
        if src and not src.startswith("data:"):
            add(src, tag, "img")
    for m in re.finditer(r"<source\b[^>]*>", body, re.I):
        ss = _attr(m.group(0), "srcset") or ""
        first = ss.split(",")[0].strip().split(" ")[0] if ss else ""
        if first and not first.startswith("data:") and re.search(r"image/|\.(jpe?g|png|webp|avif|gif)", m.group(0) + first, re.I):
            add(first, m.group(0), "picture")
    for m in re.finditer(r"style\s*=\s*\"[^\"]*background(?:-image)?\s*:[^\"]*url\(\s*['\"]?([^'\")]+)", body, re.I):
        if not m.group(1).startswith("data:"):
            add(html.unescape(m.group(1)), "", "background")
    return found


async def check_images(raw_url: str) -> dict:
    """Every image a page loads (img, srcset's largest candidate, picture sources, inline backgrounds): file size, format,
    pixel dimensions vs the width it's shown at, and lazy loading. Flags heavy files and estimates what modern formats save."""
    url = normalize_page_url(raw_url)
    async with new_client() as client:
        page = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
        _fetch_page_or_raise(page, url)
        imgs = _extract_images(page.text, page.url)
        total_found = len(imgs)
        imgs = imgs[:IMAGES_MAX]
        sem = asyncio.Semaphore(IMAGES_CONCURRENCY)
        deadline = time.monotonic() + IMAGES_BUDGET_S

        async def probe(im: dict) -> dict:
            out = dict(im, bytes=None, format=None, width=None, height=None, status=None, note=None)
            async with sem:
                if time.monotonic() > deadline:
                    return dict(out, note="Not checked: time limit reached.")
                try:
                    hr = await safe_get(client, im["url"], 1, method="HEAD", user_agent=BROWSER_UA)
                    size = int(hr.headers.get("content-length", "0") or 0) if hr.status == 200 else 0
                    cap = IMG_HEAD_BYTES if size else IMG_MEASURE_BYTES
                    gr = await safe_get(client, im["url"], cap, user_agent=BROWSER_UA)
                except FetchBlocked as exc:
                    return dict(out, note=str(exc))
            out["status"] = gr.status
            if gr.status != 200:
                return dict(out, note=f"HTTP {gr.status}" if gr.status else (gr.error or "No response."))
            ctype = gr.headers.get("content-type", "").split(";")[0].lower()
            if size == 0 and not gr.truncated:
                size = len(gr.body)
            out["bytes"] = size or None
            out["over_measure"] = size == 0 and gr.truncated
            if "svg" in ctype or im["url"].lower().split("?")[0].endswith(".svg"):
                out["format"] = "SVG"
                return out
            from PIL import Image
            Image.MAX_IMAGE_PIXELS = 40_000_000
            try:
                pim = Image.open(io.BytesIO(gr.body))
                out.update(format=(pim.format or "").upper(), width=pim.size[0], height=pim.size[1])
            except Exception:
                out["format"] = (ctype.split("/")[-1] or "").upper() or None
            return out

        results = await asyncio.gather(*[probe(i) for i in imgs])

    flagged, saving = 0, 0
    for x in results:
        flags = []
        kb = round(x["bytes"] / 1024) if x["bytes"] else (4096 if x.get("over_measure") else None)
        x["kb"] = kb
        if kb is not None:
            if x.get("over_measure"):
                flags.append(("high", "Oversized: over 4 MB", "Compress and resize it. Most images on a page should be under 200 KB."))
            elif kb > 500:
                flags.append(("high", f"Oversized: {kb:,} KB", "Compress and resize it. Most images on a page should be under 200 KB."))
            elif kb > 200:
                flags.append(("medium", f"Heavy: {kb:,} KB", "Compress it (quality 75–85 is usually indistinguishable)."))
            if x["format"] in _OLD_FORMATS and kb > 100:
                if x["format"] == "GIF" and kb > 500:
                    flags.append(("medium", "Large GIF", "Animated GIFs are huge. A short MP4 or WebM video is usually 5–10 times smaller."))
                else:
                    est = round(kb * .3)
                    saving += est
                    flags.append(("low", f"{x['format']} could be WebP or AVIF (about {est} KB smaller)",
                                  "Google measured WebP files as 25–34% smaller than comparable JPEGs."))
        if x["width"] and x["width_attr"] and x["width"] > 2 * x["width_attr"] and x["width"] > 800:
            flags.append(("medium", f"Served at {x['width']}px, shown at {x['width_attr']}px",
                          "The browser downloads pixels it throws away. Resize it, or use srcset so phones get a smaller file."))
        if x["lazy"] and x["order"] == 0:
            flags.append(("medium", "First image is lazy-loaded", "If this is the main image at the top of the page, loading=\"lazy\" delays it and slows Largest Contentful Paint. Remove lazy from images above the fold."))
        x["flags"] = [{"level": a, "title": b, "detail": c} for a, b, c in flags]
        x["state"] = "unchecked" if x["note"] else ("heavy" if any(a in ("high", "medium") for a, _, _ in flags) else ("tip" if flags else "ok"))
        flagged += x["state"] == "heavy"
    total_kb = sum(x["kb"] or 0 for x in results)
    big = [x for x in results if (x["kb"] or 0) > 500]
    issues = []
    if big:
        issues.append({"level": "high", "title": f"{len(big)} image{'s' if len(big) != 1 else ''} over 500 KB",
                       "detail": "Every visitor downloads these, phones on mobile data included. Compress them before uploading."})
    if total_kb > 2048:
        issues.append({"level": "high", "title": f"{total_kb / 1024:.1f} MB of images on one page",
                       "detail": "Heavy pages load slowly on phones and use visitors' data. Aim for well under 1–2 MB of images per page."})
    mid = [x for x in results if 200 < (x["kb"] or 0) <= 500]
    if mid:
        issues.append({"level": "medium", "title": f"{len(mid)} image{'s' if len(mid) != 1 else ''} between 200 and 500 KB", "detail": "Worth compressing."})
    if saving:
        issues.append({"level": "low", "title": f"About {saving:,} KB to save by converting to WebP or AVIF",
                       "detail": "A rough estimate from Google's published WebP comparison. Your CMS or a free converter can do it in bulk."})
    if any(f["title"] == "First image is lazy-loaded" for x in results for f in x["flags"]):
        issues.append({"level": "medium", "title": "The first image is lazy-loaded", "detail": "Remove loading=\"lazy\" from the main image at the top of the page."})
    if not total_found:
        issues.append({"level": "info", "title": "No images found in the page's HTML",
                       "detail": "If images are added by JavaScript, we can't see them here."})
    if total_found > IMAGES_MAX:
        issues.append({"level": "info", "title": f"Checked the first {IMAGES_MAX} of {total_found} images", "detail": "Very long pages are capped."})
    if big or total_kb > 2048:
        verdict, headline = "action_needed", f"{total_kb / 1024:.1f} MB of images: some need compressing" if total_kb >= 1024 else "Some images are far too large"
    elif flagged:
        verdict, headline = "improve", "Your images are mostly fine, a few are heavy"
    else:
        verdict, headline = "good", "Your images are a healthy size"
    order = {"heavy": 0, "tip": 1, "unchecked": 2, "ok": 3}
    return {"url": url, "final_url": page.url, "total_found": total_found, "checked": len(results), "total_kb": total_kb,
            "saving_kb": saving, "images": sorted(results, key=lambda x: (order[x["state"]], -(x["kb"] or 0))),
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Tool 13: Sitemap Checker ---------------------------------------------------------------

SITEMAP_BYTES = 10 * 1024 * 1024
SITEMAP_CHILDREN = 5
SITEMAP_EXTRA = 4            # 2026-10-22: also read up to 4 more sitemaps listed in robots.txt (was: only the first one found)
SITEMAP_SAMPLE = 20
SITEMAP_BUDGET_S = 30.0
_W3C_DATE = re.compile(r"^\d{4}(-\d{2}(-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:\d{2}))?)?)?$")


def _sitemap_text(r: FetchResult) -> tuple[str, bool]:
    """Body as text, gunzipped (bomb-capped) when it's a .gz sitemap. Returns (text, too_big)."""
    body = r.body
    if body[:2] == b"\x1f\x8b":
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(body, SITEMAP_BYTES + 1)
        return out[:SITEMAP_BYTES].decode("utf-8", errors="replace"), len(out) > SITEMAP_BYTES or r.truncated
    return r.text, r.truncated


def _parse_sitemap(xml: str) -> dict:
    kind = "index" if re.search(r"<sitemapindex\b", xml, re.I) else "urlset" if re.search(r"<urlset\b", xml, re.I) else None
    entries = []
    for block in re.findall(r"<(?:url|sitemap)\b[^>]*>(.*?)</(?:url|sitemap)>", xml, re.I | re.S):
        loc = re.search(r"<loc>\s*(.*?)\s*</loc>", block, re.I | re.S)
        lm = re.search(r"<lastmod>\s*(.*?)\s*</lastmod>", block, re.I | re.S)
        entries.append({"loc": html.unescape(re.sub(r"<!\[CDATA\[|\]\]>", "", loc.group(1))).strip() if loc else "",
                        "lastmod": lm.group(1).strip() if lm else None,
                        "extra": bool(re.search(r"<(changefreq|priority)>", block, re.I))})
    media = bool(re.search(r"<(image:image|video:video)\b", xml[:200000], re.I))   # image/video sitemaps repeat a page once per file
    for e in entries:
        e["media"] = media
    return {"kind": kind, "entries": entries, "ns": "sitemaps.org/schemas/sitemap" in xml[:2000], "media": media}


async def check_sitemap(raw_url: str) -> dict:
    """Finds the XML sitemap (given address, robots.txt Sitemap: lines, or common locations), validates it (format,
    50,000-URL / 50 MB limits, address host and protocol, lastmod), reads up to 5 child sitemaps of an index, and
    spot-checks up to 20 listed pages for errors, redirects and noindex."""
    raw = (raw_url or "").strip()
    page = normalize_page_url(raw)
    p = urlparse(page)
    site = f"{p.scheme}://{p.netloc}"
    given = page if re.search(r"\.xml(\.gz)?$|sitemap", p.path or "", re.I) else None
    deadline = time.monotonic() + SITEMAP_BUDGET_S
    async with new_client() as client:
        robots_r = await safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES)
        robots, _parsed = _read_robots(robots_r, site)
        in_robots = robots.get("sitemaps") or []
        candidates = ([given] if given else []) + in_robots[:3] + [site + "/sitemap.xml", site + "/sitemap_index.xml", site + "/wp-sitemap.xml"]
        sm_url, sm_r, source = None, None, None
        for c in dict.fromkeys(candidates):
            try:
                r = await safe_get(client, c, SITEMAP_BYTES)
            except FetchBlocked:
                continue
            if r.status == 200 and r.body:
                txt, _ = _sitemap_text(r)
                if re.search(r"<(urlset|sitemapindex)\b", txt[:5000], re.I):
                    sm_url, sm_r = c, r
                    source = "given" if c == given else "robots" if c in in_robots else "guessed"
                    break
            if given and c == given:   # the address they typed didn't work: say so instead of silently guessing
                source = "given_failed"
        if not sm_url:
            if given:
                raise FetchBlocked(f"{given} isn't a readable XML sitemap. Check the address, or enter just your domain and we'll look for it.")
            return {"url": page, "sitemap_url": None, "found": False, "in_robots": False, "files": [], "checks": [], "sample": [],
                    "summary": {"verdict": "action_needed", "headline": "We couldn't find a sitemap",
                                "issues": [{"level": "high", "title": "No sitemap found",
                                            "detail": "We looked in robots.txt and at /sitemap.xml, /sitemap_index.xml and /wp-sitemap.xml. Most CMSs can generate one; "
                                                      "add it, list it in robots.txt with a Sitemap: line and submit it in Google Search Console."}]}}
        txt, too_big = _sitemap_text(sm_r)
        top = _parse_sitemap(txt)
        files = [{"url": sm_url, "kind": top["kind"], "count": len(top["entries"]), "too_big": too_big, "ns": top["ns"]}]
        urls: list[dict] = []
        if top["kind"] == "index":
            for child in top["entries"][:SITEMAP_CHILDREN]:
                if time.monotonic() > deadline or not child["loc"]:
                    break
                try:
                    cr = await safe_get(client, urljoin(sm_url, child["loc"]), SITEMAP_BYTES)
                except FetchBlocked as exc:
                    files.append({"url": child["loc"], "kind": None, "count": 0, "error": str(exc)})
                    continue
                if cr.status != 200:
                    files.append({"url": child["loc"], "kind": None, "count": 0, "error": f"HTTP {cr.status or cr.error}"})
                    continue
                ct, cbig = _sitemap_text(cr)
                cp = _parse_sitemap(ct)
                files.append({"url": child["loc"], "kind": cp["kind"], "count": len(cp["entries"]), "too_big": cbig, "ns": cp["ns"], "media": cp["media"]})
                urls.extend(cp["entries"])
        else:
            urls = list(top["entries"])

        # 2026-10-22 (user: "fix it"): a site can list several sitemaps in robots.txt (cmoowls.com lists the main one and a
        # careers/jobs one); read the others too, unless the visitor typed one specific sitemap address.
        extras = [s for s in in_robots if source != "given" and not _same_url(s, sm_url)][:SITEMAP_EXTRA]
        for ex in extras:
            if time.monotonic() > deadline:
                break
            try:
                er = await safe_get(client, ex, SITEMAP_BYTES)
            except FetchBlocked as exc:
                files.append({"url": ex, "kind": None, "count": 0, "error": str(exc)})
                continue
            if er.status != 200:
                files.append({"url": ex, "kind": None, "count": 0, "error": f"HTTP {er.status or er.error}"})
                continue
            et, ebig = _sitemap_text(er)
            ep = _parse_sitemap(et)
            files.append({"url": ex, "kind": ep["kind"], "count": len(ep["entries"]), "too_big": ebig, "ns": ep["ns"], "media": ep.get("media")})
            if ep["kind"] == "index":
                for child in ep["entries"][:SITEMAP_CHILDREN]:
                    if time.monotonic() > deadline or not child["loc"]:
                        break
                    try:
                        cr = await safe_get(client, urljoin(ex, child["loc"]), SITEMAP_BYTES)
                    except FetchBlocked as exc:
                        files.append({"url": child["loc"], "kind": None, "count": 0, "error": str(exc)})
                        continue
                    if cr.status != 200:
                        files.append({"url": child["loc"], "kind": None, "count": 0, "error": f"HTTP {cr.status or cr.error}"})
                        continue
                    ct, cbig = _sitemap_text(cr)
                    cp = _parse_sitemap(ct)
                    files.append({"url": child["loc"], "kind": cp["kind"], "count": len(cp["entries"]), "too_big": cbig, "ns": cp["ns"], "media": cp["media"]})
                    urls.extend(cp["entries"])
            else:
                urls = urls + ep["entries"]

        # spot-check pages spread across the list
        locs = [u["loc"] for u in urls if u["loc"].startswith(("http://", "https://"))]
        step = max(1, len(locs) // SITEMAP_SAMPLE)
        sample_urls = list(dict.fromkeys(locs[::step]))[:SITEMAP_SAMPLE]
        sem = asyncio.Semaphore(6)

        async def probe(u: str) -> dict:
            async with sem:
                if time.monotonic() > deadline:
                    return {"url": u, "state": "unchecked", "status": None, "detail": "Not checked: time limit reached."}
                try:
                    r = await safe_get(client, u, 96 * 1024, follow_redirects=False, user_agent=BROWSER_UA)
                except FetchBlocked as exc:
                    return {"url": u, "state": "error", "status": None, "detail": str(exc)}
            if r.status is None:
                return {"url": u, "state": "unchecked", "status": None, "detail": r.error or "No response."}
            if r.status in (301, 302, 303, 307, 308):
                return {"url": u, "state": "redirect", "status": r.status, "detail": "Redirects to " + urljoin(u, r.headers.get("location", ""))}
            if r.status in _UNVERIFIABLE:
                return {"url": u, "state": "unchecked", "status": r.status, "detail": f"HTTP {r.status}: the site refused our check."}
            if r.status >= 400:
                return {"url": u, "state": "error", "status": r.status, "detail": f"HTTP {r.status}"}
            noidx = _x_robots_noindex(r.headers.get("x-robots-tag", "")) or next((m["content"] for m in _robots_meta_values(r.text) if _NOINDEX_RE.search(m["content"])), None)
            if noidx:
                return {"url": u, "state": "noindex", "status": r.status, "detail": f"Says noindex ({noidx})"}
            canon = _canonical(r.text, u)
            if canon and not _same_url(canon, u):
                return {"url": u, "state": "canonical", "status": r.status, "detail": f"Canonical points to {canon}"}
            return {"url": u, "state": "ok", "status": r.status, "detail": "HTTP 200"}

        sample = await asyncio.gather(*[probe(u) for u in sample_urls])

    checks = []
    def add(key, state, t, d):
        checks.append({"key": key, "state": state, "title": t, "detail": d})

    total = len({u["loc"] for u in urls})
    add("found", "pass", f"Sitemap found ({'listed in robots.txt' if source == 'robots' else 'the address you entered' if source == 'given' else 'at a standard address'})", sm_url)
    if not in_robots:
        add("robots", "warn", "robots.txt doesn't list your sitemap", f"Add the line \"Sitemap: {sm_url}\" to robots.txt so every search engine can find it.")
    if not top["ns"]:
        add("format", "warn", "Missing the sitemap namespace", "The root tag should declare xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\".")
    listed_read = [f for f in files if f["url"] == sm_url or f["url"] in extras]
    if len(in_robots) > 1 and source != "given":
        more = len(in_robots) - 1 - len(extras)
        add("multi", "pass", f"{len(in_robots)} sitemaps listed in robots.txt",
            f"We read {len(listed_read)} of them" + (f" (the first {1 + len(extras)})" if more > 0 else "") + ": "
            + ", ".join(f"{f['url']} ({f['count']:,} {'sitemaps' if f.get('kind') == 'index' else 'addresses'})" for f in listed_read if not f.get("error")) + ".")
    if top["kind"] == "index":
        add("index", "pass", f"Sitemap index with {len(top['entries'])} sitemap file{'s' if len(top['entries']) != 1 else ''}",
            f"We read {len(files) - 1} of them" + (f" (the first {SITEMAP_CHILDREN})" if len(top["entries"]) > SITEMAP_CHILDREN else "") + ".")
    bad_files = [f for f in files if f.get("error")]
    if bad_files:
        add("children", "fail", f"{len(bad_files)} sitemap file{'s' if len(bad_files) != 1 else ''} {'doesn' if len(bad_files) == 1 else 'don'}'t load", "; ".join(f"{f['url']} ({f['error']})" for f in bad_files[:3]))
    over = [f for f in files if f["count"] > 50000 or f.get("too_big")]
    if over:
        add("limits", "fail", "A sitemap file is over the limit", "Each sitemap file can list at most 50,000 URLs and be at most 50 MB uncompressed. Split it and use a sitemap index.")
    if total == 0:
        add("urls", "fail", "The sitemap lists no pages", "It's valid XML but empty. Check your sitemap plugin or generator settings.")
    else:
        media_n = sum(1 for f in files if f.get("media"))
        add("urls", "pass", f"{total:,} unique page address{'es' if total != 1 else ''} read",
            f"Including {media_n} image or video sitemap{'s' if media_n != 1 else ''}, which list a page once per image or video." if media_n else "")
    hosts = defaultdict(int)
    rel, http_mix, frag = 0, 0, 0
    for u in urls:
        loc = u["loc"]
        if not loc.startswith(("http://", "https://")):
            rel += 1
            continue
        up = urlparse(loc)
        hosts[(up.hostname or "").lower()] += 1
        http_mix += up.scheme != p.scheme
        frag += "#" in loc
    main_host = (urlparse(sm_url).hostname or "").lower()
    foreign = sum(n for h, n in hosts.items() if h != main_host)
    if rel:
        add("relative", "fail", f"{rel} address{'es' if rel != 1 else ''} aren't full URLs", "Every <loc> must be a full address starting with https://.")
    if foreign:
        add("host", "warn", f"{foreign} address{'es' if foreign != 1 else ''} on a different host than the sitemap",
            f"The sitemap is on {main_host}. URLs on other hosts (including www vs non-www) are ignored unless that host is verified. Use your main domain everywhere.")
    if http_mix:
        add("protocol", "warn", f"{http_mix} address{'es' if http_mix != 1 else ''} use a different protocol (http vs https)", "List only the final https addresses your pages load at.")
    plain = [u["loc"] for u in urls if not u.get("media")]
    dups = len(plain) - len(set(plain))
    if dups:
        add("dups", "warn", f"{dups} duplicate address{'es' if dups != 1 else ''}", "Each page should be listed once.")
    if frag:
        add("fragment", "warn", f"{frag} address{'es' if frag != 1 else ''} contain #", "Search engines ignore everything after #. List the page address only.")
    if total:
        first_lm: dict = {}
        for u in urls:   # one lastmod per unique page (image/video sitemaps repeat pages)
            if u["loc"] not in first_lm or (first_lm[u["loc"]] is None and u["lastmod"]):
                first_lm[u["loc"]] = u["lastmod"]
        lms = [v for v in first_lm.values() if v]
        bad_lm = [x for x in lms if not _W3C_DATE.match(x)]
        future = [x for x in lms if _W3C_DATE.match(x) and x[:10] > time.strftime("%Y-%m-%d", time.gmtime(time.time() + 86400))]
        if not lms:
            add("lastmod", "warn", "No lastmod dates", "Google uses an accurate <lastmod> to decide what to recrawl. Add it if your CMS knows when pages changed.")
        elif bad_lm:
            add("lastmod", "warn", f"{len(bad_lm)} lastmod value{'s' if len(bad_lm) != 1 else ''} aren't valid dates", f"Use the W3C format, e.g. 2026-10-10 or 2026-10-10T09:30:00+00:00. Example found: {bad_lm[0][:40]}")
        elif future:
            add("lastmod", "warn", f"{len(future)} lastmod date{'s' if len(future) != 1 else ''} in the future", "Google ignores lastmod values it can't trust. Set them to when the page really changed.")
        elif len(lms) > 20 and len(set(x[:10] for x in lms)) == 1:
            add("lastmod", "warn", "Every page has the same lastmod date", "That usually means the date is set to 'now' for every page, so Google learns to ignore it. Use each page's real change date.")
        else:
            add("lastmod", "pass", f"lastmod dates present on {len(lms):,} of {total:,} pages", "")
        if any(u["extra"] for u in urls):
            add("priority", "pass", "changefreq / priority found (harmless)", "Google says it ignores changefreq and priority. They don't hurt, but they don't help either.")
    errs = [s for s in sample if s["state"] == "error"]
    redirs = [s for s in sample if s["state"] == "redirect"]
    noidx = [s for s in sample if s["state"] == "noindex"]
    canon = [s for s in sample if s["state"] == "canonical"]
    if sample:
        if errs:
            add("sample_err", "fail", f"{len(errs)} of {len(sample)} sampled pages return errors", "A sitemap should only list pages that load. Remove or fix: " + ", ".join(s["url"] for s in errs[:3]))
        if redirs:
            add("sample_redir", "warn", f"{len(redirs)} of {len(sample)} sampled pages redirect", "List the final addresses, not ones that redirect: " + ", ".join(s["url"] for s in redirs[:3]))
        if noidx:
            add("sample_noindex", "fail", f"{len(noidx)} of {len(sample)} sampled pages say noindex", "You're asking Google to crawl pages you've told it not to index. Remove them from the sitemap or remove the noindex.")
        if canon:
            add("sample_canon", "warn", f"{len(canon)} of {len(sample)} sampled pages canonicalise elsewhere", "List the canonical version of each page only.")
        if not (errs or redirs or noidx or canon):
            add("sample_ok", "pass", f"All {len(sample)} sampled pages load cleanly", "No errors, redirects, noindex or off-page canonicals in the sample.")

    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in fails] + \
             [{"level": "medium" if c["key"] in ("robots", "host", "sample_redir", "protocol") else "low", "title": c["title"], "detail": c["detail"]} for c in warns]
    issues.append({"level": "info", "title": "We spot-check a sample",
                   "detail": f"We checked {len(sample)} pages spread across the sitemap. Google Search Console's Sitemaps and Pages reports show every URL."})
    if fails:
        verdict, headline = "action_needed", "Your sitemap has problems to fix"
    elif warns:
        verdict, headline = "improve", "Your sitemap works, with things to tidy"
    else:
        verdict, headline = "good", "Your sitemap looks healthy"
    order = {"fail": 0, "warn": 1, "pass": 2}
    return {"url": page, "sitemap_url": sm_url, "found": True, "in_robots": bool(in_robots), "source": source, "kind": top["kind"],
            "total_urls": total, "files": files, "sample": sample, "checks": sorted(checks, key=lambda c: order[c["state"]]),
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# =============================================================================================
# Link Safety Checker, SEO Page Checker,
# Security Headers & Email Record Checker (the UTM Builder runs entirely in the browser). Same guardrails: every
# web request goes through safe_get, the TLS check connects only to an address _resolve_public validated, DNS
# lookups are read-only TXT/MX queries with short timeouts. No paid APIs, no LLM calls, nothing stored.
# Deliberately NOT used: Google Safe Browsing (its free API is non-commercial only) — the page says so.
# =============================================================================================

import ssl
from datetime import datetime, timezone

try:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver
except Exception:  # pragma: no cover - dnspython is installed on the server (2.8.0)
    dns = None

# A small public-suffix table: enough to find the registrable domain for the common multi-part endings and the
# free-hosting platforms phishing pages like to sit on. (The full Public Suffix List isn't vendored.)
_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz",
    "org.nz", "co.za", "co.in", "net.in", "org.in", "co.jp", "or.jp", "ne.jp", "ac.jp", "com.br", "net.br", "org.br", "com.mx",
    "com.pk", "org.pk", "com.sg", "com.my", "com.ph", "com.tr", "com.cn", "com.hk", "com.tw", "co.kr", "com.ar", "com.co",
    "com.ng", "com.eg", "com.sa", "com.bd", "co.id", "co.th", "com.vn", "com.ua", "co.il", "com.pe", "com.ec",
    "github.io", "herokuapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "web.app", "firebaseapp.com",
    "blogspot.com", "wordpress.com", "wixsite.com", "myshopify.com", "azurewebsites.net", "cloudfront.net", "glitch.me",
    "onrender.com", "repl.co", "weebly.com", "webflow.io", "framer.website", "carrd.co", "000webhostapp.com", "ngrok.io",
    "ngrok-free.app", "sharepoint.com", "appspot.com", "s3.amazonaws.com", "r2.dev", "surge.sh",
}


def registered_domain(host: str) -> str:
    host = (host or "").lower().strip(".")
    parts = host.split(".")
    if len(parts) <= 2 or _is_ip_literal(host):
        return host
    for n in (3, 2):
        if ".".join(parts[-n:]) in _MULTI_SUFFIXES and len(parts) > n:
            return ".".join(parts[-(n + 1):])
    return ".".join(parts[-2:])


# Brands phishing most often imitates, with the registrable domains they really use.
_BRANDS = {
    "paypal": {"paypal.com", "paypal.me", "paypalobjects.com"}, "google": {"google.com", "googleusercontent.com", "goo.gl", "g.co", "youtube.com", "gmail.com"},
    "apple": {"apple.com", "icloud.com", "apple.co"}, "icloud": {"icloud.com", "apple.com"}, "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "sharepoint.com", "aka.ms"},
    "outlook": {"outlook.com", "live.com", "microsoft.com", "office.com"}, "office365": {"office.com", "microsoft.com", "microsoftonline.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.ca", "amazon.com.au", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amzn.to", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me", "meta.com"}, "instagram": {"instagram.com"}, "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"}, "linkedin": {"linkedin.com", "lnkd.in"}, "dropbox": {"dropbox.com"}, "docusign": {"docusign.com", "docusign.net"},
    "chase": {"chase.com"}, "wellsfargo": {"wellsfargo.com"}, "bankofamerica": {"bankofamerica.com"}, "coinbase": {"coinbase.com"},
    "binance": {"binance.com"}, "metamask": {"metamask.io"}, "ebay": {"ebay.com", "ebay.co.uk"}, "fedex": {"fedex.com"}, "dhl": {"dhl.com"},
    "usps": {"usps.com"}, "adobe": {"adobe.com"}, "yahoo": {"yahoo.com"}, "steam": {"steampowered.com", "steamcommunity.com"},
    "roblox": {"roblox.com"}, "tiktok": {"tiktok.com"}, "twitter": {"twitter.com", "x.com", "t.co"}, "shopify": {"shopify.com", "myshopify.com"},
    "stripe": {"stripe.com"}, "venmo": {"venmo.com"}, "cashapp": {"cash.app"}, "zoom": {"zoom.us"},
}
_SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc",
               "rb.gy", "t.ly", "s.id", "lnkd.in", "amzn.to", "bl.ink", "short.io", "bitly.com", "v.gd", "qr.ae", "trib.al"}
_HOMOGLYPH = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"})
_TYPO_BRANDS = {"paypal", "google", "amazon", "microsoft", "facebook", "instagram", "whatsapp", "netflix", "linkedin", "dropbox",
                 "docusign", "wellsfargo", "bankofamerica", "coinbase", "binance", "metamask", "outlook", "icloud", "roblox", "tiktok",
                 "twitter", "office365", "shopify"}   # distinctive names only: "steam"/"stream", "apple"/"apply" are real words
_PHISH_WORDS = {"login", "signin", "secure", "security", "account", "accounts", "support", "verify", "verification", "billing", "help",
                "update", "service", "services", "pay", "payment", "online", "app", "id", "auth", "wallet", "refund", "alert", "team", "center"}
_DOWNLOAD_EXT = re.compile(r"\.(exe|msi|apk|dmg|pkg|zip|rar|7z|scr|bat|cmd|js|vbs|jar|iso)$", re.I)


def _edit1(a: str, b: str) -> bool:
    """True when a and b differ by exactly one insertion, deletion, substitution or adjacent swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        return len(diff) == 1 or (len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]])
    s, l = (a, b) if len(a) < len(b) else (b, a)
    i = 0
    while i < len(s) and s[i] == l[i]:
        i += 1
    return s[i:] == l[i + 1:]


def _brand_signals(host: str) -> list[dict]:
    """Look-alike and brand-impersonation checks on a hostname (no network)."""
    out: list[dict] = []
    reg = registered_domain(host)
    label = reg.split(".")[0]
    sub = host[: -len(reg)].rstrip(".") if host != reg else ""
    tokens = re.split(r"[.\-_]", host)
    norm_label = label.translate(_HOMOGLYPH).replace("rn", "m").replace("vv", "w").replace("-", "")
    for brand, official in _BRANDS.items():
        if reg in official or (label == brand):
            continue
        if brand in sub.replace("-", "").split(".") or any(t == brand for t in re.split(r"[.\-_]", sub) if t):
            out.append({"level": "high", "key": "brand_sub", "title": f"\"{brand}\" appears before the real domain",
                        "detail": f"The address starts with {brand} but the site is actually {reg}. This is a common trick: the real owner of a link is the part just before the ending (.com, .co.uk…), not the start."})
            break
        if norm_label == brand and label != brand:
            out.append({"level": "high", "key": "lookalike", "title": f"{reg} imitates {brand}",
                        "detail": f"\"{label}\" swaps letters for look-alike characters (such as 0 for o or 1 for l) to read as \"{brand}\". {brand.capitalize()}'s real sites are {', '.join(sorted(official)[:3])}."})
            break
        if brand in _TYPO_BRANDS and _edit1(label, brand):
            out.append({"level": "medium", "key": "typo", "title": f"{reg} is one letter away from {brand}",
                        "detail": f"Typo domains catch people who mistype or skim. {brand.capitalize()}'s real sites are {', '.join(sorted(official)[:3])}."})
            break
        ltoks = [x for x in re.split(r"[-_0-9]+", label) if x]
        if any(t == brand or (t.startswith(brand) and t[len(brand):] in _PHISH_WORDS) or (t.endswith(brand) and t[:-len(brand)] in _PHISH_WORDS) for t in ltoks):
            out.append({"level": "medium", "key": "brand_in_name", "title": f"The domain uses the name \"{brand}\" but isn't {brand}'s",
                        "detail": f"{reg} isn't one of {brand.capitalize()}'s domains ({', '.join(sorted(official)[:3])}). It may be a reseller, a fan site or an imitation, so don't sign in or pay there unless you're sure."})
            break
    if any(t.startswith("xn--") for t in host.split(".")):
        try:
            shown = host.encode("ascii").decode("idna")
        except Exception:
            shown = host
        out.append({"level": "medium", "key": "idn", "title": "The address uses international characters",
                    "detail": f"It displays as {shown}. Letters from other alphabets can look identical to Latin ones (Cyrillic а vs Latin a), so check the domain carefully."})
    if len([p for p in sub.split(".") if p]) >= 3:
        out.append({"level": "low", "key": "deep_sub", "title": "Unusually many subdomains",
                    "detail": f"Long chains like {host[:60]} are sometimes used to push the real domain ({reg}) off the edge of a phone screen."})
    return out


def _cert_info(host: str) -> dict:
    """TLS certificate of host:443, connecting only to an address _resolve_public approved (SNI = the real hostname)."""
    ip = _resolve_public(host, 443)
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": exc.verify_message or str(exc)}
    except (OSError, ssl.SSLError) as exc:
        return {"valid": False, "error": f"No secure connection ({type(exc).__name__})."}

    def when(k):
        try:
            return datetime.strptime(cert[k], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        except Exception:
            return None
    nb, na = when("notBefore"), when("notAfter")
    issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
    now = datetime.now(timezone.utc)
    return {"valid": True, "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "days_left": (na - now).days if na else None, "age_days": (now - nb).days if nb else None,
            "expires": na.date().isoformat() if na else None}


async def _domain_age(client: httpx.AsyncClient, domain: str) -> dict:
    """Registration date from RDAP (the registries' free, public successor to WHOIS) via the rdap.org bootstrap."""
    try:
        r = await safe_get(client, f"https://rdap.org/domain/{domain}", 256 * 1024)
    except FetchBlocked:
        return {"known": False}
    if r.status != 200:
        return {"known": False}
    try:
        data = json.loads(r.text)
    except ValueError:
        return {"known": False}
    for ev in data.get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            try:
                d = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
            except ValueError:
                continue
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return {"known": True, "registered": d.date().isoformat(), "age_days": (datetime.now(timezone.utc) - d).days}
    return {"known": False}


_PASSWORD_RE = re.compile(r"<input\b[^>]*type\s*=\s*[\"']?password", re.I)


async def check_link_safety(raw_url: str) -> dict:
    """Tool 14: Link Safety Checker. Follows the link to where it really ends up and checks the warning signs people use to
    judge a link by hand: look-alike and brand-imitation domains, hidden destinations behind shorteners and redirects, a missing
    or invalid certificate, a brand-new domain, password forms on imitation pages, downloads. It does NOT consult malware
    blocklists, so 'no warning signs' is never presented as 'safe'."""
    raw = (raw_url or "").strip()
    at_trick = bool(re.match(r"^(https?://)?[^/\s]*@", raw, re.I))
    if at_trick:
        raw = re.sub(r"^(https?://)?[^/\s]*@", lambda m: m.group(1) or "", raw, count=1)
    url = normalize_page_url(raw)
    start_host = (urlparse(url).hostname or "").lower()
    async with new_client() as client:
        trace = await trace_redirects(client, url, max_hops=10, user_agent=BROWSER_UA)
        final = trace["final_url"]
        fp = urlparse(final)
        final_host = (fp.hostname or "").lower()
        page = None
        if trace["final_status"] and trace["final_status"] < 400:
            try:
                page = await safe_get(client, final, 512 * 1024, user_agent=BROWSER_UA)
            except FetchBlocked:
                page = None
        doms = list(dict.fromkeys([registered_domain(final_host), registered_domain(start_host)]))
        ages = await asyncio.gather(*[_domain_age(client, d) for d in doms if d and not _is_ip_literal(d)])
    if trace["final_status"] is None and not trace["hops"]:
        raise FetchBlocked(f"We couldn't reach {url}. {trace['error'] or ''}".strip())
    age_by = dict(zip([d for d in doms if d and not _is_ip_literal(d)], ages))
    cert = await asyncio.to_thread(_cert_info, final_host) if fp.scheme == "https" and not _is_ip_literal(final_host) else None

    signals: list[dict] = []
    def add(level, key, title, detail):
        signals.append({"level": level, "key": key, "title": title, "detail": detail})

    if at_trick:
        add("high", "at", "The link hides its real address behind an @", "Everything before the @ in a web address is ignored. A link like https://paypal.com@other.site goes to other.site.")
    if _is_ip_literal(start_host) or _is_ip_literal(final_host):
        add("medium", "ip", "The link uses a bare IP address instead of a domain", "Real businesses almost always use a domain name. A raw IP address hides who runs the site.")
    seen_brand = set()
    for h in dict.fromkeys([start_host, final_host]):
        for s in _brand_signals(h):
            if s["key"] + s["title"] not in seen_brand:
                seen_brand.add(s["key"] + s["title"])
                add(s["level"], s["key"], s["title"], s["detail"])
    if registered_domain(start_host) in _SHORTENERS or start_host in _SHORTENERS:
        add("info", "shortener", f"Shortened link ({start_host})", f"Short links hide where they go. This one leads to {final_host}.")
    hops = trace["hops"]
    redirects = max(0, len(hops) - 1)
    hop_domains = list(dict.fromkeys(registered_domain(urlparse(h["url"]).hostname or "") for h in hops))
    if trace.get("loop"):
        add("medium", "loop", "The link redirects in a loop", "It never reaches a page.")
    elif redirects >= 4:
        add("medium", "redirects", f"{redirects} redirects before the page", "Long redirect chains through several domains are a common way to hide a final destination from filters.")
    if len(hop_domains) >= 3:
        add("medium", "hop_domains", f"The link passes through {len(hop_domains)} different sites", " → ".join(hop_domains[:6]))
    elif registered_domain(start_host) != registered_domain(final_host) and registered_domain(start_host) not in _SHORTENERS:
        add("info", "cross", f"The link ends on a different site: {registered_domain(final_host)}", f"It starts on {registered_domain(start_host)} and redirects to {final_host}. Make sure that's where you expected to go.")
    if fp.scheme != "https":
        add("medium", "http", "The page isn't encrypted (http, not https)", "Anything typed into this page, such as a password or card number, travels without encryption.")
    elif cert and not cert["valid"]:
        add("high", "cert", "The site's security certificate isn't valid", f"Browsers will show a warning. ({cert.get('error')}) Don't enter anything on this site.")
    for d, a in age_by.items():
        if a.get("known") and a["age_days"] < 30:
            add("high", "new_domain", f"{d} was registered {a['age_days']} day{'s' if a['age_days'] != 1 else ''} ago", "Most phishing sites use domains a few days or weeks old. A brand-new domain asking for logins or payment is a serious red flag.")
        elif a.get("known") and a["age_days"] < 180:
            mo = max(1, round(a['age_days'] / 30))
            add("medium", "young_domain", f"{d} is only about {mo} month{'s' if mo != 1 else ''} old", f"Registered {a['registered']}. Young domains aren't bad on their own, but be careful if the site claims to be a long-established brand.")
    st = trace["final_status"]
    if st and st >= 400:
        add("info", "status", f"The page returns HTTP {st}", "The link is broken or the site refused our visit.")
    doc = page.text if page and page.status and page.status < 400 else ""
    ctype = (page.headers.get("content-type", "") if page else "").lower()
    if _DOWNLOAD_EXT.search(fp.path) or (page and not _looks_like_html(doc) and any(x in ctype for x in ("octet-stream", "x-msdownload", "android.package", "zip"))):
        add("high", "download", "The link downloads a file", f"It leads to {fp.path.rsplit('/', 1)[-1] or 'a file'} ({ctype or 'unknown type'}). Don't open files from links you didn't expect.")
    if doc:
        title = (_title(doc) or "").lower()
        reg_final = registered_domain(final_host)
        imitated = [b for b, off in _BRANDS.items() if re.search(rf"\b{b}\b", title) and reg_final not in off and reg_final.split('.')[0] != b]
        has_pw = bool(_PASSWORD_RE.search(doc))
        if imitated and has_pw:
            add("high", "brand_login", f"A login page that says \"{imitated[0].capitalize()}\" on a different domain",
                f"The page title mentions {imitated[0].capitalize()} and asks for a password, but it's on {reg_final}. This is the classic phishing pattern.")
        elif imitated:
            add("medium", "brand_title", f"The page title mentions {imitated[0].capitalize()}, but the site is {reg_final}", "It may be legitimate (a review, a reseller), or an imitation.")
        elif has_pw:
            add("info", "password", "The page asks for a password", f"Only sign in if {reg_final} is the site you meant to visit. Typing the address yourself is safer than following a link.")
        for m in re.finditer(r"<form\b[^>]*action\s*=\s*[\"']?(https?://[^\"'\s>]+)", doc, re.I):
            ah = registered_domain(urlparse(m.group(1)).hostname or "")
            if ah and ah != reg_final and has_pw:
                add("high", "form_elsewhere", f"The password form sends what you type to {ah}", f"The page is on {reg_final} but its form posts to {ah}.")
                break
        if re.search(r"<meta[^>]+http-equiv\s*=\s*[\"']?refresh", doc, re.I) or re.search(r"(window\.)?location(\.href)?\s*=\s*[\"']https?://", doc):
            add("info", "js_redirect", "The page may redirect again with code", "We don't run JavaScript, so a further redirect from the page itself may not be shown above.")

    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    signals.sort(key=lambda s: order[s["level"]])
    highs = [s for s in signals if s["level"] == "high"]
    meds = [s for s in signals if s["level"] in ("medium", "low")]
    if highs:
        verdict, headline = "action_needed", "Warning signs: don't sign in, pay or download from this link"
    elif meds:
        verdict, headline = "improve", "Some things to double-check before you trust this link"
    else:
        verdict, headline = "good", "No warning signs found"
    issues = [{"level": s["level"] if s["level"] != "low" else "low", "title": s["title"], "detail": s["detail"]} for s in signals]
    issues.append({"level": "info", "title": "Not a malware scan",
                   "detail": "We check the warning signs people look for by hand. We don't check malware or phishing blocklists, and a site can change after we look. If in doubt, type the brand's address yourself."})
    fa = age_by.get(registered_domain(final_host), {})
    return {"url": url, "final_url": final, "final_status": st, "start_domain": registered_domain(start_host), "final_domain": registered_domain(final_host),
            "hops": [{"url": h["url"], "status": h["status"]} for h in hops], "https": fp.scheme == "https",
            "cert": cert, "domain_registered": fa.get("registered"), "domain_age_days": fa.get("age_days"),
            "signals": signals, "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Tool 15: SEO Page Checker (one page, every on-page basic in one report) ---------------------------------------

def _jsonld_types(doc: str) -> tuple[list[str], int, int]:
    types, ok, bad = [], 0, 0
    for m in re.finditer(r"<script\b[^>]*type\s*=\s*[\"']application/ld\+json[\"'][^>]*>(.*?)</script>", doc, re.I | re.S):
        try:
            data = json.loads(m.group(1).strip())
        except ValueError:
            bad += 1
            continue
        ok += 1
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, list):
                stack.extend(node)
            elif isinstance(node, dict):
                t = node.get("@type")
                types.extend(t if isinstance(t, list) else [t] if isinstance(t, str) else [])
                stack.extend(v for k, v in node.items() if k == "@graph" or isinstance(v, (dict, list)))
    return list(dict.fromkeys(types)), ok, bad


async def check_seo_page(raw_url: str) -> dict:
    """Tool 15: one page, every on-page basic: indexing signals (reused from the Indexability Checker), the search result
    (title, description, Google preview — from the Meta Tag Checker), page structure, sharing tags and structured data,
    phone basics, response time and size, links. Score = passes 1 point, checks ½, fails 0, out of the checks that apply."""
    url = normalize_page_url(raw_url)
    t0 = time.monotonic()
    async with new_client() as client:
        page = await safe_get(client, url, PAGE_BYTES, user_agent=BROWSER_UA)
    elapsed_ms = round((time.monotonic() - t0) * 1000)
    _fetch_page_or_raise(page, url)
    idx, meta = await asyncio.gather(check_indexability(url), check_meta_tags(url), return_exceptions=True)
    if isinstance(meta, Exception):
        raise meta if isinstance(meta, FetchBlocked) else FetchBlocked("We couldn't read that page's tags.")
    doc = page.text
    final = page.url
    host = urlparse(final).hostname or ""

    groups: list[dict] = []
    def group(key, title, tool, checks):
        groups.append({"key": key, "title": title, "tool": tool, "checks": checks})
    def c(key, state, t, d=""):
        return {"key": key, "state": state, "title": t, "detail": d}

    # 1. indexing
    ix = []
    if not isinstance(idx, Exception):
        ix = [x for x in idx["checks"] if x["key"] in ("status", "robots", "x_robots", "meta_robots", "canonical", "sitemap", "firewall")]
    ix.append(c("https", "pass" if final.startswith("https://") else "fail", "Served over https" if final.startswith("https://") else "The page isn't on https",
                "" if final.startswith("https://") else "Browsers mark http pages as \"Not secure\" and Google prefers https. Redirect http to https."))
    group("indexing", "Can Google index it?", "/tools/indexability-checker/", ix)
    # 2. search result
    mk = {x["key"]: x for x in meta["checks"]}
    group("serp", "How it looks in Google", "/tools/meta-tag-checker/", [mk[k] for k in ("title", "description", "dup") if k in mk])
    # 3. structure + content
    group("structure", "Page structure and content", "/tools/meta-tag-checker/", [mk[k] for k in ("h1", "outline", "lang", "alt", "words") if k in mk])
    # 4. sharing + structured data
    sm = _social_meta(doc)
    sd = []
    missing = [k for k in ("og:title", "og:description", "og:image") if not sm.get(k)]
    sd.append(c("og", "pass" if not missing else ("warn" if len(missing) < 3 else "fail"),
                "Open Graph tags set" if not missing else f"Missing {', '.join(missing)}",
                "Controls the card people see when this page is shared." if not missing else "Without them, shared links show a plain or guessed card. Check the card with the Open Graph Checker."))
    sd.append(c("twitter", "pass" if sm.get("twitter:card") else "warn", "twitter:card set" if sm.get("twitter:card") else "No twitter:card tag",
                sm.get("twitter:card", "Add twitter:card = summary_large_image for the large image card on X.")))
    types, ok, bad = _jsonld_types(doc)
    if bad:
        sd.append(c("schema", "fail", f"{bad} structured data block{'s' if bad != 1 else ''} won't parse", "One broken JSON-LD block is ignored completely. Check it with the Schema Markup Checker."))
    elif ok:
        sd.append(c("schema", "pass", f"Structured data found ({', '.join(types[:5]) or 'no @type'})", f"{ok} JSON-LD block{'s' if ok != 1 else ''}."))
    else:
        sd.append(c("schema", "warn", "No structured data", "Schema markup (JSON-LD) tells search engines and AI assistants what the page is about: an article, product, business or FAQ."))
    group("sharing", "Sharing and structured data", "/tools/schema-checker/", sd)
    # 5. phone + speed basics
    mb = _viewport_checks(doc)
    size_kb = round(len(page.body) / 1024)
    mb.append(c("html_size", "pass" if size_kb <= 300 else "warn", f"HTML size {size_kb} KB" + (" (we read the first 1 MB)" if page.truncated else ""),
                "Lean HTML." if size_kb <= 300 else "Large HTML takes longer to download and parse on phones. Inline data, scripts and styles are the usual cause."))
    mb.append(c("response", "pass" if elapsed_ms <= 1200 else "warn" if elapsed_ms <= 3000 else "fail",
                f"Page downloaded in {elapsed_ms / 1000:.1f} s from our server",
                "One measurement from our server, including the connection; not a full speed test. For real-visitor speed, use the Mobile-Friendly Checker or PageSpeed Insights."))
    enc = page.headers.get("content-encoding", "")
    mb.append(c("compression", "pass" if enc else "warn", f"Compressed ({enc})" if enc else "Not compressed",
                "" if enc else "The server sent the HTML without gzip or Brotli compression, which can make it several times larger. Turn compression on in your server or CDN."))
    group("mobile", "Phones and speed basics", "/tools/mobile-friendly-checker/", mb)
    # 6. links
    links = [l for l in _extract_links(doc, final) if l["type"] == "link"]
    internal = [l for l in links if (urlparse(l["url"]).hostname or "") == host]
    external = [l for l in links if l not in internal]
    empty = [l for l in links if not l["text"]]
    lk = [c("internal", "pass" if len(internal) >= 3 else "warn", f"{len(internal)} links to your own pages",
            "Internal links help visitors and search engines find your other pages." if len(internal) >= 3 else "Very few internal links. Link to related pages so this one isn't a dead end.")]
    lk.append(c("external", "pass", f"{len(external)} links to other sites", "Linking to good sources is normal and helpful."))
    if empty:
        lk.append(c("anchor", "warn", f"{len(empty)} link{'s' if len(empty) != 1 else ''} with no text", "Links need text (or an image with alt text) that says where they go. Screen readers announce empty links as just \"link\"."))
    group("links", "Links", "/tools/broken-link-checker/", lk)

    pts = {"pass": 1.0, "warn": 0.5, "fail": 0.0}
    every = [x for g in groups for x in g["checks"]]
    score = round(100 * sum(pts[x["state"]] for x in every) / max(1, len(every)))
    fails = [x for x in every if x["state"] == "fail"]
    warns = [x for x in every if x["state"] == "warn"]
    issues = [{"level": "high", "title": x["title"], "detail": x["detail"]} for x in fails] + \
             [{"level": "medium" if x["key"] in ("title", "description", "h1", "canonical", "og", "schema", "status") else "low", "title": x["title"], "detail": x["detail"]} for x in warns][:8]
    if fails:
        verdict, headline = "action_needed", f"Score {score}/100: fix the failed checks first"
    elif warns:
        verdict, headline = "improve", f"Score {score}/100: a solid page with things to improve"
    else:
        verdict, headline = "good", f"Score {score}/100: this page covers the basics"
    issues.append({"level": "info", "title": "On-page basics, not rankings",
                   "detail": "These checks cover what you control on the page. Rankings also depend on content quality, links from other sites and competition."})
    for g in groups:
        g["checks"].sort(key=lambda x: {"fail": 0, "warn": 1, "pass": 2}[x["state"]])
    return {"url": url, "final_url": final, "score": score, "passed": sum(1 for x in every if x["state"] == "pass"), "total": len(every),
            "serp": meta["serp"], "title": meta["title"], "description": meta["description"], "response_ms": elapsed_ms, "html_kb": size_kb,
            "groups": groups, "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Tool 16: Security Headers & Email Record Checker ----------------------------------------------------------------

_DKIM_SELECTORS = ["google", "selector1", "selector2", "k1", "k2", "k3", "s1", "s2", "default", "mail", "dkim", "smtp",
                   "mandrill", "mxvault", "zoho", "protonmail", "fm1", "fm2", "fm3", "everlytickey1", "sig1", "smtpapi"]


async def _txt(name: str) -> list[str] | None:
    """TXT records for name; [] when the name has none; None when DNS failed or dnspython is missing."""
    if dns is None:
        return None
    r = dns.asyncresolver.Resolver()
    r.timeout, r.lifetime = 2.5, 4.0
    try:
        ans = await r.resolve(name, "TXT")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return [b"".join(x.strings).decode("utf-8", errors="replace") for x in ans]


async def _mx(name: str) -> list[str] | None:
    if dns is None:
        return None
    r = dns.asyncresolver.Resolver()
    r.timeout, r.lifetime = 2.5, 4.0
    try:
        ans = await r.resolve(name, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException:
        return None
    return sorted(str(x.exchange).rstrip(".") for x in ans)


async def _spf_lookups(record: str, depth: int = 0, budget: list | None = None) -> int:
    """Counts the DNS-querying mechanisms SPF evaluates (include, a, mx, ptr, exists, redirect), following includes, like
    RFC 7208's 10-lookup limit. Capped so a hostile chain can't make us query forever."""
    budget = budget if budget is not None else [25]
    n = 0
    for term in record.split()[1:]:
        t = term.lstrip("+-~?").lower()
        if t.startswith(("include:", "redirect=")):
            n += 1
            if depth < 4 and budget[0] > 0:
                budget[0] -= 1
                target = t.split(":", 1)[1] if t.startswith("include:") else t.split("=", 1)[1]
                sub = await _txt(target) or []
                rec = next((s for s in sub if s.lower().startswith("v=spf1")), None)
                if rec:
                    n += await _spf_lookups(rec, depth + 1, budget)
        elif t in ("a", "mx", "ptr") or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:", "exists:")):
            n += 1
    return n


def _split_cookies(v: str) -> list[str]:
    return [x for x in re.split(r",\s*(?=[^;,=\s]+=)", v or "") if x.strip()]


async def check_security_email(raw_url: str) -> dict:
    """Tool 16: the trust settings visitors and inbox providers check without telling you: https and the certificate,
    security headers (HSTS, CSP, clickjacking, nosniff, referrer and permissions policies), cookie flags and version leaks;
    then the domain's email records: MX, SPF (with the 10-lookup limit), DMARC policy and DKIM on common selectors."""
    site = normalize_site_url(raw_url)
    host = (urlparse(site).hostname or "").lower()
    domain = registered_domain(host)
    async with new_client() as client:
        https_r, http_r = await asyncio.gather(
            safe_get(client, f"https://{host}/", 64 * 1024, user_agent=BROWSER_UA),
            safe_get(client, f"http://{host}/", 8 * 1024, follow_redirects=False, user_agent=BROWSER_UA))
    if https_r.status is None and http_r.status is None:
        raise FetchBlocked(f"We couldn't reach {host}. {https_r.error or ''}".strip())
    cert = await asyncio.to_thread(_cert_info, host) if https_r.status is not None else {"valid": False, "error": https_r.error}
    h = https_r.headers if https_r.status is not None else {}

    web: list[dict] = []
    def w(key, state, t, d=""):
        web.append({"key": key, "state": state, "title": t, "detail": d})

    if cert.get("valid"):
        dl = cert.get("days_left")
        w("cert", "pass" if (dl or 0) > 21 else "warn", f"Valid certificate from {cert.get('issuer') or 'a trusted issuer'}",
          f"Expires {cert.get('expires')} ({dl} days)." + ("" if (dl or 0) > 21 else " Renew it soon; an expired certificate puts a full-page warning in front of every visitor."))
    else:
        w("cert", "fail", "No valid https certificate", cert.get("error") or "Visitors will see a browser warning.")
    loc = http_r.headers.get("location", "") if http_r.status else ""
    if http_r.status in (301, 308) and loc.startswith("https://"):
        w("redirect", "pass", "http redirects to https (permanent)", f"http://{host}/ → {loc}")
    elif http_r.status in (302, 307) and loc.startswith("https://"):
        w("redirect", "warn", "http redirects to https, but temporarily", f"HTTP {http_r.status}. Use a 301 so browsers and search engines remember it.")
    elif http_r.status:
        w("redirect", "fail", "http doesn't redirect to https", f"http://{host}/ answered HTTP {http_r.status}" + (f" → {loc}" if loc else "") + ". Visitors who type the address can land on the unencrypted version.")
    hsts = h.get("strict-transport-security", "")
    if hsts:
        ma = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.I)
        age = int(ma.group(1)) if ma else 0
        w("hsts", "pass" if age >= 15768000 else "warn", "HSTS is on" + (" (with preload)" if "preload" in hsts.lower() else ""),
          hsts if age >= 15768000 else f"{hsts}. A max-age under six months gives little protection; one year (31536000) is typical.")
    else:
        w("hsts", "warn", "No HSTS header", "Strict-Transport-Security tells browsers to always use https for your site, even if someone types http. Add it once https works everywhere.")
    csp = h.get("content-security-policy", "")
    if csp:
        unsafe = "'unsafe-inline'" in csp and re.search(r"(script-src|default-src)[^;]*'unsafe-inline'", csp)
        w("csp", "warn" if unsafe else "pass", "Content Security Policy set" + (" (allows inline scripts)" if unsafe else ""),
          "A CSP controls which scripts can run. 'unsafe-inline' in script-src weakens its protection against injected scripts." if unsafe else csp[:160] + ("…" if len(csp) > 160 else ""))
    elif h.get("content-security-policy-report-only"):
        w("csp", "warn", "CSP is in report-only mode", "It reports problems but doesn't block anything yet. Switch to Content-Security-Policy once the reports are clean.")
    else:
        w("csp", "warn", "No Content Security Policy", "A CSP limits which scripts, styles and frames can load, which blunts injected-script attacks. Start with a report-only policy.")
    xfo = h.get("x-frame-options", "")
    if xfo or "frame-ancestors" in csp:
        w("framing", "pass", "Protected against clickjacking", xfo and f"X-Frame-Options: {xfo}" or "CSP frame-ancestors is set.")
    else:
        w("framing", "warn", "Other sites can frame your pages", "Add X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors 'self') so your pages can't be embedded invisibly to trick clicks.")
    xcto = h.get("x-content-type-options", "")
    w("nosniff", "pass" if "nosniff" in xcto.lower() else "warn", "X-Content-Type-Options: nosniff" if "nosniff" in xcto.lower() else "No X-Content-Type-Options header",
      "" if "nosniff" in xcto.lower() else "Add X-Content-Type-Options: nosniff so browsers don't guess file types, which can turn an upload into a script.")
    rp = h.get("referrer-policy", "")
    w("referrer", "warn" if not rp or "unsafe-url" in rp.lower() else "pass", f"Referrer-Policy: {rp}" if rp else "No Referrer-Policy",
      "unsafe-url sends full addresses, including any private parameters, to other sites." if "unsafe-url" in rp.lower() else "" if rp else "strict-origin-when-cross-origin is a sensible default: other sites see your domain, not the full page address.")
    pp = h.get("permissions-policy", "")
    w("permissions", "pass" if pp else "warn", "Permissions-Policy set" if pp else "No Permissions-Policy",
      pp[:140] if pp else "Optional, but it lets you switch off browser features you don't use (camera, microphone, location) for your pages and any embedded content.")
    leaks = [f"{k}: {h[k]}" for k in ("server", "x-powered-by", "x-aspnet-version") if h.get(k) and re.search(r"\d", h[k])]
    if leaks:
        w("leak", "warn", "Server software versions are visible", "; ".join(leaks)[:160] + ". Hiding version numbers doesn't fix anything, but it stops advertising exactly what to look up.")
    cookies = _split_cookies(h.get("set-cookie", ""))
    if cookies:
        weak = [ck.split("=", 1)[0] for ck in cookies if "secure" not in ck.lower() or "httponly" not in ck.lower() or "samesite" not in ck.lower()]
        w("cookies", "warn" if weak else "pass", f"{len(cookies)} cookie{'s' if len(cookies) != 1 else ''} set on the homepage" + (f", {len(weak)} without all of Secure, HttpOnly and SameSite" if weak else ", all with Secure, HttpOnly and SameSite"),
          ("Cookies: " + ", ".join(weak[:4]) + ". Session and login cookies should have all three; analytics cookies read by scripts can't use HttpOnly.") if weak else "")

    # email records
    txt_root, dmarc_txt, mx = await asyncio.gather(_txt(domain), _txt(f"_dmarc.{domain}"), _mx(domain))
    dkim_res = await asyncio.gather(*[_txt(f"{s}._domainkey.{domain}") for s in _DKIM_SELECTORS])
    mail: list[dict] = []
    def m(key, state, t, d=""):
        mail.append({"key": key, "state": state, "title": t, "detail": d})
    dns_ok = txt_root is not None
    if mx is None:
        m("mx", "warn", "Couldn't read MX records", "DNS didn't answer in time. Try again.")
    elif mx:
        m("mx", "pass", f"Receives email ({len(mx)} MX record{'s' if len(mx) != 1 else ''})", ", ".join(mx[:3]))
    else:
        m("mx", "warn", "No MX records: this domain doesn't receive email", "If you never send email from it either, publish \"v=spf1 -all\" and a DMARC reject policy so nobody can send as you.")
    spfs = [t for t in (txt_root or []) if t.lower().startswith("v=spf1")]
    if not dns_ok:
        m("spf", "warn", "Couldn't read SPF", "DNS didn't answer in time. Try again.")
    elif not spfs:
        m("spf", "fail", "No SPF record", "SPF lists the servers allowed to send email for your domain. Without it, inboxes trust your email less and spoofing is easier. Add one TXT record starting v=spf1.")
    elif len(spfs) > 1:
        m("spf", "fail", f"{len(spfs)} SPF records (only one is allowed)", "With more than one, SPF fails for every message. Merge them into a single v=spf1 record.")
    else:
        spf = spfs[0]
        allq = re.search(r"([+\-~?]?)all\b", spf.lower())
        look = await _spf_lookups(spf)
        if not allq:
            m("spf", "warn", "SPF has no \"all\" at the end", f"{spf[:120]}. End it with -all (reject others) or ~all (mark others suspicious).")
        elif allq.group(1) in ("", "+"):
            m("spf", "fail", "SPF allows anyone to send (+all)", "This defeats the purpose of SPF. Use -all or ~all.")
        elif allq.group(1) == "?":
            m("spf", "warn", "SPF is neutral (?all)", "Neutral tells inboxes nothing. Use ~all or -all.")
        else:
            m("spf", "pass", f"SPF record found (ends {allq.group(0)})", spf[:160])
        if look > 10:
            m("spf_lookups", "fail", f"SPF needs {look} DNS lookups (the limit is 10)", "Over 10, SPF returns a permanent error and can fail every message. Remove services you no longer use, or flatten includes.")
        elif look >= 8:
            m("spf_lookups", "warn", f"SPF uses {look} of 10 DNS lookups", "Close to the limit. Adding one more service could break SPF.")
    dm = [t for t in (dmarc_txt or []) if t.lower().startswith("v=dmarc1")]
    if dmarc_txt is None:
        m("dmarc", "warn", "Couldn't read DMARC", "DNS didn't answer in time. Try again.")
    elif not dm:
        m("dmarc", "fail", "No DMARC record", f"Add a TXT record at _dmarc.{domain}, starting with v=DMARC1; p=none; rua=mailto:you@{domain}, then tighten the policy once reports look right. Large inbox providers expect DMARC from bulk senders.")
    else:
        pm = re.search(r"\bp\s*=\s*(\w+)", dm[0], re.I)
        pol = pm.group(1).lower() if pm else ""
        rua = "rua=" in dm[0].lower()
        if pol in ("quarantine", "reject"):
            m("dmarc", "pass", f"DMARC policy: {pol}", dm[0][:160])
        elif pol == "none":
            m("dmarc", "warn", "DMARC is monitoring only (p=none)", "It collects reports but doesn't stop anyone sending as you. Move to quarantine, then reject, once legitimate senders pass.")
        else:
            m("dmarc", "warn", "DMARC record has no valid policy", dm[0][:160])
        if not rua:
            m("dmarc_rua", "warn", "DMARC sends no reports", "Add rua=mailto:… so you receive daily reports of who is sending email as your domain.")
    keys = {s: [x for x in r if "p=" in x.lower() or "v=dkim1" in x.lower()] for s, r in zip(_DKIM_SELECTORS, dkim_res) if r}
    found = [s for s, v in keys.items() if any(re.search(r"\bp=\s*[A-Za-z0-9+/]{20,}", x) for x in v)]
    null = [s for s, v in keys.items() if v and s not in found and all(re.search(r"\bp=\s*(;|$)", x) for x in v)]
    if not found and null:
        m("dkim", "pass", "DKIM keys are deliberately empty", "Empty DKIM keys (p=) say this domain doesn't sign or send email, which stops anyone faking signed mail from it.")
    elif found:
        m("dkim", "pass", f"DKIM key found (selector {', '.join(found[:3])})", "DKIM signs your email so inboxes can confirm it wasn't changed and really came from your domain.")
    else:
        m("dkim", "warn", f"No DKIM key on {len(_DKIM_SELECTORS)} common selectors",
          "DKIM keys live at a name your email provider chooses (the selector). We tried the common ones; yours may use another. Check your email provider's DKIM settings.")

    allc = web + mail
    fails = [x for x in allc if x["state"] == "fail"]
    warns = [x for x in allc if x["state"] == "warn"]
    imp = ("cert", "redirect", "spf", "dmarc", "hsts", "spf_lookups")
    issues = [{"level": "high", "title": x["title"], "detail": x["detail"]} for x in fails] + \
             [{"level": "medium" if x["key"] in imp else "low", "title": x["title"], "detail": x["detail"]} for x in warns]
    if fails:
        verdict, headline = "action_needed", "Some trust settings are missing or broken"
    elif warns:
        verdict, headline = "improve", "The essentials are in place, with headers worth adding"
    else:
        verdict, headline = "good", "Your security headers and email records look strong"
    issues.append({"level": "info", "title": "Headers from your homepage only",
                   "detail": "Other pages can send different headers. Email records apply to the whole domain."})
    order = {"fail": 0, "warn": 1, "pass": 2}
    return {"url": site, "host": host, "domain": domain, "final_url": https_r.url if https_r.status else None, "cert": cert,
            "web": sorted(web, key=lambda x: order[x["state"]]), "mail": sorted(mail, key=lambda x: order[x["state"]]),
            "dkim_selectors_tried": len(_DKIM_SELECTORS), "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---------------------------------------------------------------------------------------------
# llms.txt Validator, XML Sitemap Generator,
# Keyword Density Checker, Bulk Mobile-Friendly Test. (Meta/OG/Twitter Card Generator, Social Media Calendar Template and
# Image Compressor run entirely in the visitor's browser.) Same guardrails as above: every fetch goes through safe_get
# (public IPs only, every redirect hop re-validated, byte caps, timeouts); zero LLM calls; nothing stored.
# ---------------------------------------------------------------------------------------------

# ---- llms.txt Validator (spec: https://llmstxt.org/) -------------------------------------------
LLMS_LARGE_BYTES = 200 * 1024
_MD_LINK_RE = re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)")


def _llms_target(raw: str) -> tuple[str, str]:
    """A site ("example.com") checks /llms.txt at the root; a full address ending in .txt checks that exact file
    (the spec allows llms.txt at a subpath such as /docs/llms.txt). Returns (llms url, site root)."""
    page = normalize_page_url(raw)
    site = normalize_site_url(raw)
    path = urlparse(page).path or "/"
    if path.lower().endswith(".txt"):
        return page.split("?")[0], site
    return site + "/llms.txt", site


def _validate_llms_structure(text: str) -> dict:
    lines = text.lstrip("﻿").splitlines()
    nonblank = [(i, l.rstrip()) for i, l in enumerate(lines) if l.strip()]
    h1s = [(i, l) for i, l in nonblank if re.match(r"^# \S", l)]
    h2s = [(i, l) for i, l in nonblank if re.match(r"^## \S", l)]
    deeper = [l for _, l in nonblank if re.match(r"^#{3,6} ", l)]
    quotes = [(i, l) for i, l in nonblank if l.startswith(">")]
    first_line = nonblank[0][1] if nonblank else ""
    first_h2 = h2s[0][0] if h2s else None
    links = _MD_LINK_RE.findall(text)
    # list items under H2 sections that should be links
    bad_items, sections = [], []
    current = None
    for i, l in nonblank:
        if re.match(r"^## \S", l):
            current = {"name": l[3:].strip(), "items": 0, "links": 0}
            sections.append(current)
        elif current is not None and re.match(r"^\s*[-*+] ", l):
            current["items"] += 1
            if _MD_LINK_RE.search(l):
                current["links"] += 1
            else:
                bad_items.append(l.strip()[:120])
    bare_urls = [u for u in re.findall(r"(?<![(\[])\bhttps?://[^\s)\]>]+", text)
                 if not any(u == href or u in href for _, href in links)]
    return {"first_line": first_line[:160], "has_h1_first": bool(nonblank) and bool(re.match(r"^# \S", first_line)),
            "h1_count": len(h1s), "h1": h1s[0][1][2:].strip() if h1s else None,
            "has_summary": bool(quotes), "summary_after_h1": bool(quotes and h1s and quotes[0][0] > h1s[0][0]),
            "summary": quotes[0][1].lstrip("> ").strip()[:300] if quotes else None,
            "summary_before_lists": bool(quotes and (first_h2 is None or quotes[0][0] < first_h2)),
            "sections": sections, "has_optional": any(s["name"].lower() == "optional" for s in sections),
            "deeper_headings": len(deeper), "link_count": len(links), "bad_list_items": bad_items[:10],
            "bad_list_count": len(bad_items), "bare_urls": bare_urls[:10], "links": [h for _, h in links]}


async def validate_llms_txt(raw_url: str) -> dict:
    target, site = _llms_target(raw_url)
    checks: list[dict] = []

    def add(key, state, title, detail=""):
        checks.append({"key": key, "state": state, "title": title, "detail": detail})

    async with new_client() as client:
        r, full_r = await asyncio.gather(safe_get(client, target, SMALL_FILE_BYTES),
                                         safe_get(client, site + "/llms-full.txt", 4096))
        if r.status is None:
            raise FetchBlocked(f"We couldn't reach {target}. {r.error or ''}".strip())
        ctype = r.headers.get("content-type", "").split(";")[0].strip().lower()
        moved = not _same_url(r.url, target)
        if r.status >= 400:
            add("found", "fail", f"No llms.txt at {target} (HTTP {r.status})",
                "Create one with the generator on this page and upload it to your site's root folder, so it loads at /llms.txt.")
            return {"url": target, "final_url": r.url, "status": r.status, "checks": checks, "structure": None,
                    "full_present": False, "summary": {"verdict": "action_needed", "headline": "No llms.txt file found",
                                                       "issues": [{"level": "high", "title": checks[0]["title"], "detail": checks[0]["detail"]}]}}
        text = r.text
        if _looks_like_html(text) or ctype == "text/html":
            add("format", "fail", "Your /llms.txt address returns a web page, not a text file",
                "Your server sends its normal HTML page for this address (often a 'page not found' page with a 200 status), so AI tools find no usable file. Upload a plain text llms.txt.")
            return {"url": target, "final_url": r.url, "status": r.status, "checks": checks, "structure": None,
                    "full_present": False, "summary": {"verdict": "action_needed", "headline": "Your llms.txt isn't a real text file",
                                                       "issues": [{"level": "high", "title": checks[0]["title"], "detail": checks[0]["detail"]}]}}
        add("found", "pass", f"llms.txt found (HTTP {r.status})", r.url)
        if moved:
            add("redirect", "warn", "The file is reached through a redirect",
                f"{target} redirects to {r.url}. It works, but tools that don't follow redirects may miss it. Serve it directly at the address people request.")
        if ctype in ("text/plain", "text/markdown", "text/x-markdown"):
            add("type", "pass", f"Served as {ctype}", "")
        else:
            add("type", "warn", f"Served as {ctype or 'an unknown type'}",
                "Serve it as text/plain (or text/markdown) with UTF-8, so browsers and tools read it as text.")
        size = len(r.body)
        if r.truncated or size > LLMS_LARGE_BYTES:
            add("size", "warn", f"Large file ({size // 1024} KB{'+' if r.truncated else ''})",
                "llms.txt is meant to be a short map of your key pages. Keep it focused, and put full page text in llms-full.txt if you need it.")
        else:
            add("size", "pass", f"Size: {size:,} bytes", "")

        s = _validate_llms_structure(text)
        if s["has_h1_first"] and s["h1_count"] == 1:
            add("h1", "pass", f"Starts with an H1: \"{s['h1'][:80]}\"", "The H1 (your site or project name) is the only section the format requires.")
        elif s["h1_count"] == 0:
            add("h1", "fail", "No H1 title line",
                "The first line should be your site name as a Markdown H1, for example \"# Example Studio\". It's the only required part of the format.")
        elif not s["has_h1_first"]:
            add("h1", "fail", "The H1 isn't the first line",
                f"The file starts with \"{s['first_line'][:80]}\". Put \"# Your site name\" on the first line.")
        else:
            add("h1", "warn", f"{s['h1_count']} H1 lines", "Use a single H1 (your site name); use ## for sections.")
        if not s["has_summary"]:
            add("summary", "warn", "No summary line",
                "Add a one- or two-sentence summary after the H1, written as a quote: \"> What we do and who it's for.\"")
        elif not (s["summary_after_h1"] and s["summary_before_lists"]):
            add("summary", "warn", "The summary is in the wrong place", "Put the \"> summary\" line right after the H1 and before the ## sections.")
        else:
            add("summary", "pass", "Has a summary line", s["summary"] or "")
        if not s["sections"]:
            add("sections", "warn", "No ## sections",
                "Group your key pages under ## headings (for example \"## Products\", \"## Guides\"), each followed by a list of links.")
        else:
            add("sections", "pass", f"{len(s['sections'])} section{'s' if len(s['sections']) != 1 else ''}: " + ", ".join(x["name"] for x in s["sections"][:8]), "")
        if s["link_count"] == 0:
            add("links", "fail", "No Markdown links", "List your key pages as \"- [Page name](https://...): short note\" under each section.")
        else:
            add("links", "pass", f"{s['link_count']} Markdown link{'s' if s['link_count'] != 1 else ''}", "")
        if s["bad_list_count"]:
            add("items", "warn", f"{s['bad_list_count']} list item{'s' if s['bad_list_count'] != 1 else ''} without a link",
                "Each list item in a section should be a Markdown link, for example \"- [Pricing](https://example.com/pricing): plans and prices\". First one: " + s["bad_list_items"][0])
        if s["bare_urls"]:
            add("bare", "warn", f"{len(s['bare_urls'])} address{'es' if len(s['bare_urls']) != 1 else ''} not written as links",
                "Write addresses as [name](url) so tools know what each one is. First one: " + s["bare_urls"][0])

        abs_links = []
        for href in s["links"]:
            u = urljoin(r.url, href)
            if u.startswith(("http://", "https://")) and u not in abs_links:
                abs_links.append(u)
        rel = [h for h in s["links"] if not h.startswith(("http://", "https://"))]
        if rel:
            add("relative", "warn", f"{len(rel)} relative link{'s' if len(rel) != 1 else ''}",
                f"Use full addresses (https://...) so the file still works when it's read on its own. First one: {rel[0][:100]}")
        sample = abs_links[:12]
        results = await asyncio.gather(*[safe_get(client, u, 1024) for u in sample], return_exceptions=True)
        broken = [u for u, x in zip(sample, results) if isinstance(x, Exception) or x.status is None or x.status >= 400]
        if sample:
            if broken:
                add("broken", "fail", f"{len(broken)} of {len(sample)} checked links don't load", "Fix or remove them: " + ", ".join(broken[:5]))
            else:
                add("broken", "pass", f"All {len(sample)} checked links load", "")
        full_present = full_r.status == 200 and not _looks_like_html(full_r.text)

    order = {"fail": 0, "warn": 1, "pass": 2}
    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    issues = [{"level": "high", "title": c["title"], "detail": c["detail"]} for c in fails] + \
             [{"level": "medium", "title": c["title"], "detail": c["detail"]} for c in warns]
    if fails:
        verdict, headline = "action_needed", "Your llms.txt needs fixing"
    elif warns:
        verdict, headline = "improve", "Your llms.txt works, with things to tidy"
    else:
        verdict, headline = "good", "Your llms.txt follows the format"
    return {"url": target, "final_url": r.url, "status": r.status, "checks": sorted(checks, key=lambda c: order[c["state"]]),
            "structure": {k: s[k] for k in ("h1", "summary", "sections", "has_optional", "link_count")},
            "full_present": full_present, "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- XML Sitemap Generator ---------------------------------------------------------------------
SITEMAP_GEN_MAX = 150
SITEMAP_GEN_CONCURRENCY = 6
SITEMAP_GEN_BUDGET_S = 30.0
SITEMAP_GEN_PAGE_BYTES = 600 * 1024
_SKIP_EXT = re.compile(r"\.(jpg|jpeg|png|gif|webp|avif|svg|ico|pdf|zip|rar|gz|mp4|mp3|mov|webm|css|js|json|xml|txt|woff2?|ttf|eot)$", re.I)


def _sitemap_key(u: str) -> str:
    p = urlparse(u)
    return (p.path or "/") + (("?" + p.query) if p.query else "")


async def generate_xml_sitemap(raw_url: str) -> dict:
    """Crawls a site from its homepage (same host, links in the HTML, robots.txt respected for user-agent *), keeps pages
    that return 200 HTML, aren't noindex and don't name another page as canonical, and writes a sitemaps.org XML file."""
    site = normalize_site_url(raw_url)
    started = time.monotonic()
    async with new_client() as client:
        home_r, robots_r = await asyncio.gather(safe_get(client, site + "/", SITEMAP_GEN_PAGE_BYTES),
                                                safe_get(client, site + "/robots.txt", SMALL_FILE_BYTES))
        if not home_r.status or home_r.status >= 400:
            raise FetchBlocked(f"We couldn't load {site}. {home_r.error or f'It returned HTTP {home_r.status}.'}")
        fp = urlparse(home_r.url)
        site = urlunparse((fp.scheme, fp.netloc, "", "", "", ""))
        host = fp.hostname or ""
        rules = []
        if robots_r.status == 200 and not _looks_like_html(robots_r.text):
            rules, _ = _rules_for(parse_robots(robots_r.text), "*")

        def ok_url(u: str) -> str | None:
            p = urlparse(u)
            if p.scheme not in ("http", "https") or (p.hostname or "").lower() != host.lower():
                return None
            if _SKIP_EXT.search(p.path or "") or (p.path or "").startswith("/cdn-cgi/"):
                return None
            q = "&".join(x for x in (p.query or "").split("&") if x and not x.lower().startswith(("utm_", "fbclid", "gclid", "ref=")))
            return urlunparse((fp.scheme, fp.netloc, p.path or "/", "", q, ""))

        queue = [site + "/"]
        seen = {_sitemap_key(site + "/")}
        pages, excluded = [], defaultdict(list)
        sem = asyncio.Semaphore(SITEMAP_GEN_CONCURRENCY)
        truncated = False

        async def visit(u: str):
            async with sem:
                if time.monotonic() - started > SITEMAP_GEN_BUDGET_S:
                    return u, None
                try:
                    return u, await safe_get(client, u, SITEMAP_GEN_PAGE_BYTES)
                except FetchBlocked:
                    return u, None

        while queue and len(pages) + sum(len(v) for v in excluded.values()) < SITEMAP_GEN_MAX:
            if time.monotonic() - started > SITEMAP_GEN_BUDGET_S:
                truncated = True
                break
            room = SITEMAP_GEN_MAX - len(pages) - sum(len(v) for v in excluded.values())
            batch, queue = queue[:min(room, SITEMAP_GEN_CONCURRENCY * 2)], queue[min(room, SITEMAP_GEN_CONCURRENCY * 2):]
            for u, r in await asyncio.gather(*[visit(u) for u in batch]):
                if r is None or r.status is None:
                    excluded["unreachable"].append(u)
                    continue
                if r.status >= 400:
                    excluded["error"].append(f"{u} (HTTP {r.status})")
                    continue
                final = ok_url(r.url)
                if final is None:
                    excluded["redirects_away"].append(u)
                    continue
                if "html" not in r.headers.get("content-type", "text/html"):
                    excluded["not_html"].append(u)
                    continue
                doc = r.text
                metar = (_meta(doc, "name", "robots") or "").lower() + " " + r.headers.get("x-robots-tag", "").lower()
                if "noindex" in metar:
                    excluded["noindex"].append(u)
                else:
                    canon = _canonical(doc, r.url)
                    if canon and not _same_url(canon, r.url):
                        excluded["canonical_elsewhere"].append(f"{u} → {canon}")
                    elif not any(_same_url(p["loc"], final) for p in pages):
                        lm = r.headers.get("last-modified")
                        lastmod = None
                        if lm:
                            try:
                                from email.utils import parsedate_to_datetime
                                lastmod = parsedate_to_datetime(lm).date().isoformat()
                            except Exception:
                                lastmod = None
                        pages.append({"loc": final, "lastmod": lastmod, "depth": urlparse(final).path.strip("/").count("/") + (1 if urlparse(final).path.strip("/") else 0)})
                for href in re.findall(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\'#]+)', _strip_noise(doc), re.I):
                    nu = ok_url(urljoin(r.url, html.unescape(href.strip())))
                    if not nu:
                        continue
                    k = _sitemap_key(nu)
                    if k in seen:
                        continue
                    seen.add(k)
                    if rules and not is_allowed(rules, k):
                        excluded["blocked_by_robots"].append(nu)
                        continue
                    queue.append(nu)
        if queue:
            truncated = True

    pages.sort(key=lambda p: (p["depth"], p["loc"]))
    xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for p in pages:
        xml_lines.append("  <url>")
        xml_lines.append(f"    <loc>{html.escape(p['loc'], quote=False)}</loc>")
        if p["lastmod"]:
            xml_lines.append(f"    <lastmod>{p['lastmod']}</lastmod>")
        xml_lines.append("  </url>")
    xml_lines.append("</urlset>")
    return {"site": site, "xml": "\n".join(xml_lines) + "\n", "page_count": len(pages),
            "with_lastmod": sum(1 for p in pages if p["lastmod"]), "truncated": truncated, "limit": SITEMAP_GEN_MAX,
            "excluded": {k: {"count": len(v), "examples": v[:5]} for k, v in excluded.items()},
            "robots_rules": bool(rules)}


# ---- Keyword Density Checker -------------------------------------------------------------------
_STOPWORDS = set("""a about above after again against all am an and any are aren't as at be because been before being below between both
but by can can't cannot could couldn't did didn't do does doesn't doing don't down during each few for from further had hadn't has hasn't
have haven't having he he'd he'll he's her here here's hers herself him himself his how how's i i'd i'll i'm i've if in into is isn't it
it's its itself let's me more most mustn't my myself no nor not of off on once only or other ought our ours ourselves out over own same
shan't she she'd she'll she's should shouldn't so some such than that that's the their theirs them themselves then there there's these
they they'd they'll they're they've this those through to too under until up very was wasn't we we'd we'll we're we've were weren't what
what's when when's where where's which while who who's whom why why's will with won't would wouldn't you you'd you'll you're you've your
yours yourself yourselves also just get got may might must one two us via etc use used using new like make made many much every""".split())
_WORD_RE = re.compile(r"[^\W\d_](?:[\w'’-]*[^\W_])?", re.UNICODE)


def _ngrams(tokens: list[str], n: int) -> Counter:
    c: Counter = Counter()
    for i in range(len(tokens) - n + 1):
        g = tokens[i:i + n]
        if g[0] in _STOPWORDS or g[-1] in _STOPWORDS:
            continue
        c[" ".join(g)] += 1
    return c


async def check_keyword_density(raw_url: str) -> dict:
    """Counts the most-used words and 2-3 word phrases in a page's visible text (scripts, styles, nav and footer
    removed), with density and where each top phrase also appears (title, meta description, H1, headings, URL)."""
    page = normalize_page_url(raw_url)
    async with new_client() as client:
        r = await safe_get(client, page, PAGE_BYTES, user_agent=BROWSER_UA)
    _fetch_page_or_raise(r, page)
    doc = r.text
    title = _title(doc) or ""
    desc = _meta(doc, "name", "description") or ""
    heads = _headings(doc)
    h1 = " ".join(h["text"] for h in heads if h["level"] == 1)
    hx = " ".join(h["text"] for h in heads if h["level"] > 1)
    body = re.sub(r"<(nav|footer|header|aside)\b.*?</\1>", " ", doc, flags=re.I | re.S)
    text = _visible_text(body)
    words = [w.lower().replace("’", "'") for w in _WORD_RE.findall(text)]
    total = len(words)
    if total < 30:
        raise FetchBlocked("We found fewer than 30 words of readable text on that page. If its content loads with JavaScript, a keyword counter can't see it (and many crawlers can't either).")
    content = [w for w in words if w not in _STOPWORDS and len(w) > 1]
    places = {"title": title.lower(), "description": desc.lower(), "h1": h1.lower(), "headings": hx.lower(),
              "url": urlparse(r.url).path.lower().replace("-", " ").replace("_", " ")}

    def rows(counter: Counter, n: int, k: int = 15) -> list[dict]:
        out = []
        for term, cnt in counter.most_common(k):
            if cnt < 2:
                break
            out.append({"term": term, "count": cnt, "density": round(cnt * n / total * 100, 2),
                        "in": [p for p, v in places.items() if re.search(r"\b" + re.escape(term) + r"\b", v)]})
        return out

    one = Counter(content)
    singles = rows(one, 1, 20)
    two, three = rows(_ngrams(words, 2), 2), rows(_ngrams(words, 3), 3)
    issues = []
    heavy = [x for x in singles if x["density"] > 4 and x["count"] >= 8]
    if heavy:
        issues.append({"level": "medium", "title": f"\"{heavy[0]['term']}\" makes up {heavy[0]['density']}% of the words",
                       "detail": "That's high for natural writing. Google warns against keyword stuffing; use synonyms and related terms, and write for the reader."})
    top_phrase = (two or three or singles or [None])[0]
    if top_phrase and not top_phrase["in"]:
        issues.append({"level": "low", "title": f"Your most-used phrase, \"{top_phrase['term']}\", isn't in the title, H1 or description",
                       "detail": "If that phrase is what the page is about, say so in the title and H1. If it isn't, the page may be drifting off topic."})
    if total < 300:
        issues.append({"level": "info", "title": f"Short page: {total} words of text",
                       "detail": "Short pages can rank when they fully answer the search. Check that this one does."})
    verdict = "improve" if any(i["level"] == "medium" for i in issues) else "good"
    headline = "Some words are used very heavily" if verdict == "improve" else "Keyword use looks natural"
    return {"url": page, "final_url": r.url, "title": title, "description": desc, "h1": h1, "word_count": total,
            "unique_words": len(set(content)), "single": singles, "two": two, "three": three,
            "summary": {"verdict": verdict, "headline": headline, "issues": issues}}


# ---- Bulk Mobile-Friendly Test (no speed test, so it never spends PageSpeed quota) -------------------
MOBILE_BULK_MAX = 5


async def _mobile_basics(client: httpx.AsyncClient, page: str) -> dict:
    try:
        mob, desk = await asyncio.gather(safe_get(client, page, MOBILE_PAGE_BYTES, user_agent=MOBILE_UA),
                                         safe_get(client, page, MOBILE_PAGE_BYTES, user_agent=BROWSER_UA))
    except FetchBlocked as exc:
        return {"url": page, "verdict": "error", "headline": str(exc), "checks": []}
    checks: list[dict] = []
    def add(key, state, title, detail=""):
        checks.append({"key": key, "state": state, "title": title, "detail": detail})
    if mob.status is None or mob.status >= 400:
        add("loads", "fail", f"Phones can't load the page (HTTP {mob.status or 'no response'})", mob.error or "")
    else:
        add("loads", "pass", f"Loads on phones (HTTP {mob.status})")
        doc = mob.text
        checks.extend(_viewport_checks(doc))
        mw = _visible_word_count(doc)
        dw = _visible_word_count(desk.text) if desk.status and desk.status < 400 else 0
        if dw >= 150 and mw < dw * 0.6:
            add("parity", "warn", "Phones get much less content than desktop", f"About {mw} words on mobile, {dw} on desktop.")
        elif dw:
            add("parity", "pass", "Same content as desktop", f"About {mw} words on mobile, {dw} on desktop.")
        imgs = re.findall(r"<img\b[^>]*>", doc, re.I)
        nosize = [i for i in imgs if not (re.search(r"\bwidth\s*=", i, re.I) and re.search(r"\bheight\s*=", i, re.I)) and not re.search(r"\.svg\b", i, re.I)]
        if len(nosize) >= 3:
            add("img_size", "warn", f"{len(nosize)} of {len(imgs)} images have no width and height", "The page jumps as they load (layout shift).")
        head = doc.split("</head>", 1)[0] if "</head>" in doc.lower() else doc[:20000]
        blocking = [s for s in re.findall(r"<script\b[^>]*\bsrc=[^>]*>", head, re.I) if not re.search(r"\b(async|defer)\b|type\s*=\s*[\"']?module", s, re.I)]
        if len(blocking) >= 3:
            add("blocking", "warn", f"{len(blocking)} render-blocking scripts", "Add async or defer so the page shows sooner on mobile networks.")
    fails = [c for c in checks if c["state"] == "fail"]
    warns = [c for c in checks if c["state"] == "warn"]
    verdict = "action_needed" if fails else ("improve" if warns else "good")
    headline = {"action_needed": "Not ready for phones", "improve": "Works on phones, with fixes", "good": "Ready for phones"}[verdict]
    order = {"fail": 0, "warn": 1, "pass": 2}
    return {"url": page, "final_url": mob.url, "verdict": verdict, "headline": headline,
            "checks": sorted(checks, key=lambda c: order[c["state"]])}


async def check_mobile_bulk(raw_url: str) -> dict:
    parts = [x for x in re.split(r"[\s,]+", (raw_url or "").strip()) if x]
    if not parts:
        raise FetchBlocked("Please enter one to five page addresses, one per line.")
    pages = []
    for x in parts[:MOBILE_BULK_MAX]:
        u = normalize_page_url(x)
        if u not in pages:
            pages.append(u)
    sem = asyncio.Semaphore(3)
    async with new_client() as client:
        async def one(u):
            async with sem:
                return await _mobile_basics(client, u)
        results = await asyncio.gather(*[one(u) for u in pages])
    bad = [r for r in results if r["verdict"] in ("action_needed", "error")]
    mid = [r for r in results if r["verdict"] == "improve"]
    if bad:
        verdict, headline = "action_needed", f"{len(bad)} of {len(results)} pages aren't ready for phones"
    elif mid:
        verdict, headline = "improve", f"All {len(results)} pages work on phones; {len(mid)} {'has' if len(mid) == 1 else 'have'} fixes to make"
    else:
        verdict, headline = "good", f"All {len(results)} pages are ready for phones"
    return {"results": results, "skipped": max(0, len(parts) - MOBILE_BULK_MAX),
            "summary": {"verdict": verdict, "headline": headline, "issues": []}}
