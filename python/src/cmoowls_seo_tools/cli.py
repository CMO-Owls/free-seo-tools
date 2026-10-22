"""Command line for the CMO Owls free SEO tools.

    cmoowls-seo <tool> <url> [--json] [--out FILE]

Every tool prints a plain-English verdict and the issues it found; --json prints the full result. Generators (llms-txt,
sitemap-generate) print the file, or save it with --out. Full visual reports: https://www.cmoowls.com/tools/
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys

from . import core

# tool name -> (function, what it does, hosted version)
TOOLS = {
    "ai-visibility": (core.check_ai_visibility, "Can ChatGPT, Claude, Perplexity and Google's AI reach the site?", "ai-visibility-checker"),
    "crawler-access": (core.check_crawler_access, "Visit the site as 15+ search and AI crawlers; see which ones get blocked", "ai-crawler-access-test"),
    "robots": (core.analyze_robots, "Read robots.txt and show which crawlers each rule affects", "robots-txt-generator"),
    "llms-txt": (core.generate_llms_txt, "Generate an llms.txt file from the site's sitemap", "llms-txt-generator"),
    "llms-validate": (core.validate_llms_txt, "Validate an existing llms.txt against the format", "llms-txt-generator"),
    "schema": (core.check_schema, "Find broken or incomplete JSON-LD structured data", "schema-checker"),
    "broken-links": (core.check_links, "Check every link, image, script and stylesheet on a page", "broken-link-checker"),
    "indexability": (core.check_indexability, "Status code, robots.txt, noindex, canonical and sitemap in one verdict", "indexability-checker"),
    "redirects": (core.check_redirects, "Follow every redirect hop: 301 vs 302, chains, loops", "redirect-checker"),
    "mobile": (core.check_mobile, "Mobile-friendly test: viewport, zoom, content parity, layout shift, speed", "mobile-friendly-checker"),
    "mobile-bulk": (core.check_mobile_bulk, "Mobile checks for up to 5 URLs (one per line or comma-separated)", "mobile-friendly-checker"),
    "meta-tags": (core.check_meta_tags, "Title and description by pixel width, headings and alt text", "meta-tag-checker"),
    "open-graph": (core.check_open_graph, "Open Graph and Twitter Card tags, og:image size and shape", "open-graph-checker"),
    "images": (core.check_images, "Every image's size, format and dimensions; heavy ones flagged", "image-size-checker"),
    "sitemap": (core.check_sitemap, "Find and validate the XML sitemap, spot-check listed pages", "sitemap-checker"),
    "sitemap-generate": (core.generate_xml_sitemap, "Crawl up to 150 pages and build a clean sitemap.xml", "xml-sitemap-generator"),
    "keyword-density": (core.check_keyword_density, "Most-used words and 2-3 word phrases, and where they appear", "keyword-density-checker"),
    "link-safety": (core.check_link_safety, "Where a link really goes; look-alike and brand-new domains", "link-safety-checker"),
    "seo-page": (core.check_seo_page, "Every on-page SEO basic for one page, scored", "seo-page-checker"),
    "security": (core.check_security_email, "HTTPS, security headers, cookie flags, SPF, DKIM and DMARC", "security-headers-checker"),
}
LEVEL = {"high": "HIGH", "medium": "MED ", "low": "LOW ", "info": "INFO"}


def _print(tool: str, r: dict, out: str | None) -> None:
    text = r.get("llms_txt") or r.get("xml")
    if text is not None:
        if out:
            with open(out, "w", encoding="utf-8") as f:
                f.write(text)
            print(f"Saved {out}")
        else:
            print(text)
    if r.get("crawlers"):   # robots: one line per crawler
        word = {"allowed": "allowed", "partial": "allowed, some paths blocked", "blocked": "BLOCKED"}
        for cr in r["crawlers"]:
            print(f"  {cr['name']:<20} {cr['company']:<14} {word.get(cr.get('status'), cr.get('status'))}")
    if r.get("pages_included") is not None and not out:
        print(f"\n{r['pages_included']} pages included" + (" (from the sitemap)" if r.get("used_sitemap") else ""))
    s = r.get("summary")
    if isinstance(s, dict) and s:
        print(f"\n{s.get('headline', '')}  [{s.get('verdict', '')}]")
        for i in s.get("issues", []):
            print(f"  {LEVEL.get(i.get('level'), '    ')}  {i.get('title', '')}")
            if i.get("detail"):
                print(f"        {i['detail']}")
    print(f"\nFull visual report: https://www.cmoowls.com/tools/{TOOLS[tool][2]}/")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="cmoowls-seo", description="Free SEO and AI-visibility checks from CMO Owls (cmoowls.com).",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog="tools:\n" + "\n".join(f"  {k:<17} {v[1]}" for k, v in TOOLS.items()))
    p.add_argument("tool", choices=sorted(TOOLS), metavar="tool", help="which check to run (see the list below)")
    p.add_argument("url", help="website or page address, e.g. example.com")
    p.add_argument("--json", action="store_true", help="print the full result as JSON")
    p.add_argument("--out", help="save a generated file (llms-txt, sitemap-generate) to this path")
    a = p.parse_args(argv)
    try:
        r = asyncio.run(TOOLS[a.tool][0](a.url))
    except Exception as exc:   # the engine raises user-facing messages for invalid or unreachable addresses
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    if a.json:
        print(json.dumps(r, indent=2, ensure_ascii=False, default=str))
    else:
        _print(a.tool, r, a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
