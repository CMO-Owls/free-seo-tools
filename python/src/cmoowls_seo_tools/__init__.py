"""CMO Owls free SEO tools: the open-source engine behind https://www.cmoowls.com/tools/.

    import asyncio
    from cmoowls_seo_tools import check_ai_visibility
    result = asyncio.run(check_ai_visibility("example.com"))
"""
from .core import (analyze_robots, check_ai_visibility, check_crawler_access, check_images, check_indexability,
                   check_keyword_density, check_link_safety, check_links, check_meta_tags, check_mobile, check_mobile_bulk,
                   check_open_graph, check_redirects, check_schema, check_security_email, check_seo_page, check_sitemap,
                   generate_llms_txt, generate_xml_sitemap, is_allowed, normalize_site_url, parse_robots, validate_llms_txt)

__version__ = "1.0.0"
__all__ = [n for n in dir() if not n.startswith("_")]
