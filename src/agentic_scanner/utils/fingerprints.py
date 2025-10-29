from typing import Dict, Any, List
import re
from loguru import logger

COMMON_FRAMEWORK_HEADERS = {
    "x-powered-by": {
        "express": "Express",
        "php": "PHP",
        "asp.net": ".NET",
        "next.js": "Next.js",
        "laravel": "Laravel",
        "django": "Django",
        "rails": "Ruby on Rails",
    },
}

COMMON_LIB_HINTS = [
    (re.compile(r"/wp-content/|/wp-includes/", re.I), "WordPress"),
    (re.compile(r"/_next/static/", re.I), "Next.js"),
    (re.compile(r"/static/admin/", re.I), "Django Admin"),
]

TLS_CIPHERS_HINTS = {
    # placeholders for future TLS inspection integration
}

def fingerprint_from_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    tech = {"frameworks": [], "languages": [], "server": None, "confidence": 0.0}
    h = {k.lower(): v for k, v in headers.items()}
    if "server" in h:
        tech["server"] = h["server"]
        tech["confidence"] += 0.2
    if "x-powered-by" in h:
        xp = h["x-powered-by"].lower()
        for key, name in COMMON_FRAMEWORK_HEADERS["x-powered-by"].items():
            if key in xp:
                tech["frameworks"].append(name)
                tech["confidence"] += 0.2
    # Cookie flags give hints of frameworks sometimes
    if "set-cookie" in h and "sessionid" in h["set-cookie"].lower():
        tech["frameworks"].append("Django?")
        tech["confidence"] += 0.05
    tech["confidence"] = min(1.0, tech["confidence"])
    return tech

def fingerprint_from_paths(paths: List[str]) -> List[str]:
    hits = set()
    for p in paths:
        for pat, label in COMMON_LIB_HINTS:
            if pat.search(p):
                hits.add(label)
    return list(hits)
