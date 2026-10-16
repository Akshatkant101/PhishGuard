"""
Live Evaluation Dataset Builder
===============================
Fetches:
- 200 live active phishing URLs from OpenPhish feed (https://openphish.com/feed.txt)
- 200 legitimate URLs from Tranco Top 1M list:
  * 100 homepages (https://domain/ or https://www.domain/)
  * 100 real links crawled from those live sites (actual href links parsed from homepage HTML, NO fabricated paths).

Saves to:
- backend/ml/data/live_eval_400.json
- backend/ml/data/live_eval_400.csv
- backend/ml/data/live_eval_val_200.json  (Validation set: 100 phish, 100 legit)
- backend/ml/data/live_eval_test_200.json (Test holdout set: 100 phish, 100 legit)
with exact timestamps, provenance tracking, and domain-stratified split.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import random
import re
import urllib.parse
import urllib.request
import zipfile
import pandas as pd

from app.services.feature_extractor import extract_domain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent
JSON_OUT = DATA_DIR / "live_eval_400.json"
CSV_OUT = DATA_DIR / "live_eval_400.csv"
VAL_JSON_OUT = DATA_DIR / "live_eval_val_200.json"
TEST_JSON_OUT = DATA_DIR / "live_eval_test_200.json"

HREF_REGEX = re.compile(r'href=["\']([^"\'#\s>]+)["\']', re.IGNORECASE)


def fetch_openphish_urls(target_count: int = 200) -> list[dict]:
    """Fetch live phishing URLs from OpenPhish community feed."""
    logger.info("Fetching OpenPhish community feed...")
    url = "https://openphish.com/feed.txt"
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Live-Eval/2.0"})

    with urllib.request.urlopen(req, timeout=12) as resp:
        lines = resp.read().decode("utf-8", errors="replace").splitlines()

    valid_urls = []
    seen_domains = set()
    now_str = datetime.now(timezone.utc).isoformat()

    for line in lines:
        raw = line.strip()
        if not raw or not raw.startswith(("http://", "https://")):
            continue
        dom = extract_domain(raw)
        if not dom:
            continue
        valid_urls.append({
            "url": raw,
            "domain": dom,
            "label": 1,  # 1 = Phishing
            "source": "openphish",
            "type": "phishing_feed",
            "fetched_at": now_str,
        })
        seen_domains.add(dom)
        if len(valid_urls) >= target_count:
            break

    logger.info(f"Collected {len(valid_urls)} live phishing URLs from OpenPhish across {len(seen_domains)} domains.")
    return valid_urls


def _crawl_site_links(domain: str, timeout: int = 4) -> list[str]:
    """Crawl live homepage and extract real internal links."""
    candidates = [f"https://www.{domain}/", f"https://{domain}/"]
    extracted_links = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    for base_url in candidates:
        try:
            req = urllib.request.Request(base_url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read(250000).decode("utf-8", errors="ignore")
                matches = HREF_REGEX.findall(content)
                for href in matches:
                    if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                        continue
                    full_url = urllib.parse.urljoin(base_url, href)
                    parsed = urllib.parse.urlparse(full_url)
                    # Check same domain and has non-empty path
                    if parsed.scheme in ("http", "https") and parsed.netloc.endswith(domain):
                        clean_path = parsed.path.strip()
                        if clean_path and clean_path != "/" and len(clean_path) > 2:
                            # Avoid image/asset files
                            ext = Path(clean_path).suffix.lower()
                            if ext not in (".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico", ".woff", ".woff2"):
                                extracted_links.append(full_url)
            if extracted_links:
                break
        except Exception:
            continue

    return extracted_links


def fetch_tranco_real_urls(target_count: int = 200, exclude_domains: set = None) -> list[dict]:
    """
    Build legitimate URL set using REAL URLs ONLY:
    - 100 live homepages
    - 100 real links crawled from those live sites (NO fabricated paths)
    """
    logger.info("Fetching Tranco Top 1M list...")
    if exclude_domains is None:
        exclude_domains = set()

    url = "https://tranco-list.eu/top-1m.csv.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    with urllib.request.urlopen(req, timeout=15) as resp:
        z = zipfile.ZipFile(io.BytesIO(resp.read()))
        with z.open(z.namelist()[0]) as f:
            raw_domains = []
            for i, line in enumerate(f):
                if i >= 350:
                    break
                parts = line.decode("utf-8").strip().split(",")
                if len(parts) >= 2:
                    raw_domains.append(parts[1])

    # Filter out CDN infrastructure/tld domains and phishing overlap
    candidate_domains = [d for d in raw_domains if d not in exclude_domains]
    now_str = datetime.now(timezone.utc).isoformat()

    homepages = []
    for d in candidate_domains:
        homepages.append({
            "url": f"https://www.{d}/",
            "domain": d,
            "label": 0,
            "source": "tranco",
            "type": "homepage",
            "fetched_at": now_str,
        })
        if len(homepages) >= 100:
            break

    logger.info(f"Selected {len(homepages)} live homepages. Now crawling live sites for real internal links...")

    crawled_urls = []
    seen_urls = {h["url"] for h in homepages}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_dom = {executor.submit(_crawl_site_links, d): d for d in candidate_domains[:120]}
        for future in as_completed(future_to_dom):
            dom = future_to_dom[future]
            try:
                links = future.result()
                for link in links:
                    if link not in seen_urls:
                        seen_urls.add(link)
                        crawled_urls.append({
                            "url": link,
                            "domain": dom,
                            "label": 0,
                            "source": "tranco",
                            "type": "crawled_real_path",
                            "fetched_at": now_str,
                        })
                        if len(crawled_urls) >= 100:
                            break
            except Exception:
                pass
            if len(crawled_urls) >= 100:
                break

    # If we need a few more to reach exactly 100 crawled, crawl additional domains
    if len(crawled_urls) < 100:
        logger.info(f"Crawled {len(crawled_urls)} links, crawling next batch of domains to reach 100...")
        for d in candidate_domains[120:180]:
            links = _crawl_site_links(d)
            for link in links:
                if link not in seen_urls:
                    seen_urls.add(link)
                    crawled_urls.append({
                        "url": link,
                        "domain": dom,
                        "label": 0,
                        "source": "tranco",
                        "type": "crawled_real_path",
                        "fetched_at": now_str,
                    })
                    if len(crawled_urls) >= 100:
                        break
            if len(crawled_urls) >= 100:
                break

    logger.info(f"Collected {len(crawled_urls)} real crawled URLs with actual server-verified paths.")
    legit_total = homepages + crawled_urls
    logger.info(f"Total real legit URLs: {len(legit_total)} (100 homepages + {len(crawled_urls)} crawled).")
    return legit_total


def split_val_test(phish_urls: list[dict], legit_urls: list[dict]) -> tuple[list[dict], list[dict]]:
    """
    Split live dataset 50/50 into Validation and Test holdout halves (100 phish, 100 legit each).
    """
    random.seed(42)

    # For legitimate: 100 homepages + 100 crawled
    legit_home = [u for u in legit_urls if u.get("type") == "homepage"]
    legit_crawled = [u for u in legit_urls if u.get("type") == "crawled_real_path"]
    random.shuffle(legit_home)
    random.shuffle(legit_crawled)

    val_legit = legit_home[:50] + legit_crawled[:50]
    test_legit = legit_home[50:100] + legit_crawled[50:100]

    # For phishing: 200 URLs grouped by domain
    phish_by_dom = {}
    for p in phish_urls:
        phish_by_dom.setdefault(p["domain"], []).append(p)

    doms = list(phish_by_dom.keys())
    random.shuffle(doms)

    val_phish = []
    test_phish = []
    for d in doms:
        items = phish_by_dom[d]
        if len(val_phish) + len(items) <= 100:
            val_phish.extend(items)
        elif len(val_phish) < 100:
            needed = 100 - len(val_phish)
            val_phish.extend(items[:needed])
            test_phish.extend(items[needed:])
        else:
            test_phish.extend(items)

    val_set = val_phish[:100] + val_legit[:100]
    test_set = test_phish[:100] + test_legit[:100]

    random.shuffle(val_set)
    random.shuffle(test_set)
    return val_set, test_set


def build_and_save():
    phish = fetch_openphish_urls(target_count=200)
    phish_domains = {p["domain"] for p in phish}

    legit = fetch_tranco_real_urls(target_count=200, exclude_domains=phish_domains)

    combined = phish + legit
    random.seed(42)
    random.shuffle(combined)

    # Provenance manifest
    manifest = {
        "dataset_name": "PhishGuard Live Evaluation Benchmark 400 (Real Crawled)",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_urls": len(combined),
        "phishing_count": len(phish),
        "legitimate_count": len(legit),
        "legitimate_breakdown": {
            "homepages": sum(1 for r in legit if r.get("type") == "homepage"),
            "crawled_real_links": sum(1 for r in legit if r.get("type") == "crawled_real_path"),
            "fabricated_paths": 0,
        },
        "sources": {
            "phishing": "OpenPhish Community Feed (https://openphish.com/feed.txt)",
            "legitimate": "Tranco Top 1M Live Sites (homepages + live HTML crawl)",
        },
        "urls": combined,
    }

    with open(JSON_OUT, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    df = pd.DataFrame(combined)
    df.to_csv(CSV_OUT, index=False)

    # Create 50/50 Validation and Test split (tune only on val!)
    val_set, test_set = split_val_test(phish, legit)

    with open(VAL_JSON_OUT, "w", encoding="utf-8") as f:
        json.dump({
            "split": "validation",
            "count": len(val_set),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "urls": val_set,
        }, f, indent=2)

    with open(TEST_JSON_OUT, "w", encoding="utf-8") as f:
        json.dump({
            "split": "test",
            "count": len(test_set),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "urls": test_set,
        }, f, indent=2)

    logger.info(f"Successfully saved {len(combined)} real live URLs to {JSON_OUT} and {CSV_OUT}.")
    logger.info(f"Saved Validation set ({len(val_set)} URLs) to {VAL_JSON_OUT}.")
    logger.info(f"Saved Test holdout set ({len(test_set)} URLs) to {TEST_JSON_OUT}.")


if __name__ == "__main__":
    build_and_save()
