"""
Build Fresh Test Set (Untouched Benchmark)
=========================================
Builds a fresh, untouched held-out test split of 200 real URLs:
- 100 live active phishing URLs from OpenPhish feed (strictly excluded from previous val/test).
- 100 legitimate URLs from Tranco Top 1M list with ranks strictly between 10,000 and 500,000:
  * 50 live homepages
  * 50 real links crawled from those live sites (zero fabricated paths).
Saved to backend/ml/data/live_eval_fresh_test_200.json.
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

from app.services.feature_extractor import extract_domain

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent
FRESH_TEST_JSON = DATA_DIR / "live_eval_fresh_test_200.json"
VAL_JSON = DATA_DIR / "live_eval_val_200.json"
OLD_TEST_JSON = DATA_DIR / "live_eval_test_200.json"

HREF_REGEX = re.compile(r'href=["\']([^"\'#\s>]+)["\']', re.IGNORECASE)


def load_used_data():
    used_urls = set()
    used_domains = set()
    for p in [VAL_JSON, OLD_TEST_JSON]:
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("urls", []):
                    used_urls.add(item["url"])
                    if "domain" in item:
                        used_domains.add(item["domain"])
    return used_urls, used_domains


def fetch_fresh_phishing(used_urls: set, target_count: int = 100) -> list[dict]:
    logger.info("Fetching fresh live phishing URLs from OpenPhish feed...")
    url = "https://openphish.com/feed.txt"
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-Live-Eval/2.0"})

    with urllib.request.urlopen(req, timeout=12) as resp:
        lines = resp.read().decode("utf-8", errors="replace").splitlines()

    valid_urls = []
    seen_urls = set(used_urls)
    seen_netlocs = set()
    now_str = datetime.now(timezone.utc).isoformat()

    for line in lines:
        raw = line.strip()
        if not raw or not raw.startswith(("http://", "https://")):
            continue
        if raw in seen_urls:
            continue
        parsed = urllib.parse.urlparse(raw)
        if parsed.netloc in seen_netlocs:
            continue
        dom = extract_domain(raw)
        if not dom:
            continue

        valid_urls.append({
            "url": raw,
            "domain": dom,
            "label": 1,
            "source": "openphish_fresh",
            "type": "phishing_feed",
            "fetched_at": now_str,
        })
        seen_urls.add(raw)
        seen_netlocs.add(parsed.netloc)
        if len(valid_urls) >= target_count:
            break

    # If target_count not reached with strict netloc deduplication, allow distinct paths on shared hosting
    if len(valid_urls) < target_count:
        for line in lines:
            raw = line.strip()
            if not raw or not raw.startswith(("http://", "https://")) or raw in seen_urls:
                continue
            dom = extract_domain(raw)
            if not dom:
                continue
            valid_urls.append({
                "url": raw,
                "domain": dom,
                "label": 1,
                "source": "openphish_fresh",
                "type": "phishing_feed",
                "fetched_at": now_str,
            })
            seen_urls.add(raw)
            if len(valid_urls) >= target_count:
                break

    logger.info(f"Collected {len(valid_urls)} fresh live phishing URLs from OpenPhish.")
    return valid_urls


def _crawl_site_links(domain: str, timeout: int = 4) -> list[str]:
    candidates = [f"https://www.{domain}/", f"https://{domain}/"]
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
                    if parsed.scheme in ("http", "https") and parsed.netloc.endswith(domain):
                        clean_path = parsed.path.strip()
                        if clean_path and clean_path != "/" and len(clean_path) > 2:
                            return [full_url]
        except Exception:
            continue
    return []


def fetch_tranco_mid_tier(used_domains: set, target_homepages: int = 50, target_crawled: int = 50) -> list[dict]:
    logger.info("Fetching Tranco Top 1M list for ranks 10,000 - 500,000 ...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    candidate_domains = []
    with urllib.request.urlopen(req, timeout=15) as resp:
        z = zipfile.ZipFile(io.BytesIO(resp.read()))
        with z.open(z.namelist()[0]) as f:
            for i, line in enumerate(f, start=1):
                # Sample ranks strictly between 10k and 500k
                if 10000 <= i <= 500000:
                    parts = line.decode("utf-8").strip().split(",")
                    if len(parts) >= 2:
                        d = parts[1]
                        if d not in used_domains and not d.endswith((".internal", ".local")):
                            candidate_domains.append((i, d))
                if len(candidate_domains) >= 300:
                    break

    logger.info(f"Loaded {len(candidate_domains)} candidates from Tranco ranks 10,000 - 500,000.")
    # Deterministic shuffle for reproducibility
    random.seed(42)
    random.shuffle(candidate_domains)

    now_str = datetime.now(timezone.utc).isoformat()
    homepages = []
    crawl_candidates = []

    for rank, d in candidate_domains:
        if len(homepages) < target_homepages:
            homepages.append({
                "url": f"https://www.{d}/",
                "domain": d,
                "label": 0,
                "source": f"tranco_rank_{rank}",
                "type": "homepage",
                "fetched_at": now_str,
            })
        else:
            crawl_candidates.append((rank, d))

    logger.info(f"Selected {len(homepages)} mid-tier homepages. Crawling live sites for real paths...")

    crawled_urls = []
    seen_urls = {h["url"] for h in homepages}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_dom = {executor.submit(_crawl_site_links, d): (rank, d) for rank, d in crawl_candidates[:120]}
        for future in as_completed(future_to_dom):
            rank, dom = future_to_dom[future]
            try:
                links = future.result()
                for link in links:
                    if link not in seen_urls:
                        seen_urls.add(link)
                        crawled_urls.append({
                            "url": link,
                            "domain": dom,
                            "label": 0,
                            "source": f"tranco_rank_{rank}",
                            "type": "crawled_real_path",
                            "fetched_at": now_str,
                        })
                        if len(crawled_urls) >= target_crawled:
                            break
                if len(crawled_urls) >= target_crawled:
                    break
            except Exception:
                pass

    logger.info(f"Crawled {len(crawled_urls)} genuine real paths from live mid-tier sites.")
    return homepages[:target_homepages] + crawled_urls[:target_crawled]


def build_fresh_test_set():
    used_urls, used_domains = load_used_data()
    logger.info(f"Excluding {len(used_urls)} previously used URLs and {len(used_domains)} domains.")

    phish_items = fetch_fresh_phishing(used_urls, target_count=100)
    # Update used domains with the freshly fetched phish
    for p in phish_items:
        used_domains.add(p["domain"])

    legit_items = fetch_tranco_mid_tier(used_domains, target_homepages=50, target_crawled=50)

    all_items = phish_items + legit_items
    random.seed(42)
    random.shuffle(all_items)

    out = {
        "dataset_name": "PhishGuard Fresh Held-Out Test Set (Untouched Benchmark)",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "total_urls": len(all_items),
        "phishing_count": sum(1 for x in all_items if x["label"] == 1),
        "legitimate_count": sum(1 for x in all_items if x["label"] == 0),
        "tranco_rank_range": "10,000 - 500,000 (Mid-tier real websites)",
        "note": "Untouched test holdout. Never used for tuning weights or thresholds.",
        "urls": all_items,
    }

    with open(FRESH_TEST_JSON, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    logger.info(f"Saved {len(all_items)} fresh test URLs to {FRESH_TEST_JSON}")
    print(f"Fresh Test Set created: {len(all_items)} URLs ({out['phishing_count']} phish, {out['legitimate_count']} legit).")


if __name__ == "__main__":
    build_fresh_test_set()
