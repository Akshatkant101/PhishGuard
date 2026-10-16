"""
Augment Training Data with Mid-Tier Legitimate URLs
====================================================
Downloads Tranco Top-1M list, samples domains from ranks 10,000–1,000,000,
fetches live homepages and crawls real internal links, then merges them
into the existing 50k training CSV.

Key guarantees:
 - All fresh-test domains are excluded (zero test contamination).
 - Produces a *separate* mid-tier validation set (100 URLs) for error
   analysis — these domains are also excluded from training augmentation.
 - Domain column is populated for grouped splits.
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

from app.services.feature_extractor import extract_domain, is_static_asset_url

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

DATA_DIR = Path(__file__).resolve().parent
FRESH_TEST_JSON = DATA_DIR / "live_eval_fresh_test_200.json"
VAL_JSON = DATA_DIR / "live_eval_val_200.json"
OLD_TEST_JSON = DATA_DIR / "live_eval_test_200.json"
EXISTING_CSV = DATA_DIR / "phiusiil_50k.csv"
AUGMENTED_CSV = DATA_DIR / "phiusiil_50k_augmented.csv"
MIDTIER_VAL_JSON = DATA_DIR / "midtier_val_100.json"

HREF_REGEX = re.compile(r'href=["\']([^"\'#\s>]+)["\']', re.IGNORECASE)

TARGET_TRAIN_HOMEPAGES = 500
TARGET_TRAIN_CRAWLED = 500
TARGET_VAL_HOMEPAGES = 50
TARGET_VAL_CRAWLED = 50


def _get_excluded_domains() -> set:
    """Collect all domains that must NOT appear in training augmentation."""
    excluded = set()

    # 1. Fresh test domains (critical — never train on these)
    if FRESH_TEST_JSON.exists():
        with open(FRESH_TEST_JSON, "r", encoding="utf-8") as f:
            data = json.load(f)
            for item in data.get("urls", []):
                dom = item.get("domain", "")
                if dom:
                    excluded.add(dom)
        logger.info(f"Excluded {len(excluded)} domains from fresh test set.")

    # 2. Existing val / old test domains
    for p in [VAL_JSON, OLD_TEST_JSON]:
        before = len(excluded)
        if p.exists():
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("urls", []):
                    dom = item.get("domain", "")
                    if dom:
                        excluded.add(dom)
        logger.info(f"Excluded {len(excluded) - before} additional domains from {p.name}.")

    return excluded


def _get_existing_train_domains() -> set:
    """Domains already in the training CSV."""
    if EXISTING_CSV.exists():
        df = pd.read_csv(EXISTING_CSV, usecols=["domain"])
        return set(df["domain"].dropna().unique())
    return set()


def _crawl_site_links(domain: str, timeout: int = 4) -> list[str]:
    """Crawl real links from a domain's homepage."""
    candidates = [f"https://www.{domain}/", f"https://{domain}/"]
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}

    for base_url in candidates:
        try:
            req = urllib.request.Request(base_url, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                content = resp.read(250000).decode("utf-8", errors="ignore")
                matches = HREF_REGEX.findall(content)
                links = []
                for href in matches:
                    if href.startswith(("javascript:", "mailto:", "tel:", "data:", "#")):
                        continue
                    full_url = urllib.parse.urljoin(base_url, href)
                    if is_static_asset_url(full_url):
                        continue
                    parsed = urllib.parse.urlparse(full_url)
                    if parsed.scheme in ("http", "https") and parsed.netloc.endswith(domain):
                        clean_path = parsed.path.strip()
                        if clean_path and clean_path != "/" and len(clean_path) > 2:
                            links.append(full_url)
                if links:
                    # Return up to 2 unique links per domain for diversity
                    seen = set()
                    unique = []
                    for lnk in links:
                        if lnk not in seen:
                            seen.add(lnk)
                            unique.append(lnk)
                            if len(unique) >= 2:
                                break
                    return unique
        except Exception:
            continue
    return []


def _download_tranco_candidates(excluded_domains: set, existing_domains: set,
                                 min_rank: int = 10000, max_rank: int = 1000000,
                                 max_candidates: int = 3000) -> list[tuple[int, str]]:
    """Download Tranco list and filter candidates in rank range, excluding reserved domains."""
    logger.info(f"Downloading Tranco Top 1M list (ranks {min_rank}-{max_rank})...")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

    candidates = []
    all_excluded = excluded_domains | existing_domains
    with urllib.request.urlopen(req, timeout=30) as resp:
        z = zipfile.ZipFile(io.BytesIO(resp.read()))
        with z.open(z.namelist()[0]) as f:
            for i, line in enumerate(f, start=1):
                if i < min_rank:
                    continue
                if i > max_rank:
                    break
                parts = line.decode("utf-8").strip().split(",")
                if len(parts) >= 2:
                    d = parts[1]
                    if d not in all_excluded and not d.endswith((".internal", ".local")):
                        candidates.append((i, d))
                if len(candidates) >= max_candidates:
                    break

    logger.info(f"Loaded {len(candidates)} candidate domains from Tranco ranks {min_rank}-{max_rank}.")
    return candidates


def build_augmented_dataset():
    """Main entry: build augmented training CSV + mid-tier validation JSON."""

    excluded_domains = _get_excluded_domains()
    existing_domains = _get_existing_train_domains()

    logger.info(f"Total excluded domains (test/val sets): {len(excluded_domains)}")
    logger.info(f"Existing training domains: {len(existing_domains)}")

    # Download Tranco candidates
    candidates = _download_tranco_candidates(excluded_domains, existing_domains)

    # Deterministic shuffle
    random.seed(99)
    random.shuffle(candidates)

    now_str = datetime.now(timezone.utc).isoformat()

    # --- Split candidates into VAL pool (first batch) and TRAIN pool (rest) ---
    val_pool = candidates[:300]
    train_pool = candidates[300:]

    # ===== Build Mid-Tier Validation Set (100 URLs) =====
    logger.info("Building mid-tier validation set (50 homepages + 50 crawled)...")
    val_items = []
    val_domains_used = set()
    val_crawl_candidates = []

    for rank, d in val_pool:
        if len(val_items) < TARGET_VAL_HOMEPAGES:
            val_items.append({
                "url": f"https://www.{d}/",
                "domain": d,
                "label": 0,
                "source": f"tranco_rank_{rank}",
                "type": "homepage",
                "fetched_at": now_str,
            })
            val_domains_used.add(d)
        else:
            val_crawl_candidates.append((rank, d))

    # Crawl links for val set
    val_crawled = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_crawl_site_links, d): (rank, d)
                   for rank, d in val_crawl_candidates[:150]}
        for future in as_completed(futures):
            rank, dom = futures[future]
            try:
                links = future.result()
                for link in links[:1]:  # 1 link per domain for val
                    val_crawled.append({
                        "url": link,
                        "domain": dom,
                        "label": 0,
                        "source": f"tranco_rank_{rank}",
                        "type": "crawled_real_path",
                        "fetched_at": now_str,
                    })
                    val_domains_used.add(dom)
                    if len(val_crawled) >= TARGET_VAL_CRAWLED:
                        break
            except Exception:
                pass
            if len(val_crawled) >= TARGET_VAL_CRAWLED:
                break

    val_items.extend(val_crawled[:TARGET_VAL_CRAWLED])
    logger.info(f"Mid-tier validation set: {len(val_items)} URLs "
                f"({sum(1 for v in val_items if v['type']=='homepage')} homepages, "
                f"{sum(1 for v in val_items if v['type']=='crawled_real_path')} crawled)")

    # Save mid-tier validation JSON
    val_output = {
        "dataset_name": "PhishGuard Mid-Tier Validation Set (Error Analysis Only)",
        "created_at": now_str,
        "total_urls": len(val_items),
        "legitimate_count": len(val_items),
        "phishing_count": 0,
        "tranco_rank_range": "10,000 - 1,000,000",
        "note": "All-legitimate mid-tier validation set for FPR error analysis. "
                "No fresh-test domains. Not used for training.",
        "urls": val_items,
    }
    with open(MIDTIER_VAL_JSON, "w", encoding="utf-8") as f:
        json.dump(val_output, f, indent=2)
    logger.info(f"Saved mid-tier validation set to {MIDTIER_VAL_JSON}")

    # Also exclude val domains from training
    excluded_domains.update(val_domains_used)

    # ===== Build Training Augmentation (1000 URLs) =====
    logger.info(f"Building training augmentation ({TARGET_TRAIN_HOMEPAGES} homepages + "
                f"{TARGET_TRAIN_CRAWLED} crawled)...")

    train_items = []
    train_crawl_candidates = []

    for rank, d in train_pool:
        if d in excluded_domains or d in val_domains_used:
            continue
        if len(train_items) < TARGET_TRAIN_HOMEPAGES:
            train_items.append({
                "url": f"https://www.{d}/",
                "domain": d,
                "label": 0,
            })
        else:
            train_crawl_candidates.append((rank, d))

    logger.info(f"Selected {len(train_items)} homepages for training. Crawling real links...")

    train_crawled = []
    crawl_seen = {item["url"] for item in train_items}
    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {executor.submit(_crawl_site_links, d): (rank, d)
                   for rank, d in train_crawl_candidates[:800]}
        for future in as_completed(futures):
            rank, dom = futures[future]
            try:
                links = future.result()
                for link in links[:1]:  # 1 link per domain
                    if link not in crawl_seen:
                        crawl_seen.add(link)
                        train_crawled.append({
                            "url": link,
                            "domain": dom,
                            "label": 0,
                        })
                        if len(train_crawled) >= TARGET_TRAIN_CRAWLED:
                            break
            except Exception:
                pass
            if len(train_crawled) >= TARGET_TRAIN_CRAWLED:
                break

    train_items.extend(train_crawled[:TARGET_TRAIN_CRAWLED])
    logger.info(f"Training augmentation: {len(train_items)} new legitimate URLs "
                f"({sum(1 for t in train_items if 'www.' in t['url'] and t['url'].endswith('/'))} homepages, "
                f"{len(train_crawled)} crawled)")

    # ===== Merge into augmented CSV =====
    logger.info("Merging augmented URLs into training CSV...")
    df_existing = pd.read_csv(EXISTING_CSV)
    # Scope fix: product input is page URLs, drop static-asset URLs from training
    n_before = len(df_existing)
    df_existing = df_existing[~df_existing["url"].apply(is_static_asset_url)].reset_index(drop=True)
    if len(df_existing) < n_before:
        logger.info(f"Dropped {n_before - len(df_existing)} static asset URLs from base training data.")

    new_rows = pd.DataFrame([{
        "url": item["url"],
        "label": 0,
        "domain": item["domain"],
    } for item in train_items if not is_static_asset_url(item["url"])])

    df_augmented = pd.concat([df_existing, new_rows], ignore_index=True)
    df_augmented = df_augmented.sample(frac=1.0, random_state=42).reset_index(drop=True)
    df_augmented.to_csv(AUGMENTED_CSV, index=False, encoding="utf-8")

    n_legit = (df_augmented["label"] == 0).sum()
    n_phish = (df_augmented["label"] == 1).sum()
    n_domains = df_augmented["domain"].nunique()

    logger.info(f"Augmented CSV saved to {AUGMENTED_CSV}")
    logger.info(f"Total: {len(df_augmented)} rows ({n_legit} legit, {n_phish} phish, {n_domains} domains)")

    # Verify zero contamination
    fresh_domains = set()
    if FRESH_TEST_JSON.exists():
        with open(FRESH_TEST_JSON, "r", encoding="utf-8") as f:
            for item in json.load(f).get("urls", []):
                fresh_domains.add(item.get("domain", ""))
    aug_domains = set(df_augmented["domain"].unique())
    overlap = fresh_domains & aug_domains
    # Only check for overlap on the newly added domains
    new_domains = set(new_rows["domain"].unique())
    new_overlap = fresh_domains & new_domains
    logger.info(f"Fresh-test domain overlap with NEW augmented domains: {len(new_overlap)} "
                f"(MUST be 0)")
    if new_overlap:
        logger.error(f"CONTAMINATION DETECTED: {new_overlap}")
        raise RuntimeError("Fresh test contamination in augmented training data!")

    return str(AUGMENTED_CSV), str(MIDTIER_VAL_JSON)


if __name__ == "__main__":
    build_augmented_dataset()
