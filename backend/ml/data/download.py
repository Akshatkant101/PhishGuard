"""
PhiUSIIL Real Dataset Downloader & Balancer
===========================================
Downloads the real-world PhiUSIIL Phishing URL Dataset (235,795 URLs),
balances the legitimate class with realistic web paths to avoid
path-length bias, and creates a verified 50,000-URL benchmark.
"""

from pathlib import Path
import urllib.request
import numpy as np
import pandas as pd
from app.services.feature_extractor import extract_domain

DATA_DIR = Path(__file__).resolve().parent
RAW_CSV = DATA_DIR / "phiusiil_raw.csv"
OUTPUT_CSV = DATA_DIR / "phiusiil_50k.csv"
REMOTE_URL = "https://raw.githubusercontent.com/elaaatif/DATA-MINING-PhiUSIIL-Phishing-URL/main/PhiUSIIL_Phishing_URL_Dataset.csv"

REALISTIC_LEGIT_PATHS = [
    "/about", "/contact", "/privacy-policy", "/terms-of-service", "/faq",
    "/products", "/services", "/blog", "/news/latest", "/articles/index.html",
    "/support/help-center", "/docs/overview/v2", "/search?q=account+settings",
    "/category/item-detail-10294.html", "/resources/whitepaper-guide.pdf",
    "/company/leadership-team", "/events/2024/annual-developer-conference",
    "/shop/cart/checkout", "/pricing/enterprise-plans", "/careers/open-positions/apply",
    "/media/press-releases/announcement-2024", "/community/forums/thread/discussion?page=2",
    "/security/disclosure/policy", "/solutions/cloud-infrastructure", "/portal/dashboard"
]


def download_raw_dataset() -> Path:
    """Download PhiUSIIL raw dataset if not present."""
    if not RAW_CSV.exists() or RAW_CSV.stat().st_size < 1000000:
        print(f"Downloading PhiUSIIL dataset (~56MB) from {REMOTE_URL} ...")
        urllib.request.urlretrieve(REMOTE_URL, RAW_CSV)
        print("Download complete.")
    return RAW_CSV


def generate_sample_dataset(
    n_legit: int = 25000,
    n_phish: int = 25000,
    seed: int = 42,
    output_path: Path | str | None = None,
) -> Path:
    """Generate a balanced dataset with specified counts, sampled from real PhiUSIIL URLs."""
    raw_path = download_raw_dataset()
    df = pd.read_csv(raw_path, usecols=["URL", "label"], encoding="utf-8")

    phish_pool = df[df["label"] == 0].copy()
    legit_pool = df[df["label"] == 1].copy()

    phish_sampled = phish_pool.sample(n=min(n_phish, len(phish_pool)), random_state=seed).copy()
    legit_sampled = legit_pool.sample(n=min(n_legit, len(legit_pool)), random_state=seed).copy()

    rng = np.random.RandomState(seed)
    augmented_legit = []
    for u in legit_sampled["URL"].tolist():
        # Represent both www and bare domains in legitimate URLs
        if rng.rand() < 0.50:
            if u.startswith("https://www."):
                u = "https://" + u[len("https://www."):]
            elif u.startswith("http://www."):
                u = "http://" + u[len("http://www."):]
        if rng.rand() < 0.35:
            path = rng.choice(REALISTIC_LEGIT_PATHS)
            u = u.rstrip("/") + path
        augmented_legit.append(u)
    legit_sampled["URL"] = augmented_legit

    # PRD standard: 1 = Phishing, 0 = Legitimate
    phish_sampled["label"] = 1
    legit_sampled["label"] = 0

    combined = pd.concat([phish_sampled[["URL", "label"]], legit_sampled[["URL", "label"]]])
    combined = combined.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    combined.rename(columns={"URL": "url"}, inplace=True)
    combined["domain"] = [extract_domain(u) for u in combined["url"]]

    out = Path(output_path) if output_path else OUTPUT_CSV
    out.parent.mkdir(parents=True, exist_ok=True)
    combined.to_csv(out, index=False, encoding="utf-8")
    return out


def prepare_balanced_50k(sample_size: int = 50000, seed: int = 42) -> pd.DataFrame:
    """Generate default 50k benchmark dataset."""
    out = generate_sample_dataset(
        n_legit=sample_size // 2,
        n_phish=sample_size // 2,
        seed=seed,
        output_path=OUTPUT_CSV,
    )
    return pd.read_csv(out)


if __name__ == "__main__":
    prepare_balanced_50k()
