"""Shared test fixtures for PhishGuard test suite."""

import sys
from pathlib import Path

import pytest

# Ensure backend root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


@pytest.fixture
def legit_urls():
    """Legitimate URL samples covering diverse patterns."""
    return [
        "https://www.google.com/search?q=test",
        "https://github.com/user/repo",
        "https://stackoverflow.com/questions/12345/how-to-test",
        "https://en.wikipedia.org/wiki/Python",
        "https://amazon.com/dp/B08N5WRWNW",
        "https://www.bbc.co.uk/news/technology",
        "https://harvard.edu/about",
        "https://nasa.gov/missions/artemis",
        "http://example.com",
        "https://docs.python.org/3/library/json.html",
    ]


@pytest.fixture
def phish_urls():
    """Phishing URL samples covering common attack patterns."""
    return [
        "http://g00gle-login.tk/signin",
        "http://paypa1-secure.ml/verify",
        "http://paypal.secure-login.xyz/auth",
        "http://45.33.32.156/login",
        "http://amaz0n-verify.ga/account/confirm?id=abc",
        "http://apple.id-confirmation.ml/secure",
        "http://micros0ft-auth.cf/",
        "http://legitimate-site.com@evil.tk/login",
        "http://secure-update-account.tk/billing",
        "http://faceb00k-secure.top/recover/password",
    ]


@pytest.fixture
def sample_csv(tmp_path, legit_urls, phish_urls):
    """Write a small CSV for pipeline tests."""
    import csv

    path = tmp_path / "test_urls.csv"
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["url", "label"])
        for u in legit_urls:
            writer.writerow([u, 0])
        for u in phish_urls:
            writer.writerow([u, 1])
    return path
