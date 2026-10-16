"""
Tests for the shared feature extractor.

Verifies:
- Feature count and naming consistency
- Individual feature correctness
- Edge cases (empty URLs, IP addresses, punycode, etc.)
- Batch extraction
- No path-length bias in feature design (ratio-based features)
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from app.services.feature_extractor import (
    FEATURE_NAMES,
    extract_domain,
    extract_features,
    extract_features_batch,
    get_feature_description,
    get_feature_names,
)


class TestFeatureCount:
    """Feature count and canonical ordering."""

    def test_feature_count_is_29(self):
        feats = extract_features("https://example.com")
        assert len(feats) == 29

    def test_feature_names_match_constant(self):
        feats = extract_features("https://example.com")
        assert list(feats.keys()) == FEATURE_NAMES

    def test_get_feature_names_returns_copy(self):
        names = get_feature_names()
        assert names == FEATURE_NAMES
        names.append("extra")
        assert len(get_feature_names()) == 29  # original unchanged


class TestSchemeFeatures:

    def test_https_detected(self):
        assert extract_features("https://example.com")["is_https"] == 1.0

    def test_http_detected(self):
        assert extract_features("http://example.com")["is_https"] == 0.0

    def test_no_scheme_defaults_to_http(self):
        assert extract_features("example.com")["is_https"] == 0.0


class TestDomainFeatures:

    def test_domain_length(self):
        feats = extract_features("https://example.com")
        assert feats["domain_length"] == len("example.com")

    def test_hostname_length_with_subdomain(self):
        feats = extract_features("https://sub.example.com")
        assert feats["hostname_length"] == len("sub.example.com")

    def test_dot_count(self):
        feats = extract_features("https://a.b.c.example.com")
        assert feats["domain_dot_count"] == 4.0

    def test_hyphen_count(self):
        feats = extract_features("https://my-cool-site.com")
        assert feats["domain_hyphen_count"] == 2.0

    def test_digit_count_and_ratio(self):
        feats = extract_features("https://abc123.com")
        assert feats["domain_digit_count"] == 3.0
        assert feats["domain_digit_ratio"] > 0

    def test_entropy_positive(self):
        feats = extract_features("https://google.com")
        assert feats["domain_entropy"] > 0

    def test_subdomain_count(self):
        assert extract_features("https://example.com")["subdomain_count"] == 0
        assert extract_features("https://www.example.com")["subdomain_count"] == 0
        assert extract_features("https://login.example.com")["subdomain_count"] == 1
        assert extract_features("https://a.b.example.com")["subdomain_count"] == 2

    def test_ip_address_detected(self):
        feats = extract_features("http://192.168.1.1/login")
        assert feats["has_ip_address"] == 1.0

    def test_non_ip_not_detected(self):
        feats = extract_features("https://google.com")
        assert feats["has_ip_address"] == 0.0

    def test_suspicious_tld(self):
        # Learned continuous rates or binary fallback
        tk_rate = extract_features("http://evil.tk")["suspicious_tld"]
        com_rate = extract_features("https://google.com")["suspicious_tld"]
        assert tk_rate > 0.5
        assert tk_rate > com_rate

    def test_punycode(self):
        assert extract_features("http://xn--e1afsy.xn--p1ai")["has_punycode"] == 1.0
        assert extract_features("https://google.com")["has_punycode"] == 0.0


class TestBrandDetection:

    def test_brand_in_domain(self):
        # Typosquatted / compound brand domain
        feats = extract_features("https://paypal-update.com/login")
        assert feats["brand_in_domain"] == 1.0
        assert feats["brand_impersonation"] == 0.0

    def test_official_brand_domain_not_penalized(self):
        # Official brand domain should NEVER be flagged as brand_in_domain
        feats = extract_features("https://paypal.com/login")
        assert feats["brand_in_domain"] == 0.0
        assert feats["brand_subdomain"] == 0.0 if "brand_subdomain" in feats else True
        assert feats["brand_impersonation"] == 0.0

    def test_brand_impersonation(self):
        feats = extract_features("http://paypal.evil-login.tk")
        assert feats["brand_in_subdomain"] == 1.0
        assert feats["brand_in_domain"] == 0.0
        assert feats["brand_impersonation"] == 1.0

    def test_no_brand(self):
        feats = extract_features("https://example.com")
        assert feats["brand_in_subdomain"] == 0.0
        assert feats["brand_in_domain"] == 0.0
        assert feats["brand_impersonation"] == 0.0


class TestURLLevelFeatures:

    def test_at_symbol(self):
        feats = extract_features("http://legit.com@evil.com/login")
        assert feats["has_at_symbol"] == 1.0

    def test_double_slash_redirect(self):
        feats = extract_features("http://evil.com//redirect//login")
        assert feats["has_double_slash_redirect"] == 1.0

    def test_special_char_ratio_is_ratio(self):
        feats = extract_features("https://example.com/path")
        assert 0 <= feats["url_special_char_ratio"] <= 1

    def test_digit_ratio_is_ratio(self):
        feats = extract_features("https://example.com/path123")
        assert 0 <= feats["url_digit_ratio"] <= 1

    def test_shortened_url(self):
        assert extract_features("https://bit.ly/abc123")["is_shortened"] == 1.0
        assert extract_features("https://google.com")["is_shortened"] == 0.0


class TestPathFeatures:

    def test_has_path(self):
        assert extract_features("https://example.com/page")["has_path"] == 1.0
        assert extract_features("https://example.com/")["has_path"] == 0.0
        assert extract_features("https://example.com")["has_path"] == 0.0

    def test_path_depth(self):
        feats = extract_features("https://example.com/a/b/c")
        assert feats["path_depth"] == 3.0

    def test_path_digit_ratio_is_ratio(self):
        feats = extract_features("https://example.com/123abc")
        assert 0 <= feats["path_digit_ratio"] <= 1

    def test_suspicious_extension(self):
        assert extract_features("http://evil.com/login.php")["path_has_suspicious_ext"] == 1.0
        assert extract_features("https://example.com/page.html")["path_has_suspicious_ext"] == 0.0


class TestQueryFeatures:

    def test_query_param_count(self):
        feats = extract_features("https://example.com/s?q=test&page=1&lang=en")
        assert feats["query_param_count"] == 3.0

    def test_query_length_ratio_is_ratio(self):
        feats = extract_features("https://example.com/?q=test")
        assert 0 <= feats["query_length_ratio"] <= 1

    def test_has_fragment(self):
        assert extract_features("https://example.com/page#section")["has_fragment"] == 1.0
        assert extract_features("https://example.com/page")["has_fragment"] == 0.0


class TestEdgeCases:

    def test_empty_string(self):
        feats = extract_features("")
        assert len(feats) == 29
        assert all(isinstance(v, float) for v in feats.values())

    def test_just_domain(self):
        feats = extract_features("example.com")
        assert len(feats) == 29

    def test_very_long_url(self):
        long_url = "https://example.com/" + "a" * 5000
        feats = extract_features(long_url)
        assert len(feats) == 29

    def test_unicode_url(self):
        feats = extract_features("https://例え.jp/ページ")
        assert len(feats) == 29

    def test_all_values_are_float(self):
        feats = extract_features("https://example.com/page?q=test#section")
        for k, v in feats.items():
            assert isinstance(v, float), f"{k} is {type(v)}, expected float"


class TestBatchExtraction:

    def test_batch_returns_dataframe(self, legit_urls):
        df = extract_features_batch(legit_urls)
        assert isinstance(df, pd.DataFrame)
        assert len(df) == len(legit_urls)
        assert list(df.columns) == FEATURE_NAMES

    def test_batch_matches_single(self, legit_urls):
        df = extract_features_batch(legit_urls)
        for i, url in enumerate(legit_urls):
            single = extract_features(url)
            for col in FEATURE_NAMES:
                assert df.iloc[i][col] == single[col], (
                    f"Mismatch for {url} feature {col}"
                )


class TestDomainExtraction:

    def test_simple_domain(self):
        assert extract_domain("https://www.google.com/search") == "google.com"

    def test_co_uk_domain(self):
        assert extract_domain("https://www.bbc.co.uk/news") == "bbc.co.uk"

    def test_ip_domain(self):
        assert extract_domain("http://192.168.1.1/login") == "192.168.1.1"

    def test_bare_domain(self):
        assert extract_domain("example.com") == "example.com"


class TestRatioFeaturesPreventBias:
    """Verify that ratio-based features don't leak absolute path length."""

    def test_same_domain_different_paths_similar_domain_features(self):
        """Domain features should be identical regardless of path length."""
        short = extract_features("https://example.com/")
        long = extract_features("https://example.com/a/b/c/d/e/f?q=1&r=2#s")

        domain_features = [
            "domain_length", "hostname_length", "domain_dot_count",
            "domain_hyphen_count", "domain_digit_count", "domain_digit_ratio",
            "domain_entropy", "subdomain_count", "has_ip_address",
            "suspicious_tld", "tld_length", "has_punycode",
        ]
        for feat in domain_features:
            assert short[feat] == long[feat], (
                f"{feat} differs between short and long path URLs"
            )

    def test_path_features_are_ratios_not_counts(self):
        """Path features should be bounded [0, 1] for ratio features."""
        url = "https://example.com/path/with/123/parts/and-hyphens"
        feats = extract_features(url)
        assert 0 <= feats["path_digit_ratio"] <= 1
        assert 0 <= feats["path_hyphen_ratio"] <= 1
        assert 0 <= feats["url_digit_ratio"] <= 1
        assert 0 <= feats["url_special_char_ratio"] <= 1
        assert 0 <= feats["query_length_ratio"] <= 1


class TestFeatureDescriptions:

    def test_all_features_have_descriptions(self):
        for name in FEATURE_NAMES:
            desc = get_feature_description(name)
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_unknown_feature_returns_formatted_name(self):
        desc = get_feature_description("unknown_feature_xyz")
        assert desc == "Unknown Feature Xyz"
