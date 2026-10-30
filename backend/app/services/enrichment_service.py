"""
PhishGuard Stage 2 Live Threat Intelligence & Content Enrichment Service
========================================================================
Performs secure, live multi-signal enrichment:
1. Live TLS Certificate Inspection (validity, issuer, remaining days).
2. DNS Resolution (IPv4/IPv6 address resolution, host validation).
3. WHOIS / RDAP Domain Age (<30 day newly registered domain detection).
4. SSRF-Safe Content Inspection:
   - Validates IP against private/loopback/link-local/multicast IP ranges.
   - Re-validates EVERY redirect hop before following.
   - DNS Rebinding protection via socket-level address guard.
   - Response size strictly capped (max bytes stream cap).
   - Strict short timeout (2.0s maximum).
   - Extracts page features: has_password_field, has_external_form_action,
     has_iframe, external_link_ratio, page_title.
5. Optional Google Safe Browsing v4 Threat Lookup (only runs if API key configured).
6. Documented Rule-Based Adjustments:
   - Documented point adjustments based on live signals.
   - Separated cleanly from ML SHAP feature attributions.
7. Graceful Fallback: Any failure immediately falls back to the lexical model.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import ipaddress
import logging
import re
import socket
import ssl
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, urljoin

import httpx
from app.config import settings

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────
#  SSRF Protection: IP & DNS Rebinding Guard
# ──────────────────────────────────────────────────────────

def is_ssrf_safe_ip(ip_str: str) -> bool:
    """
    Strictly block private, loopback, link-local, multicast, or reserved IPs.
    Handles IPv4, IPv6, and IPv4-mapped IPv6 addresses.
    Also blocks RFC 6598 Carrier-Grade NAT (100.64.0.0/10) and cloud metadata.
    """
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
            ip = ip.ipv4_mapped

        # Standard RFC blocking
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            return False

        # Carrier Grade NAT (100.64.0.0/10)
        cgnat_net = ipaddress.ip_network("100.64.0.0/10")
        if ip.version == 4 and ip in cgnat_net:
            return False

        # Cloud Metadata IP (169.254.169.254)
        if str(ip) == "169.254.169.254":
            return False

        return True
    except (ValueError, AttributeError):
        return False


class SSRFGuard:
    """
    Context manager that guards socket.getaddrinfo to prevent DNS rebinding attacks.
    Every DNS resolution attempted by underlying HTTP or socket libraries is checked.
    If any IP is non-public/forbidden, a PermissionError is raised immediately.
    """
    def __init__(self):
        self._orig_getaddrinfo = socket.getaddrinfo

    def __enter__(self):
        def guarded_getaddrinfo(host, port, *args, **kwargs):
            results = self._orig_getaddrinfo(host, port, *args, **kwargs)
            for res in results:
                ip_addr = res[4][0]
                if not is_ssrf_safe_ip(ip_addr):
                    raise PermissionError(f"SSRF Blocked: DNS resolved to forbidden address {ip_addr}")
            return results

        socket.getaddrinfo = guarded_getaddrinfo
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        socket.getaddrinfo = self._orig_getaddrinfo


@dataclass
class RuleAdjustment:
    signal: str
    points: float
    description: str
    direction: str  # "suspicious" | "benign"


def _match_wildcard_san(pattern: str, hostname: str) -> bool:
    """Match hostname against certificate SAN pattern including wildcards & apex."""
    pat = pattern.lower().strip()
    host = hostname.lower().strip()
    if pat == host:
        return True
    if pat.startswith("*."):
        suffix = pat[2:]
        # Apex match: *.googlevideo.com covers googlevideo.com
        if host == suffix:
            return True
        # Subdomain match: *.googlevideo.com covers r1.googlevideo.com
        if host.endswith("." + suffix):
            return True
    return False


class EnrichmentService:
    def __init__(self):
        self.timeout = settings.ENRICHMENT_TIMEOUT_SECONDS
        self.max_bytes = settings.ENRICHMENT_MAX_CONTENT_BYTES
        self.safe_browsing_key = settings.GOOGLE_SAFE_BROWSING_KEY
        self.max_redirect_hops = 3
        self._dns_cache: Dict[str, Any] = {}
        self._tls_cache: Dict[str, Any] = {}
        self._age_cache: Dict[str, Any] = {}

    def _populate_cert_details(self, cert: dict, result: dict):
        issuer_dict = dict(x[0] for x in cert.get("issuer", []))
        org_name = issuer_dict.get("organizationName") or issuer_dict.get("commonName")
        result["issuer"] = org_name

        not_after_str = cert.get("notAfter")
        not_before_str = cert.get("notBefore")
        now = datetime.now(timezone.utc)

        if not_after_str:
            try:
                not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result["days_until_expiration"] = max(0, (not_after - now).days)
            except Exception:
                pass

        if not_before_str:
            try:
                not_before = datetime.strptime(not_before_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                result["cert_age_days"] = max(0, (now - not_before).days)
            except Exception:
                pass

        if result["days_until_expiration"] is not None and result["days_until_expiration"] < 14:
            result["is_short_lived"] = True

    # ──────────────────────────────────────────────────────────
    #  1. Live TLS Certificate Inspection (Standard SSL & SNI)
    # ──────────────────────────────────────────────────────────
    def check_tls(self, domain: str) -> Dict[str, Any]:
        """Inspect live TLS certificate on port 443 with standard SSL hostname verification & SNI."""
        result = {
            "tls_active": False,
            "tls_valid": False,
            "issuer": None,
            "days_until_expiration": None,
            "cert_age_days": None,
            "is_short_lived": False,
            "error": None,
        }
        if not domain or domain.replace(".", "").isdigit():
            return result

        if domain in self._tls_cache:
            return self._tls_cache[domain]

        # Standard SNI candidates: try primary host, fallback to canonical www/apex alias
        candidates = [domain]
        if not domain.startswith("www."):
            candidates.append(f"www.{domain}")
        elif domain.startswith("www.") and len(domain) > 4:
            candidates.append(domain[4:])

        last_error = None
        for cand in candidates:
            try:
                # Standard Python SSL context with native RFC 6125 certificate and hostname validation
                ctx = ssl.create_default_context()
                ctx.check_hostname = True
                ctx.verify_mode = ssl.CERT_REQUIRED

                with socket.create_connection((cand, 443), timeout=self.timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=cand) as ssock:
                        cert = ssock.getpeercert()
                        result["tls_active"] = True
                        result["tls_valid"] = True
                        self._populate_cert_details(cert, result)
                        self._tls_cache[domain] = result
                        return result
            except ssl.SSLCertVerificationError as e:
                result["tls_active"] = True
                last_error = getattr(e, "verify_message", None) or getattr(e, "strerror", None) or str(e)
            except Exception as e:
                last_error = str(e)

        if result["tls_active"] and not result["tls_valid"]:
            result["error"] = f"SSL Certificate Verification Failed: {last_error}"
        else:
            result["error"] = last_error

        self._tls_cache[domain] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  2. DNS & Host Resolution
    # ──────────────────────────────────────────────────────────
    def check_dns(self, domain: str) -> Dict[str, Any]:
        """Resolve domain IP addresses and check reachability."""
        result = {
            "resolves": False,
            "ips": [],
            "error": None,
        }
        if not domain:
            result["error"] = "No domain provided"
            return result

        if domain in self._dns_cache:
            return self._dns_cache[domain]

        candidates = [domain]
        if not domain.startswith("www."):
            candidates.append(f"www.{domain}")
        elif domain.startswith("www.") and len(domain) > 4:
            candidates.append(domain[4:])

        orig_timeout = socket.getdefaulttimeout()
        for cand in candidates:
            try:
                socket.setdefaulttimeout(self.timeout)
                try:
                    addr_info = socket.getaddrinfo(cand, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    ips = list(set([item[4][0] for item in addr_info]))
                    if ips:
                        result["resolves"] = True
                        result["ips"] = ips
                        result["error"] = None
                        self._dns_cache[domain] = result
                        return result
                finally:
                    socket.setdefaulttimeout(orig_timeout)
            except Exception as e:
                result["error"] = f"DNS resolution failed: {e}"

        self._dns_cache[domain] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  3. SSRF-Safe Page Content Inspection with Redirect Validation & Capped Size
    # ──────────────────────────────────────────────────────────
    def inspect_page_content(self, url: str, domain: str, resolved_ips: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Fetch and inspect page content with:
        - Strict SSRF check on initial host and EVERY redirect hop.
        - DNS Rebinding guard at the socket layer.
        - Strictly capped response stream size (max_bytes) to prevent resource exhaustion.
        - Short timeout.
        """
        result = {
            "content_fetched": False,
            "has_password_field": False,
            "has_external_form_action": False,
            "has_iframe": False,
            "external_link_ratio": 0.0,
            "page_title": None,
            "error": None,
            "redirect_count": 0,
        }

        # Check initial resolved IPs if provided
        if resolved_ips:
            for ip in resolved_ips:
                if not is_ssrf_safe_ip(ip):
                    result["error"] = f"SSRF Blocked: Target resolved to forbidden IP {ip}"
                    return result

        curr_url = url
        headers = {
            "User-Agent": "PhishGuard-Security-Radar/1.0 (Safe Crawler)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        try:
            with httpx.Client(timeout=self.timeout, follow_redirects=False) as client:
                for hop in range(self.max_redirect_hops + 1):
                    parsed = urlparse(curr_url)
                    if parsed.scheme not in ("http", "https"):
                        result["error"] = f"SSRF Blocked: Prohibited URL scheme '{parsed.scheme}'"
                        return result

                    target_host = parsed.hostname
                    if not target_host:
                        result["error"] = f"Invalid host in target URL: {curr_url}"
                        return result

                    # DNS & SSRF Validation for current hop
                    try:
                        addr_info = socket.getaddrinfo(target_host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                        hop_ips = list(set([item[4][0] for item in addr_info]))
                        for ip in hop_ips:
                            if not is_ssrf_safe_ip(ip):
                                result["error"] = f"SSRF Blocked: Hop {hop} ({target_host}) resolved to forbidden IP {ip}"
                                return result
                    except Exception as dns_err:
                        result["error"] = f"DNS resolution failed at hop {hop} ({target_host}): {dns_err}"
                        return result

                    # Perform request inside SSRFGuard (protects against DNS rebinding)
                    with SSRFGuard():
                        with client.stream("GET", curr_url, headers=headers) as resp:
                            result["redirect_count"] = hop

                            # Handle Redirects
                            if resp.status_code in (301, 302, 303, 307, 308):
                                loc = resp.headers.get("Location")
                                if not loc:
                                    result["error"] = f"Redirect status {resp.status_code} with no Location header"
                                    return result
                                # Re-validate next hop
                                curr_url = urljoin(curr_url, loc)
                                continue

                            # Handle 200 OK
                            if resp.status_code == 200:
                                # Stream capped response body
                                raw_bytes = bytearray()
                                for chunk in resp.iter_bytes(chunk_size=8192):
                                    raw_bytes.extend(chunk)
                                    if len(raw_bytes) >= self.max_bytes:
                                        break

                                html_text_raw = raw_bytes[:self.max_bytes].decode("utf-8", errors="replace")
                                html_text = html_text_raw.lower()
                                result["content_fetched"] = True

                                # 1. Password input field
                                if 'type="password"' in html_text or "type='password'" in html_text:
                                    result["has_password_field"] = True

                                # 2. External form action
                                form_actions = re.findall(r'<form[^>]*action=["\']([^"\']+)["\']', html_text)
                                for action in form_actions:
                                    if action.startswith(("http://", "https://")):
                                        action_host = urlparse(action).hostname or ""
                                        if domain not in action_host and action_host not in domain:
                                            result["has_external_form_action"] = True
                                            break

                                # 3. Iframe
                                if "<iframe" in html_text:
                                    result["has_iframe"] = True

                                # 4. External link ratio
                                all_links = re.findall(r'<a[^>]*href=["\']([^"\']+)["\']', html_text)
                                if all_links:
                                    external_links = [
                                        l for l in all_links
                                        if l.startswith(("http://", "https://")) and urlparse(l).hostname and domain not in urlparse(l).hostname.lower()
                                    ]
                                    result["external_link_ratio"] = round(len(external_links) / len(all_links), 4)

                                # 5. Title (Preserves original case)
                                title_match = re.search(r'<title[^>]*>([^<]+)</title>', html_text_raw, flags=re.IGNORECASE)
                                if title_match:
                                    result["page_title"] = title_match.group(1).strip()[:100]

                                return result

                            # Other non-redirect, non-200 status
                            result["error"] = f"HTTP {resp.status_code} returned by host"
                            return result

                result["error"] = f"Exceeded maximum redirect hops ({self.max_redirect_hops})"
        except PermissionError as pe:
            result["error"] = str(pe)
        except Exception as e:
            result["error"] = f"Page fetch timed out or unavailable: {e}"

        return result

    # ──────────────────────────────────────────────────────────
    #  4. WHOIS / RDAP Domain Age
    # ──────────────────────────────────────────────────────────
    def check_domain_age(self, domain: str) -> Dict[str, Any]:
        """Query RDAP for domain registration date and age in days."""
        result = {
            "domain_age_days": None,
            "created_date": None,
            "is_newly_registered": False,
            "error": None,
        }
        if not domain or domain.replace(".", "").isdigit():
            return result

        if domain in self._age_cache:
            return self._age_cache[domain]

        try:
            rdap_url = f"https://rdap.org/domain/{domain}"
            with httpx.Client(timeout=self.timeout, follow_redirects=True) as client:
                resp = client.get(rdap_url)
                if resp.status_code == 200:
                    data = resp.json()
                    events = data.get("events", [])
                    for ev in events:
                        if ev.get("eventAction") == "registration":
                            date_str = ev.get("eventDate", "")[:10]
                            reg_date = datetime.strptime(date_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            age_days = (now - reg_date).days
                            result["created_date"] = date_str
                            result["domain_age_days"] = age_days
                            result["is_newly_registered"] = age_days < 30
                            break
        except Exception as e:
            result["error"] = f"RDAP domain age lookup unavailable: {e}"

        self._age_cache[domain] = result
        return result

    # ──────────────────────────────────────────────────────────
    #  5. Google Safe Browsing Lookup (Optional Layer)
    # ──────────────────────────────────────────────────────────
    def check_safe_browsing(self, url: str) -> Dict[str, Any]:
        """Query Google Safe Browsing v4 threatMatches endpoint if API key exists."""
        result = {
            "checked": False,
            "is_threat": False,
            "threat_type": None,
            "platform_type": None,
        }
        if not self.safe_browsing_key:
            return result

        try:
            endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={self.safe_browsing_key}"
            payload = {
                "client": {"clientId": "phishguard", "clientVersion": "1.0.0"},
                "threatInfo": {
                    "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                    "platformTypes": ["ANY_PLATFORM"],
                    "threatEntryTypes": ["URL"],
                    "threatEntries": [{"url": url}],
                },
            }
            with httpx.Client(timeout=1.5) as client:
                resp = client.post(endpoint, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    result["checked"] = True
                    matches = data.get("matches", [])
                    if matches:
                        result["is_threat"] = True
                        result["threat_type"] = matches[0].get("threatType")
                        result["platform_type"] = matches[0].get("platformType")
        except Exception as e:
            logger.warning(f"Google Safe Browsing lookup failed: {e}")

        return result

    # ──────────────────────────────────────────────────────────
    #  6. Documented Rule-Based Adjustments Calculation
    # ──────────────────────────────────────────────────────────
    @staticmethod
    def compute_enrichment_adjustments(
        enrichment_data: Dict[str, Any],
        has_ip: bool = False
    ) -> List[RuleAdjustment]:
        """
        Calculates documented rule-based risk score adjustments.
        Kept strictly separate from ML SHAP feature attributions.

        Documented Adjustment Weights:
        - Safe Browsing Threat: +60.0
        - Credential Harvesting (Password + External Form): +25.0
        - Password Field Present: +15.0
        - External Form Action: +15.0
        - Critical Newly Registered Domain (< 14 days): +25.0
        - Recent Newly Registered Domain (14-30 days): +15.0
        - Established Mature Domain (> 2 years / 730 days): -15.0
        - Invalid TLS Certificate: +20.0
        - Short-lived TLS (< 14 days expiration): +10.0
        - Valid Trusted TLS on mature domain: -5.0
        - Unresolvable DNS (NXDOMAIN / host down): +15.0
        - Deceptive Iframe Embedded: +10.0
        - Anomalous External Link Ratio (> 80%): +10.0
        """
        adjustments: List[RuleAdjustment] = []

        # A. Google Safe Browsing Threat Feed
        sb = enrichment_data.get("safe_browsing", {})
        if sb.get("is_threat"):
            adjustments.append(RuleAdjustment(
                signal="google_safe_browsing",
                points=60.0,
                description=f"Flagged by Google Safe Browsing Threat Feed ({sb.get('threat_type', 'MALWARE')})",
                direction="suspicious",
            ))

        # B. Content Signals
        content = enrichment_data.get("content", {})
        if content.get("has_password_field") and content.get("has_external_form_action"):
            adjustments.append(RuleAdjustment(
                signal="credential_harvesting",
                points=25.0,
                description="Live content inspection detected password field submitting to external domain",
                direction="suspicious",
            ))
        elif content.get("has_password_field"):
            adjustments.append(RuleAdjustment(
                signal="password_field_present",
                points=15.0,
                description="Live page contains password input field (<input type='password'>)",
                direction="suspicious",
            ))
        elif content.get("has_external_form_action"):
            adjustments.append(RuleAdjustment(
                signal="external_form_action",
                points=15.0,
                description="Form action targets external third-party domain (data exfiltration risk)",
                direction="suspicious",
            ))

        if content.get("has_iframe"):
            adjustments.append(RuleAdjustment(
                signal="deceptive_iframe",
                points=10.0,
                description="Page embeds hidden or external iframe (overlay/clickjacking risk)",
                direction="suspicious",
            ))

        if content.get("external_link_ratio", 0.0) >= 0.8:
            adjustments.append(RuleAdjustment(
                signal="high_external_link_ratio",
                points=10.0,
                description=f"Anomalous external link ratio ({int(content['external_link_ratio'] * 100)}% outbound links)",
                direction="suspicious",
            ))

        # C. Domain Age (RDAP / WHOIS)
        age = enrichment_data.get("domain_age", {})
        age_days = age.get("domain_age_days")
        if age_days is not None:
            if age_days < 14:
                adjustments.append(RuleAdjustment(
                    signal="newly_registered_critical",
                    points=25.0,
                    description=f"Critical: Domain registered only {age_days} days ago (< 14 days, high phishing velocity)",
                    direction="suspicious",
                ))
            elif age_days < 30:
                adjustments.append(RuleAdjustment(
                    signal="newly_registered_recent",
                    points=15.0,
                    description=f"Newly registered domain created {age_days} days ago (< 30 days)",
                    direction="suspicious",
                ))
            elif age_days > 730:
                adjustments.append(RuleAdjustment(
                    signal="established_mature_domain",
                    points=-15.0,
                    description=f"Established mature domain active for {round(age_days / 365, 1)} years (reduced risk baseline)",
                    direction="benign",
                ))

        # D. TLS Certificate
        tls = enrichment_data.get("tls", {})
        if tls.get("tls_active"):
            if not tls.get("tls_valid"):
                adjustments.append(RuleAdjustment(
                    signal="invalid_tls_certificate",
                    points=20.0,
                    description=f"Invalid live TLS certificate: {tls.get('error', 'Handshake error or untrusted CA')}",
                    direction="suspicious",
                ))
            elif tls.get("is_short_lived"):
                adjustments.append(RuleAdjustment(
                    signal="short_lived_tls_certificate",
                    points=10.0,
                    description=f"Short-lived TLS certificate expiring in {tls.get('days_until_expiration')} days (< 14 days)",
                    direction="suspicious",
                ))
            elif age_days is not None and age_days > 365:
                adjustments.append(RuleAdjustment(
                    signal="valid_trusted_tls",
                    points=-5.0,
                    description=f"Valid TLS certificate issued by {tls.get('issuer', 'Verified CA')} on established domain",
                    direction="benign",
                ))

        # E. DNS Resolution
        dns = enrichment_data.get("dns", {})
        if not dns.get("resolves") and not has_ip:
            adjustments.append(RuleAdjustment(
                signal="unresolvable_dns",
                points=15.0,
                description="Domain failed DNS resolution (NXDOMAIN or host unreachable)",
                direction="suspicious",
            ))

        return adjustments

    # ──────────────────────────────────────────────────────────
    #  7. Master Orchestrator with Graceful Fallback
    # ──────────────────────────────────────────────────────────
    def enrich_url(self, url: str, domain: str, has_ip: bool = False) -> Dict[str, Any]:
        """Perform all live stage 2 checks with strict timeouts, SSRF guards, and rule adjustments."""
        # 1. DNS Resolution
        dns_res = self.check_dns(domain)
        resolved_ips = dns_res.get("ips", [])

        # 2. Live TLS Certificate
        tls_res = self.check_tls(domain)

        # 3. SSRF-Safe Content Inspection (with redirect re-validation & capped size)
        content_res = self.inspect_page_content(url, domain, resolved_ips)

        # 4. Domain Age
        age_res = self.check_domain_age(domain)

        # 5. Optional Safe Browsing
        sb_res = self.check_safe_browsing(url)

        # Live activity flag
        live_active = dns_res["resolves"] or tls_res["tls_active"] or content_res["content_fetched"]

        enrichment_data = {
            "live_enrichment_active": live_active,
            "dns": dns_res,
            "tls": tls_res,
            "content": content_res,
            "domain_age": age_res,
            "safe_browsing": sb_res,
        }

        # Calculate rule adjustments
        adjustments = self.compute_enrichment_adjustments(enrichment_data, has_ip=has_ip)
        total_adj = sum(a.points for a in adjustments)

        enrichment_data["adjustments"] = [asdict(a) for a in adjustments]
        enrichment_data["total_adjustment_points"] = total_adj

        return enrichment_data


enrichment_service = EnrichmentService()
