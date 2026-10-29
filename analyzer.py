
"""Defensive phishing email analysis using explainable rules."""

from email import policy
from email.parser import Parser
from urllib.parse import urlparse
import ipaddress
import re

URL_PATTERN = re.compile(r"""https?://[^\s<>"']+""", re.IGNORECASE)

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
}

SUSPICIOUS_TERMS = {
    "verify your account",
    "urgent action",
    "account suspended",
    "password expires",
    "confirm your identity",
    "payment failed",
    "immediately",
}


def normalize_address(value):
    """Extract a lowercase email address from a header."""
    if not value:
        return ""

    match = re.search(r"<([^<>]+@[^<>]+)>", value)
    address = match.group(1) if match else value.strip()
    return address.strip().lower()


def extract_urls(text):
    """Extract URLs without visiting them."""
    urls = [
        match.rstrip(".,;:!?) ]}")
        for match in URL_PATTERN.findall(text or "")
    ]
    return list(dict.fromkeys(urls))


def analyze_url(url):
    """Identify URL indicators without making network requests."""
    findings = []

    try:
        parsed = urlparse(url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return [{
                "severity": "medium",
                "indicator": "Unexpected URL scheme",
                "evidence": "The link does not use HTTP or HTTPS.",
            }]

        hostname = parsed.hostname

        if not hostname:
            return [{
                "severity": "medium",
                "indicator": "Missing hostname",
                "evidence": "The URL has no recognizable hostname.",
            }]

        hostname = hostname.lower().rstrip(".")

        if parsed.username or parsed.password:
            findings.append({
                "severity": "high",
                "indicator": "URL contains user information",
                "evidence": "The URL includes credentials before the hostname.",
            })

        try:
            ipaddress.ip_address(hostname)
            findings.append({
                "severity": "medium",
                "indicator": "IP-address URL",
                "evidence": "The hostname is an IP address, not a domain name.",
            })
        except ValueError:
            pass

        if hostname in URL_SHORTENERS:
            findings.append({
                "severity": "medium",
                "indicator": "URL shortener",
                "evidence": "The link uses a known URL-shortening service.",
            })

        if parsed.scheme.lower() == "http":
            findings.append({
                "severity": "low",
                "indicator": "Unencrypted HTTP link",
                "evidence": "The link uses HTTP rather than HTTPS.",
            })

        if hostname.startswith("xn--") or ".xn--" in hostname:
            findings.append({
                "severity": "medium",
                "indicator": "Internationalized domain label",
                "evidence": (
                    "Inspect the IDN-encoded hostname for lookalike characters."
                ),
            })

    except (ValueError, UnicodeError):
        findings.append({
            "severity": "medium",
            "indicator": "URL parsing issue",
            "evidence": "The URL could not be parsed reliably.",
        })

    return findings


def analyze_email(raw_email):
    """Analyze email text and return a JSON-serializable report."""

    # Remove a possible UTF-8 byte-order mark before parsing headers.
    raw_email = (raw_email or "").lstrip("\ufeff")

    message = Parser(policy=policy.default).parsestr(raw_email)

    sender = normalize_address(str(message.get("From", "")))
    reply_to = normalize_address(str(message.get("Reply-To", "")))
    subject = str(message.get("Subject", ""))

    body_parts = []

    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                try:
                    content = part.get_content()
                    if isinstance(content, str):
                        body_parts.append(content)
                except (LookupError, UnicodeError):
                    continue
    else:
        try:
            content = message.get_content()
            if isinstance(content, str):
                body_parts.append(content)
        except (LookupError, UnicodeError):
            body_parts.append("")

    body = "\n".join(body_parts)
    findings = []

    if not sender or "@" not in sender:
        findings.append({
            "severity": "medium",
            "indicator": "Missing or unusual sender",
            "evidence": "The sender address is missing or not recognizable.",
        })

    if reply_to and sender and reply_to != sender:
        findings.append({
            "severity": "medium",
            "indicator": "Sender and Reply-To mismatch",
            "evidence": "The reply address differs from the sender address.",
        })

    combined_text = f"{subject}\n{body}".lower()

    matched_terms = sorted(
        term for term in SUSPICIOUS_TERMS
        if term in combined_text
    )

    if matched_terms:
        findings.append({
            "severity": "low",
            "indicator": "Urgency or account-action language",
            "evidence": "Matched phrases: " + ", ".join(matched_terms),
        })

    urls = extract_urls(body)

    if not urls:
        findings.append({
            "severity": "info",
            "indicator": "No plain-text URLs found",
            "evidence": (
                "No HTTP or HTTPS URLs were extracted from the body."
            ),
        })

    for url in urls:
        for item in analyze_url(url):
            findings.append({
                **item,
                "evidence": f"{item['evidence']} URL: {url}",
            })

    weights = {
        "high": 3,
        "medium": 2,
        "low": 1,
        "info": 0,
    }

    score = min(
        10,
        sum(weights.get(item["severity"], 0) for item in findings),
    )

    risk = (
        "High" if score >= 6
        else "Medium" if score >= 3
        else "Low"
    )

    return {
        "subject": subject or "(no subject)",
        "sender": sender or "(missing)",
        "reply_to": reply_to or "(not provided)",
        "risk_level": risk,
        "risk_score": score,
        "urls_found": urls,
        "findings": findings,
        "disclaimer": (
            "Heuristic triage only. A low score does not prove an email is "
            "safe, and a high score does not prove it is malicious."
        ),
    }
