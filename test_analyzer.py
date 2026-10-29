"""Unit tests for the phishing email analysis engine."""

import unittest

from analyzer import analyze_email, analyze_url, extract_urls


class TestURLExtraction(unittest.TestCase):
    def test_extracts_http_urls(self):
        self.assertEqual(
            extract_urls("Visit https://example.com/path for information."),
            ["https://example.com/path"],
        )

    def test_removes_duplicate_urls(self):
        self.assertEqual(
            len(extract_urls("https://example.com https://example.com")),
            1,
        )

    def test_empty_text_returns_no_urls(self):
        self.assertEqual(extract_urls(""), [])


class TestURLAnalysis(unittest.TestCase):
    def test_detects_ip_address_url(self):
        indicators = [
            item["indicator"]
            for item in analyze_url("http://192.0.2.10/login")
        ]
        self.assertIn("IP-address URL", indicators)

    def test_detects_url_shortener(self):
        indicators = [
            item["indicator"]
            for item in analyze_url("https://bit.ly/example")
        ]
        self.assertIn("URL shortener", indicators)

    def test_plain_https_not_flagged_by_itself(self):
        self.assertEqual(analyze_url("https://example.com"), [])


class TestEmailAnalysis(unittest.TestCase):
    def test_detects_reply_to_mismatch(self):
        raw = (
            "From: sender@example.com\n"
            "Reply-To: other@example.com\n"
            "Subject: Test\n\nHello."
        )
        report = analyze_email(raw)
        indicators = [item["indicator"] for item in report["findings"]]
        self.assertIn("Sender and Reply-To mismatch", indicators)

    def test_returns_valid_risk_level(self):
        report = analyze_email(
            "From: sender@example.com\nSubject: Hello\n\nNormal sample."
        )
        self.assertIn(report["risk_level"], {"Low", "Medium", "High"})
        self.assertGreaterEqual(report["risk_score"], 0)
        self.assertLessEqual(report["risk_score"], 10)

    def test_detects_urgency_language(self):
        report = analyze_email(
            "From: sender@example.com\nSubject: Urgent action\n\n"
            "Please verify your account."
        )
        indicators = [item["indicator"] for item in report["findings"]]
        self.assertIn("Urgency or account-action language", indicators)

    def test_handles_empty_input(self):
        report = analyze_email("")
        self.assertEqual(report["sender"], "(missing)")
        self.assertIn(report["risk_level"], {"Low", "Medium", "High"})


if __name__ == "__main__":
    unittest.main()
