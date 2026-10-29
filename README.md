# Phishing Email Analysis Lab

A lightweight Python-based defensive email triage tool that identifies
potential phishing indicators using explainable, rule-based checks.

## Overview

The tool parses a local email sample, examines selected headers, extracts
HTTP/HTTPS links without visiting them, and generates a JSON report with
findings and a simple risk score.

## Features

- Sender, Reply-To, and subject extraction
- Sender/Reply-To mismatch detection
- URL extraction without network requests
- Detection of selected URL characteristics
- Common urgency phrase detection
- Explainable severity labels and risk scoring
- JSON report generation
- Automated unit tests

## Technology

Python 3 and its standard library. No third-party dependencies are required.

## Project Structure

    phishing-email-analysis-lab/
    ├── analyzer.py
    ├── main.py
    ├── test_analyzer.py
    ├── requirements.txt
    ├── README.md
    ├── .gitignore
    ├── samples/
    │   └── sample_email.eml
    └── reports/
        └── .gitkeep

## Setup

    python -m venv .venv

Activate on Windows PowerShell:

    .venv\Scripts\Activate.ps1

## Run Tests

    python -m unittest -v

## Analyze the Sample

    python main.py

## Analyze Another Authorized Email

    python main.py --file samples/sample_email.eml --output reports/analysis_report.json

Use only synthetic or authorized email samples.

## Risk Scoring

- High finding: 3 points
- Medium finding: 2 points
- Low finding: 1 point
- Informational finding: 0 points

The total score is capped at 10. Scores below 3 are Low, 3–5 are Medium,
and 6 or above are High.

This is a demonstration heuristic, not a validated probability of phishing.

## Security and Privacy

- Does not send emails or make network requests
- Does not visit extracted URLs
- Uses synthetic sample data
- Excludes generated JSON reports from Git by default
- Requires no external API keys

Review reports before sharing them. Real email data may contain personal
information, internal domains, and tracking links.

## Limitations

The lab does not verify SPF, DKIM, or DMARC, query domain reputation,
detonate attachments, or establish whether an email is malicious.

Legitimate emails may trigger warnings, and malicious emails may evade
these rules. A low score does not mean an email is safe.

## Learning Outcomes

Email parsing, URL inspection, security triage, explainable detection,
risk scoring, JSON reporting, unit testing, and defensive documentation.

## Responsible Use

For defensive education and authorized email analysis only.
