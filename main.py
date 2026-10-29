"""Command-line entry point for the phishing analysis lab."""

import argparse
import json
from pathlib import Path

from analyzer import analyze_email

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_SAMPLE = BASE_DIR / "samples" / "sample_email.eml"
REPORT_DIR = BASE_DIR / "reports"


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a local email for phishing indicators."
    )
    parser.add_argument(
        "--file", type=Path, default=DEFAULT_SAMPLE,
        help="Path to a local email text file.",
    )
    parser.add_argument(
        "--output", type=Path,
        default=REPORT_DIR / "analysis_report.json",
        help="Path for the JSON report.",
    )
    args = parser.parse_args()

    if not args.file.is_file():
        parser.error("Input file does not exist.")

    try:
        raw_email = args.file.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        parser.error(f"Could not read input file: {exc}")

    report = analyze_email(raw_email)

    try:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    except OSError as exc:
        parser.error(f"Could not write report: {exc}")

    print("=" * 58)
    print("          PHISHING EMAIL ANALYSIS REPORT")
    print("=" * 58)
    print(f"Subject    : {report['subject']}")
    print(f"Sender     : {report['sender']}")
    print(f"Reply-To   : {report['reply_to']}")
    print(f"Risk level : {report['risk_level']}")
    print(f"Risk score : {report['risk_score']}/10")
    print(f"URLs found : {len(report['urls_found'])}")
    print("-" * 58)
    print("FINDINGS")

    for index, finding in enumerate(report["findings"], start=1):
        print(
            f"{index}. [{finding['severity'].upper()}] "
            f"{finding['indicator']}"
        )
        print(f"   Evidence: {finding['evidence']}")

    print("-" * 58)
    print(report["disclaimer"])
    print(f"\nJSON report saved to: {args.output}")


if __name__ == "__main__":
    main()
