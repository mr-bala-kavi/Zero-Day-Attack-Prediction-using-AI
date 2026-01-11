#!/usr/bin/env python3
"""
Download CVE/NVD vulnerability data for training.

Usage:
    python scripts/download_cve_data.py --recent 30
    python scripts/download_cve_data.py --cwe CWE-79 CWE-89 CWE-119
    python scripts/download_cve_data.py --year 2023
"""

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.logger import setup_logger
from src.data.nvd_collector import NVDCollector


def parse_args():
    parser = argparse.ArgumentParser(description="Download CVE data from NVD")
    parser.add_argument(
        "--recent",
        type=int,
        default=None,
        help="Download CVEs from the last N days",
    )
    parser.add_argument(
        "--year",
        type=int,
        default=None,
        help="Download CVEs from a specific year",
    )
    parser.add_argument(
        "--cwe",
        nargs="+",
        default=None,
        help="Download CVEs for specific CWE IDs",
    )
    parser.add_argument(
        "--severity",
        type=str,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Filter by CVSS severity",
    )
    parser.add_argument(
        "--keyword",
        type=str,
        default=None,
        help="Search keyword in CVE descriptions",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="data/raw/cve_data.json",
        help="Output file path",
    )
    parser.add_argument(
        "--common-cwes",
        action="store_true",
        help="Download CVEs for common vulnerability types",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logger("download", level="INFO")

    logger.info("=" * 60)
    logger.info("NVD CVE Data Downloader")
    logger.info("=" * 60)

    # Initialize collector
    collector = NVDCollector()

    all_cves = []

    if args.common_cwes:
        # Download CVEs for common vulnerability types
        cwe_ids = collector.get_common_cwes()
        logger.info(f"Downloading CVEs for {len(cwe_ids)} common CWE types...")

        for cwe_id in cwe_ids:
            logger.info(f"Fetching {cwe_id}...")
            cves = list(collector.fetch_cves(cwe_id=cwe_id))
            extracted = [collector.extract_cve_info(cve) for cve in cves]
            all_cves.extend(extracted)
            logger.info(f"  Found {len(cves)} CVEs for {cwe_id}")

    elif args.cwe:
        # Download CVEs for specified CWE IDs
        for cwe_id in args.cwe:
            logger.info(f"Fetching {cwe_id}...")
            cves = list(collector.fetch_cves(cwe_id=cwe_id))
            extracted = [collector.extract_cve_info(cve) for cve in cves]
            all_cves.extend(extracted)
            logger.info(f"  Found {len(cves)} CVEs for {cwe_id}")

    elif args.recent:
        # Download recent CVEs
        logger.info(f"Fetching CVEs from the last {args.recent} days...")
        cves = collector.fetch_recent(days=args.recent)
        all_cves = [collector.extract_cve_info(cve) for cve in cves]

    elif args.year:
        # Download CVEs from a specific year
        start_date = datetime(args.year, 1, 1)
        end_date = datetime(args.year, 12, 31, 23, 59, 59)
        logger.info(f"Fetching CVEs from {args.year}...")
        cves = list(collector.fetch_cves(
            start_date=start_date,
            end_date=end_date,
            cvss_severity=args.severity,
            keyword=args.keyword,
        ))
        all_cves = [collector.extract_cve_info(cve) for cve in cves]

    else:
        # Default: fetch recent high-severity CVEs
        logger.info("Fetching recent HIGH and CRITICAL severity CVEs...")
        for severity in ["HIGH", "CRITICAL"]:
            cves = collector.fetch_recent(days=90)
            for cve in cves:
                extracted = collector.extract_cve_info(cve)
                if extracted.get("cvss_severity") == severity:
                    all_cves.append(extracted)

    # Remove duplicates
    seen = set()
    unique_cves = []
    for cve in all_cves:
        if cve["cve_id"] not in seen:
            seen.add(cve["cve_id"])
            unique_cves.append(cve)

    logger.info(f"\nTotal unique CVEs collected: {len(unique_cves)}")

    # Save to file
    collector.save_cves(unique_cves, args.output)

    # Print summary
    severity_counts = {}
    cwe_counts = {}
    for cve in unique_cves:
        sev = cve.get("cvss_severity", "UNKNOWN")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        for cwe in cve.get("cwes", []):
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

    logger.info("\nSeverity Distribution:")
    for sev, count in sorted(severity_counts.items()):
        logger.info(f"  {sev}: {count}")

    logger.info("\nTop CWE Types:")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]:
        logger.info(f"  {cwe}: {count}")

    logger.info(f"\nData saved to {args.output}")


if __name__ == "__main__":
    main()
