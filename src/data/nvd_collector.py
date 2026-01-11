"""
NVD (National Vulnerability Database) data collector.

Fetches CVE data from the NVD API for training vulnerability detection models.
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Generator, List, Optional

import requests
from tqdm import tqdm

from ..utils.config import get_config
from ..utils.logger import get_logger


class NVDCollector:
    """
    Collector for CVE/vulnerability data from the National Vulnerability Database.

    The NVD provides machine-readable data about software vulnerabilities
    that can be used to train vulnerability detection models.
    """

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize the NVD collector.

        Args:
            api_key: NVD API key for higher rate limits. If None, uses config/env.
        """
        self.config = get_config()
        self.logger = get_logger("nvd_collector")

        self.api_base = self.config.get(
            "nvd.api_base_url",
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        )
        self.api_key = api_key or self.config.get("nvd.api_key")
        self.results_per_page = self.config.get("nvd.results_per_page", 2000)

        # Rate limiting: 6 seconds without key, 0.6 seconds with key
        self.rate_limit_delay = 0.6 if self.api_key else 6

        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    def fetch_cves(
        self,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        keyword: Optional[str] = None,
        cwe_id: Optional[str] = None,
        cvss_severity: Optional[str] = None,
    ) -> Generator[Dict, None, None]:
        """
        Fetch CVEs from the NVD API with optional filters.

        Args:
            start_date: Filter CVEs published after this date
            end_date: Filter CVEs published before this date
            keyword: Search keyword in CVE descriptions
            cwe_id: Filter by CWE ID (e.g., "CWE-79" for XSS)
            cvss_severity: Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)

        Yields:
            Dict containing CVE data
        """
        params = {"resultsPerPage": self.results_per_page}

        if start_date:
            params["pubStartDate"] = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if end_date:
            params["pubEndDate"] = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if keyword:
            params["keywordSearch"] = keyword
        if cwe_id:
            params["cweId"] = cwe_id
        if cvss_severity:
            params["cvssV3Severity"] = cvss_severity

        start_index = 0
        total_results = None

        with tqdm(desc="Fetching CVEs", unit="CVEs") as pbar:
            while True:
                params["startIndex"] = start_index

                try:
                    response = self.session.get(self.api_base, params=params)
                    response.raise_for_status()
                    data = response.json()
                except requests.RequestException as e:
                    self.logger.error(f"API request failed: {e}")
                    break

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    pbar.total = total_results
                    self.logger.info(f"Total CVEs to fetch: {total_results}")

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    yield vuln.get("cve", {})
                    pbar.update(1)

                start_index += len(vulnerabilities)
                if start_index >= total_results:
                    break

                # Rate limiting
                time.sleep(self.rate_limit_delay)

    def fetch_by_cwe(self, cwe_ids: List[str]) -> Dict[str, List[Dict]]:
        """
        Fetch CVEs organized by CWE category.

        Args:
            cwe_ids: List of CWE IDs to fetch (e.g., ["CWE-79", "CWE-89"])

        Returns:
            Dictionary mapping CWE IDs to lists of CVEs
        """
        results = {}
        for cwe_id in cwe_ids:
            self.logger.info(f"Fetching CVEs for {cwe_id}")
            results[cwe_id] = list(self.fetch_cves(cwe_id=cwe_id))
            time.sleep(self.rate_limit_delay)
        return results

    def fetch_recent(self, days: int = 30) -> List[Dict]:
        """
        Fetch CVEs from the last N days.

        Args:
            days: Number of days to look back

        Returns:
            List of recent CVEs
        """
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        return list(self.fetch_cves(start_date=start_date, end_date=end_date))

    def save_cves(self, cves: List[Dict], output_path: str) -> None:
        """
        Save CVEs to a JSON file.

        Args:
            cves: List of CVE dictionaries
            output_path: Path to save the JSON file
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(cves, f, indent=2, default=str)

        self.logger.info(f"Saved {len(cves)} CVEs to {output_path}")

    def load_cves(self, input_path: str) -> List[Dict]:
        """
        Load CVEs from a JSON file.

        Args:
            input_path: Path to the JSON file

        Returns:
            List of CVE dictionaries
        """
        with open(input_path, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def extract_cve_info(cve: Dict) -> Dict:
        """
        Extract relevant information from a CVE entry.

        Args:
            cve: Raw CVE dictionary from NVD API

        Returns:
            Simplified CVE information dictionary
        """
        # Extract basic info
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            ""
        )

        # Extract CWE information
        weaknesses = cve.get("weaknesses", [])
        cwes = []
        for weakness in weaknesses:
            for desc in weakness.get("description", []):
                if desc.get("lang") == "en" and desc.get("value", "").startswith("CWE-"):
                    cwes.append(desc["value"])

        # Extract CVSS scores
        metrics = cve.get("metrics", {})
        cvss_v3 = None
        cvss_severity = None

        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            cvss_v3 = cvss_data.get("baseScore")
            cvss_severity = cvss_data.get("baseSeverity")

        # Extract affected configurations
        configurations = cve.get("configurations", [])
        affected_products = []
        for config in configurations:
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_products.append(cpe_match.get("criteria", ""))

        # Extract references
        references = [
            ref.get("url") for ref in cve.get("references", [])
        ]

        return {
            "cve_id": cve_id,
            "description": description,
            "cwes": cwes,
            "cvss_v3_score": cvss_v3,
            "cvss_severity": cvss_severity,
            "affected_products": affected_products,
            "references": references,
            "published": cve.get("published"),
            "last_modified": cve.get("lastModified"),
        }

    def get_common_cwes(self) -> List[str]:
        """
        Get a list of common CWE IDs for vulnerability detection.

        Returns:
            List of important CWE IDs
        """
        return [
            "CWE-79",   # Cross-site Scripting (XSS)
            "CWE-89",   # SQL Injection
            "CWE-20",   # Improper Input Validation
            "CWE-22",   # Path Traversal
            "CWE-78",   # OS Command Injection
            "CWE-119",  # Buffer Overflow
            "CWE-200",  # Information Exposure
            "CWE-264",  # Permissions/Privileges
            "CWE-287",  # Authentication Issues
            "CWE-352",  # CSRF
            "CWE-400",  # Resource Exhaustion
            "CWE-416",  # Use After Free
            "CWE-434",  # Unrestricted File Upload
            "CWE-476",  # NULL Pointer Dereference
            "CWE-502",  # Deserialization
            "CWE-611",  # XXE
            "CWE-787",  # Out-of-bounds Write
            "CWE-798",  # Hard-coded Credentials
            "CWE-862",  # Missing Authorization
            "CWE-918",  # SSRF
        ]
