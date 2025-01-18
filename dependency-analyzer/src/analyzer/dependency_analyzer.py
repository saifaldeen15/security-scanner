import re
import requests
from typing import List, Dict
from datetime import datetime

from dataclasses import dataclass
from packaging import version
import math

@dataclass
class VulnerabilitySummary:
    id: str
    summary: str
    severity: str
    affected_versions: List[str]
    fixed_versions: List[str]
    published_date: str

class DependencyAnalyzer:
    def __init__(self):
        self.osv_url = "https://api.osv.dev/v1/query"
        self.pypi_url = "https://pypi.org/pypi/{package}/json"
        self.default_ecosystem = "PyPI"

    def extract_imported_packages(self, code):
        pattern = r'^\s*(?:from\s+([\w.]+)\s+import\s+[\w*, ]+|import\s+([\w.]+))'
        imports = re.findall(pattern, code, re.MULTILINE)
        packages = set(filter(None, [match[0] or match[1] for match in imports]))
        return list(packages)

    def get_package_versions(self, package_name: str) -> List[str]:
        """Get all available versions for a package from PyPI"""
        try:
            response = requests.get(self.pypi_url.format(package=package_name))
            response.raise_for_status()
            releases = response.json()['releases']

            # Filter out pre-releases and sort versions
            versions = [v for v in releases.keys() if not (
                'a' in v or 'b' in v or 'rc' in v or 'dev' in v
            )]
            versions.sort(key=lambda x: version.parse(x))
            return versions
        except:
            return []

    def is_recent_version(self, check_version: str, all_versions: List[str], threshold: float = 0.1) -> bool:
        """Check if a version is in the most recent 10% of versions"""
        if not all_versions:
            return True  # If we can't get versions, include everything
            
        try:
            # Calculate how many versions constitute the latest 10%
            num_recent = math.ceil(len(all_versions) * threshold)
            recent_versions = all_versions[-num_recent:]
            
            # Convert versions to comparable objects
            check_ver = version.parse(check_version)
            recent_vers = [version.parse(v) for v in recent_versions]
            
            # Check if the version is in the recent range
            return any(check_ver >= rv for rv in recent_vers)
        except:
            return True  # If version comparison fails, include it

    def _parse_vulnerability(self, vuln: Dict, all_versions: List[str]) -> VulnerabilitySummary:
        """Parse a vulnerability entry into a summary, filtering for recent versions"""
        affected_versions = []
        fixed_versions = []
        
        # Check if this vulnerability affects recent versions
        is_recent = False
        for affected in vuln.get('affected', []):
            for ver in affected.get('versions', []):
                if self.is_recent_version(ver, all_versions):
                    is_recent = True
                    break
        if not is_recent:
            return None

        # Get affected and fixed versions
        for affected in vuln.get('affected', []):
            for version_range in affected.get('ranges', []):
                for event in version_range.get('events', []):
                    if 'introduced' in event:
                        affected_versions.append(f">={event['introduced']}")
                    if 'fixed' in event:
                        fixed_versions.append(event['fixed'])

        # Get severity
        severity = "UNKNOWN"
        if 'database_specific' in vuln and 'severity' in vuln['database_specific']:
            severity = vuln['database_specific']['severity']
        elif 'severity' in vuln and len(vuln['severity']) > 0:
            severity = vuln['severity'][0].get('score', 'UNKNOWN')

        return VulnerabilitySummary(
            id=vuln.get('id', 'Unknown'),
            summary=vuln.get('summary', 'No summary available'),
            severity=severity,
            affected_versions=affected_versions,
            fixed_versions=fixed_versions,
            published_date=vuln.get('published', 'Unknown')
        )

    def check_vulnerabilities(self, package_name: str) -> Dict:
        """Check vulnerabilities for a specific package, focusing on recent versions"""
        query = {
            "package": {
                "name": package_name,
                "ecosystem": self.default_ecosystem
            }
        }

        try:
            response = requests.post(self.osv_url, json=query)
            response.raise_for_status()
            # Get all versions for the package
            all_versions = self.get_package_versions(package_name)

            # Parse and filter vulnerabilities
            vulnerabilities = response.json().get('vulns', [])
            parsed_vulns = []
            for vuln in vulnerabilities:
                summary = self._parse_vulnerability(vuln, all_versions)
                if summary:  # Only include if it affects recent versions
                    parsed_vulns.append(summary)

            # Sort by severity
            severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}
            parsed_vulns.sort(key=lambda x: severity_order.get(x.severity, 5))

            return {
                "package": package_name,
                "total_vulnerabilities": len(parsed_vulns),
                "vulnerabilities": [
                    {
                        "id": vuln.id,
                        "summary": vuln.summary,
                        "severity": vuln.severity,
                        "affected_versions": vuln.affected_versions,
                        "fixed_in": vuln.fixed_versions
                    }
                    for vuln in parsed_vulns
                ]
            }

        except requests.exceptions.RequestException as e:
            return {
                "package": package_name,
                "error": f"Failed to fetch vulnerabilities: {str(e)}"
            }

    def analyze(self, code: str) -> Dict:
        """Analyze dependencies focusing on recent vulnerabilities"""
        try:
            dependencies = self.extract_imported_packages(code)
            results = []
            total_vulnerabilities = 0

            for package_name in dependencies:
                vuln_info = self.check_vulnerabilities(package_name)
                if vuln_info.get('total_vulnerabilities', 0) > 0:
                    results.append(vuln_info)
                    total_vulnerabilities += vuln_info['total_vulnerabilities']

            summary = {
                "status": "success",
                "scan_timestamp": datetime.now().isoformat(),
                "total_packages_scanned": len(dependencies),
                "total_vulnerabilities_found": total_vulnerabilities,
                "vulnerable_packages": results  # Only include packages with vulnerabilities
            }

            return summary

        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "scan_timestamp": datetime.now().isoformat()
            }
