"""
Base auditor class providing common functionality for all auditors.
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from datetime import datetime, timezone
import logging

from ..utils.severity import Finding


logger = logging.getLogger(__name__)


class BaseAuditor(ABC):
    """
    Abstract base class for all configuration auditors.

    Provides common functionality for running checks, collecting findings,
    and generating audit reports.
    """

    def __init__(self, verbose: bool = False):
        """
        Initialize the auditor.

        Args:
            verbose: Enable verbose logging output
        """
        self.verbose = verbose
        self.findings: List[Finding] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None

        if verbose:
            logging.basicConfig(level=logging.DEBUG)

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the name of this auditor."""
        pass

    @property
    @abstractmethod
    def checks(self) -> List[str]:
        """Return list of available check IDs."""
        pass

    @abstractmethod
    def run_all_checks(self) -> List[Finding]:
        """
        Run all available security checks.

        Returns:
            List of findings from all checks
        """
        pass

    def run_check(self, check_id: str) -> Optional[Finding]:
        """
        Run a specific security check by ID.

        Args:
            check_id: The ID of the check to run

        Returns:
            Finding from the check, or None if check not found
        """
        check_method = getattr(self, f"_check_{check_id.lower().replace('-', '_')}", None)
        if check_method:
            try:
                return check_method()
            except Exception as e:
                logger.error(f"Error running check {check_id}: {e}")
                return None
        logger.warning(f"Check {check_id} not found")
        return None

    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the results."""
        self.findings.append(finding)
        if self.verbose:
            print(finding)

    def clear_findings(self) -> None:
        """Clear all collected findings."""
        self.findings = []

    def run_audit(self, checks: Optional[List[str]] = None) -> List[Finding]:
        """
        Run the audit with specified checks or all checks.

        Args:
            checks: Optional list of specific check IDs to run.
                   If None, runs all checks.

        Returns:
            List of findings from the audit
        """
        self.start_time = datetime.now(timezone.utc)
        self.clear_findings()

        logger.info(f"Starting {self.name} audit...")

        if checks:
            for check_id in checks:
                finding = self.run_check(check_id)
                if finding:
                    self.add_finding(finding)
        else:
            findings = self.run_all_checks()
            for finding in findings:
                self.add_finding(finding)

        self.end_time = datetime.now(timezone.utc)
        duration = (self.end_time - self.start_time).total_seconds()
        logger.info(f"Audit completed in {duration:.2f} seconds")

        return self.findings

    def get_summary(self) -> dict:
        """
        Get a summary of the audit results.

        Returns:
            Dictionary with summary statistics
        """
        from ..utils.severity import Severity

        summary = {
            "total_findings": len(self.findings),
            "passed": sum(1 for f in self.findings if f.passed),
            "failed": sum(1 for f in self.findings if not f.passed),
            "by_severity": {},
            "duration_seconds": 0,
        }

        for severity in Severity:
            count = sum(1 for f in self.findings if f.severity == severity and not f.passed)
            if count > 0:
                summary["by_severity"][severity.name] = count

        if self.start_time and self.end_time:
            summary["duration_seconds"] = (
                self.end_time - self.start_time
            ).total_seconds()

        return summary
