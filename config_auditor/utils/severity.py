"""
Severity levels and Finding data structures for configuration audits.
"""

from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


class Severity(Enum):
    """Severity levels for security findings."""

    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __str__(self) -> str:
        return self.name

    @property
    def color(self) -> str:
        """Return ANSI color code for terminal output."""
        colors = {
            Severity.CRITICAL: "\033[91m",  # Red
            Severity.HIGH: "\033[93m",      # Yellow
            Severity.MEDIUM: "\033[94m",    # Blue
            Severity.LOW: "\033[92m",       # Green
            Severity.INFO: "\033[90m",      # Gray
        }
        return colors.get(self, "\033[0m")

    @property
    def icon(self) -> str:
        """Return icon for visual representation."""
        icons = {
            Severity.CRITICAL: "🔴",
            Severity.HIGH: "🟠",
            Severity.MEDIUM: "🟡",
            Severity.LOW: "🟢",
            Severity.INFO: "ℹ️",
        }
        return icons.get(self, "•")


@dataclass
class Finding:
    """
    Represents a single security finding from an audit check.

    Attributes:
        check_id: Unique identifier for the check (e.g., "SSH-001")
        title: Short descriptive title
        description: Detailed description of the finding
        severity: Severity level of the finding
        resource: The resource being checked (file path, AWS resource, etc.)
        recommendation: Recommended remediation steps
        references: Links to relevant documentation or standards
        metadata: Additional contextual information
        timestamp: When the finding was discovered
    """

    check_id: str
    title: str
    description: str
    severity: Severity
    resource: str
    recommendation: str
    references: list[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=_utcnow)
    passed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for JSON serialization."""
        return {
            "check_id": self.check_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.name,
            "resource": self.resource,
            "recommendation": self.recommendation,
            "references": self.references,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
            "passed": self.passed,
        }

    def __str__(self) -> str:
        """Human-readable string representation."""
        status = "✓ PASS" if self.passed else "✗ FAIL"
        return (
            f"[{self.severity.icon} {self.severity.name}] {self.check_id}: {self.title}\n"
            f"    Resource: {self.resource}\n"
            f"    Status: {status}\n"
            f"    {self.description}"
        )
