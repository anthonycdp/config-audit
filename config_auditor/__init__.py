"""
Configuration Audit Tool
A comprehensive security configuration auditor for Linux systems and AWS cloud environments.
"""

__version__ = "1.0.0"
__author__ = "Security Team"

from .reporters.report_generator import ReportGenerator

# Lazy imports for platform-specific auditors
def __getattr__(name: str):
    if name == "LinuxAuditor":
        from .auditors.linux import LinuxAuditor
        return LinuxAuditor
    elif name == "AWSAuditor":
        from .auditors.aws import AWSAuditor
        return AWSAuditor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["LinuxAuditor", "AWSAuditor", "ReportGenerator"]
