"""Auditors module for Linux and AWS configuration checks."""

from .base import BaseAuditor

# Lazy imports for platform-specific auditors
def __getattr__(name: str):
    if name == "LinuxAuditor":
        from .linux import LinuxAuditor
        return LinuxAuditor
    elif name == "AWSAuditor":
        from .aws import AWSAuditor
        return AWSAuditor
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = ["BaseAuditor", "LinuxAuditor", "AWSAuditor"]
