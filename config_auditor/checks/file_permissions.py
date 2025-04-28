"""
File permission security checks.

Provides reusable check functions for Linux file permission validation.
"""

import os
import stat
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..utils.severity import Finding, Severity


class FilePermissionChecks:
    """
    Collection of file permission security check functions.

    These checks validate file and directory permissions against
    security best practices.
    """

    # Critical system files and their expected permissions (octal)
    CRITICAL_FILES = {
        '/etc/shadow': {'expected': 0o600, 'owner': 'root', 'severity': Severity.CRITICAL},
        '/etc/gshadow': {'expected': 0o600, 'owner': 'root', 'severity': Severity.CRITICAL},
        '/etc/passwd': {'expected': 0o644, 'owner': 'root', 'severity': Severity.HIGH},
        '/etc/group': {'expected': 0o644, 'owner': 'root', 'severity': Severity.MEDIUM},
        '/etc/sudoers': {'expected': 0o440, 'owner': 'root', 'severity': Severity.CRITICAL},
        '/etc/ssh/sshd_config': {'expected': 0o600, 'owner': 'root', 'severity': Severity.HIGH},
        '/etc/crontab': {'expected': 0o600, 'owner': 'root', 'severity': Severity.MEDIUM},
        '/etc/cron.allow': {'expected': 0o600, 'owner': 'root', 'severity': Severity.MEDIUM},
        '/etc/at.allow': {'expected': 0o600, 'owner': 'root', 'severity': Severity.MEDIUM},
    }

    # Directories to check for world-writable files
    SENSITIVE_DIRECTORIES = [
        '/etc',
        '/bin',
        '/sbin',
        '/usr/bin',
        '/usr/sbin',
        '/lib',
        '/lib64',
    ]

    def __init__(self, verbose: bool = False):
        """
        Initialize file permission checks.

        Args:
            verbose: Enable verbose output
        """
        self.verbose = verbose

    def check_file_permissions(
        self,
        file_path: str,
        expected_perms: int,
        severity: Optional[Severity] = None
    ) -> Finding:
        """
        Check permissions of a specific file.

        Args:
            file_path: Path to the file
            expected_perms: Expected permissions (octal)
            severity: Severity if misconfigured

        Returns:
            Finding with check result
        """
        check_id = f"FILE-{Path(file_path).name.upper().replace('.', '-')}"

        try:
            stat_info = os.stat(file_path)
            current_perms = stat.S_IMODE(stat_info.st_mode)

            if current_perms <= expected_perms:
                return Finding(
                    check_id=check_id,
                    title=f"{file_path} Permissions Secure",
                    description=f"Permissions are {oct(current_perms)} (expected {oct(expected_perms)} or more restrictive).",
                    severity=Severity.INFO,
                    resource=file_path,
                    recommendation="Continue maintaining secure permissions.",
                    passed=True,
                )
            else:
                return Finding(
                    check_id=check_id,
                    title=f"{file_path} Permissions Too Permissive",
                    description=f"Permissions are {oct(current_perms)}, should be {oct(expected_perms)} or more restrictive.",
                    severity=severity or Severity.HIGH,
                    resource=file_path,
                    recommendation=f"Run 'chmod {oct(expected_perms)[2:]} {file_path}'.",
                    passed=False,
                )
        except FileNotFoundError:
            return Finding(
                check_id=check_id,
                title=f"{file_path} Not Found",
                description=f"File {file_path} does not exist.",
                severity=Severity.INFO,
                resource=file_path,
                recommendation="File may not be applicable to this system.",
                passed=True,
            )
        except PermissionError:
            return Finding(
                check_id=check_id,
                title=f"Cannot Check {file_path}",
                description="Permission denied. Run with elevated privileges.",
                severity=Severity.INFO,
                resource=file_path,
                recommendation="Run auditor with sudo/root for complete checks.",
                passed=True,
                metadata={"requires_root": True},
            )

    def check_critical_files(self) -> List[Finding]:
        """
        Check permissions on critical system files.

        Returns:
            List of findings from all checks
        """
        findings = []

        for file_path, config in self.CRITICAL_FILES.items():
            finding = self.check_file_permissions(
                file_path,
                config['expected'],
                config['severity']
            )
            findings.append(finding)

        return findings

    def check_world_writable_files(
        self,
        directories: Optional[List[str]] = None,
        max_findings: int = 20
    ) -> Finding:
        """
        Check for world-writable files in specified directories.

        Args:
            directories: Directories to check (defaults to SENSITIVE_DIRECTORIES)
            max_findings: Maximum number of files to report

        Returns:
            Finding with results
        """
        check_id = "FILE-WORLD-WRITABLE"

        if directories is None:
            directories = self.SENSITIVE_DIRECTORIES

        world_writable_files = []

        for directory in directories:
            if not os.path.exists(directory):
                continue

            try:
                for root, dirs, files in os.walk(directory):
                    for filename in files:
                        filepath = os.path.join(root, filename)
                        try:
                            stat_info = os.lstat(filepath)

                            # Skip symlinks
                            if stat.S_ISLNK(stat_info.st_mode):
                                continue

                            perms = stat.S_IMODE(stat_info.st_mode)
                            if perms & stat.S_IWOTH:
                                world_writable_files.append(filepath)

                                if len(world_writable_files) >= max_findings:
                                    break
                        except (PermissionError, FileNotFoundError):
                            continue

                    if len(world_writable_files) >= max_findings:
                        break
            except PermissionError:
                continue

        if world_writable_files:
            return Finding(
                check_id=check_id,
                title="World-Writable Files Found",
                description=f"Found {len(world_writable_files)} world-writable files in system directories.",
                severity=Severity.HIGH,
                resource=", ".join(world_writable_files[:5]) + ("..." if len(world_writable_files) > 5 else ""),
                recommendation="Remove world-writable permissions with 'chmod o-w <file>'.",
                metadata={"files": world_writable_files, "total": len(world_writable_files)},
                passed=False,
            )

        return Finding(
            check_id=check_id,
            title="No World-Writable Files",
            description="No world-writable files found in system directories.",
            severity=Severity.INFO,
            resource="System directories",
            recommendation="Continue monitoring for world-writable files.",
            passed=True,
        )

    def check_unowned_files(
        self,
        search_paths: Optional[List[str]] = None,
        max_findings: int = 20
    ) -> Finding:
        """
        Check for files without valid owner/group.

        Args:
            search_paths: Paths to search
            max_findings: Maximum findings to report

        Returns:
            Finding with results
        """
        check_id = "FILE-UNOWNED"

        if search_paths is None:
            search_paths = ['/home', '/tmp', '/var/tmp']

        unowned_files = []

        for path in search_paths:
            if not os.path.exists(path):
                continue

            try:
                for root, dirs, files in os.walk(path):
                    for item in files + dirs:
                        filepath = os.path.join(root, item)
                        try:
                            stat_info = os.lstat(filepath)

                            # Check if UID exists (Unix-only)
                            if pwd is None:
                                # Skip this check on Windows
                                continue
                            try:
                                pwd.getpwuid(stat_info.st_uid)
                            except KeyError:
                                unowned_files.append({
                                    "path": filepath,
                                    "uid": stat_info.st_uid
                                })

                            # Check if GID exists
                            try:
                                grp.getgrgid(stat_info.st_gid)
                            except KeyError:
                                pass

                            if len(unowned_files) >= max_findings:
                                break
                        except (PermissionError, FileNotFoundError):
                            continue

                    if len(unowned_files) >= max_findings:
                        break
            except PermissionError:
                continue

        if unowned_files:
            return Finding(
                check_id=check_id,
                title="Unowned Files Found",
                description=f"Found {len(unowned_files)} files with non-existent owner/group.",
                severity=Severity.MEDIUM,
                resource="File system",
                recommendation="Assign proper ownership with 'chown'.",
                metadata={"files": unowned_files},
                passed=False,
            )

        return Finding(
            check_id=check_id,
            title="No Unowned Files",
            description="All files have valid owner/group.",
            severity=Severity.INFO,
            resource="File system",
            recommendation="Continue monitoring file ownership.",
            passed=True,
        )

    def check_suid_sgid_files(
        self,
        search_paths: Optional[List[str]] = None
    ) -> Finding:
        """
        Check for SUID/SGID files.

        Args:
            search_paths: Paths to search for SUID/SGID files

        Returns:
            Finding with results
        """
        check_id = "FILE-SUID-SGID"

        if search_paths is None:
            search_paths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin']

        # Known legitimate SUID/SGID binaries
        legitimate_suid = {
            '/usr/bin/sudo', '/usr/bin/passwd', '/usr/bin/su',
            '/usr/bin/ping', '/usr/bin/newgrp', '/usr/bin/chsh',
            '/usr/bin/chfn', '/usr/bin/gpasswd', '/usr/bin/at',
            '/usr/lib/openssh/ssh-keysign',
            '/usr/lib/dbus-1.0/dbus-daemon-launch-helper',
        }

        suspicious_files = []

        for path in search_paths:
            if not os.path.exists(path):
                continue

            try:
                for entry in os.listdir(path):
                    full_path = os.path.join(path, entry)
                    try:
                        stat_info = os.lstat(full_path)

                        if stat.S_ISREG(stat_info.st_mode):
                            mode = stat_info.st_mode
                            if mode & stat.S_ISUID or mode & stat.S_ISGID:
                                if full_path not in legitimate_suid:
                                    suspicious_files.append({
                                        "path": full_path,
                                        "suid": bool(mode & stat.S_ISUID),
                                        "sgid": bool(mode & stat.S_ISGID),
                                    })
                    except (PermissionError, FileNotFoundError):
                        continue
            except PermissionError:
                continue

        if suspicious_files:
            return Finding(
                check_id=check_id,
                title="Suspicious SUID/SGID Files",
                description=f"Found {len(suspicious_files)} files with SUID/SGID bits outside expected locations.",
                severity=Severity.MEDIUM,
                resource="System binaries",
                recommendation="Review and remove SUID/SGID bits if not required.",
                metadata={"files": suspicious_files},
                passed=False,
            )

        return Finding(
            check_id=check_id,
            title="SUID/SGID Files OK",
            description="All SUID/SGID files are in expected locations.",
            severity=Severity.INFO,
            resource="System binaries",
            recommendation="Continue monitoring for unauthorized SUID/SGID files.",
            passed=True,
        )


# Import pwd and grp for unowned file checks (Unix-only)
try:
    import pwd
    import grp
except ImportError:
    # Windows compatibility - these modules don't exist on Windows
    pwd = None  # type: ignore
    grp = None  # type: ignore
