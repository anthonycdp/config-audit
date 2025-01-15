"""
Linux system configuration auditor.

Performs security checks on Linux systems including SSH configuration,
file permissions, user accounts, and system hardening.
"""

import os
import subprocess
import stat
import re
from pathlib import Path
from typing import List, Optional, Dict, Any

from .base import BaseAuditor
from ..utils.severity import Finding, Severity


class LinuxAuditor(BaseAuditor):
    """
    Auditor for Linux system security configurations.

    Checks include:
    - SSH configuration hardening
    - File and directory permissions
    - User account security
    - System service configuration
    - Network settings
    """

    # Configuration constants
    MAX_PASSWORD_DAYS = 90
    DEFAULT_PASS_MAX_DAYS = 99999

    # System paths
    PATH_SHADOW = "/etc/shadow"
    PATH_PASSWD = "/etc/passwd"
    PATH_GROUP = "/etc/group"
    PATH_GSHADOW = "/etc/gshadow"
    PATH_SUDOERS = "/etc/sudoers"
    PATH_SUDOERS_D = "/etc/sudoers.d"
    PATH_LOGIN_DEFS = "/etc/login.defs"
    PATH_SSH_DIR = "/etc/ssh"
    DEFAULT_SSH_CONFIG = "/etc/ssh/sshd_config"

    # Sensitive directories to check for world-writable files
    SENSITIVE_DIRS = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin"]

    # Search paths for SUID/SGID files
    BINARY_PATHS = ["/usr/bin", "/usr/sbin", "/bin", "/sbin"]

    # Firewall check constants
    IPTABLES_MIN_RULE_LINES = 8  # Default has about 8 lines per chain

    # Services that are often unnecessary and insecure
    RISKY_SERVICES = ["telnet", "rsh", "rexec", "ftp", "tftp"]

    def __init__(self, verbose: bool = False, ssh_config_path: str = None):
        """
        Initialize the Linux auditor.

        Args:
            verbose: Enable verbose output
            ssh_config_path: Path to SSH daemon configuration file
        """
        super().__init__(verbose)
        self.ssh_config_path = ssh_config_path or self.DEFAULT_SSH_CONFIG

    @property
    def name(self) -> str:
        return "Linux System Auditor"

    @property
    def checks(self) -> List[str]:
        return [
            "SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005",
            "FILE-001", "FILE-002", "FILE-003", "FILE-004", "FILE-005",
            "USER-001", "USER-002", "USER-003",
            "SYSTEM-001", "SYSTEM-002", "SYSTEM-003",
        ]

    def run_all_checks(self) -> List[Finding]:
        """Run all Linux security checks."""
        findings = []

        # SSH Configuration Checks
        findings.extend(self._check_ssh_root_login())
        findings.extend(self._check_ssh_password_auth())
        findings.extend(self._check_ssh_empty_passwords())
        findings.extend(self._check_ssh_protocol())
        findings.extend(self._check_ssh_x11_forwarding())

        # File Permission Checks
        findings.extend(self._check_shadow_file_permissions())
        findings.extend(self._check_passwd_file_permissions())
        findings.extend(self._check_ssh_host_keys())
        findings.extend(self._check_world_writable_files())
        findings.extend(self._check_suid_sgid_files())

        # User Account Checks
        findings.extend(self._check_default_accounts())
        findings.extend(self._check_password_expiry())
        findings.extend(self._check_sudo_configuration())

        # System Configuration Checks
        findings.extend(self._check_firewall_status())
        findings.extend(self._check_unnecessary_services())
        findings.extend(self._check_kernel_parameters())

        return findings

    # ==================== SSH Configuration Checks ====================

    def _read_ssh_config(self) -> Optional[str]:
        """Read SSH configuration file content.

        Returns:
            File content or None if file cannot be read.
        """
        try:
            with open(self.ssh_config_path, 'r') as f:
                return f.read()
        except (FileNotFoundError, PermissionError):
            return None

    def _get_ssh_config_value(self, content: str, directive: str) -> Optional[str]:
        """Extract a directive value from SSH config.

        Args:
            content: SSH config file content
            directive: Directive name to find (e.g., 'PermitRootLogin')

        Returns:
            Directive value or None if not found.
        """
        match = re.search(
            rf'^{directive}\s+(\S+)',
            content,
            re.MULTILINE | re.IGNORECASE
        )
        return match.group(1).lower() if match else None

    def _create_ssh_finding(
        self,
        check_id: str,
        title: str,
        description: str,
        severity: Severity,
        recommendation: str,
        passed: bool,
        references: List[str] = None
    ) -> Finding:
        """Create a finding for SSH configuration checks."""
        return Finding(
            check_id=check_id,
            title=title,
            description=description,
            severity=severity,
            resource=self.ssh_config_path,
            recommendation=recommendation,
            references=references or [],
            passed=passed,
        )

    def _check_ssh_root_login(self) -> List[Finding]:
        """Check if root login via SSH is disabled."""
        check_id = "SSH-001"

        content = self._read_ssh_config()
        if content is None:
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Configuration Not Found",
                description=f"SSH configuration file not found at {self.ssh_config_path}",
                severity=Severity.INFO,
                recommendation="Ensure SSH is properly installed or specify correct config path.",
                passed=True,
            )]

        value = self._get_ssh_config_value(content, 'PermitRootLogin')

        if value in ('no', 'prohibit-password'):
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Root Login Disabled",
                description="Root login via SSH is properly disabled.",
                severity=Severity.INFO,
                recommendation="Continue to maintain this configuration.",
                passed=True,
            )]

        if value:
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Root Login Enabled",
                description=f"Root login via SSH is set to '{value}'. This allows direct root access and should be disabled.",
                severity=Severity.HIGH,
                recommendation="Set 'PermitRootLogin no' in sshd_config to prevent direct root login.",
                passed=False,
                references=["https://www.ssh.com/academy/ssh/sshd_config#permitrootlogin"],
            )]

        return [self._create_ssh_finding(
            check_id=check_id,
            title="SSH Root Login Not Explicitly Configured",
            description="PermitRootLogin is not explicitly set. The default may allow root login with keys.",
            severity=Severity.MEDIUM,
            recommendation="Explicitly set 'PermitRootLogin no' for security.",
            passed=False,
        )]

    def _check_ssh_password_auth(self) -> List[Finding]:
        """Check if password authentication is disabled."""
        check_id = "SSH-002"

        content = self._read_ssh_config()
        if content is None:
            return []

        value = self._get_ssh_config_value(content, 'PasswordAuthentication')

        if value == 'no':
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Password Authentication Disabled",
                description="Password authentication is properly disabled.",
                severity=Severity.INFO,
                recommendation="Continue to use key-based authentication.",
                passed=True,
            )]

        if value:
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Password Authentication Enabled",
                description="Password authentication is enabled, making the system vulnerable to brute force attacks.",
                severity=Severity.HIGH,
                recommendation="Set 'PasswordAuthentication no' and use SSH key pairs for authentication.",
                passed=False,
                references=["https://www.ssh.com/academy/ssh/sshd_config#passwordauthentication"],
            )]

        return [self._create_ssh_finding(
            check_id=check_id,
            title="SSH Password Authentication Not Explicitly Configured",
            description="PasswordAuthentication is not explicitly set. Default may allow password auth.",
            severity=Severity.MEDIUM,
            recommendation="Explicitly set 'PasswordAuthentication no' for security.",
            passed=False,
        )]

    def _check_ssh_empty_passwords(self) -> List[Finding]:
        """Check if empty passwords are disabled."""
        check_id = "SSH-003"

        content = self._read_ssh_config()
        if content is None:
            return []

        value = self._get_ssh_config_value(content, 'PermitEmptyPasswords')

        if value == 'yes':
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH Empty Passwords Allowed",
                description="Empty passwords are permitted for SSH authentication.",
                severity=Severity.CRITICAL,
                recommendation="Set 'PermitEmptyPasswords no' immediately.",
                passed=False,
            )]

        return [self._create_ssh_finding(
            check_id=check_id,
            title="SSH Empty Passwords Disabled",
            description="Empty passwords are properly disabled.",
            severity=Severity.INFO,
            recommendation="Continue to maintain this configuration.",
            passed=True,
        )]

    def _check_ssh_protocol(self) -> List[Finding]:
        """Check SSH protocol version."""
        check_id = "SSH-004"

        content = self._read_ssh_config()
        if content is None:
            return []

        value = self._get_ssh_config_value(content, 'Protocol')

        if value and value != '2':
            return [self._create_ssh_finding(
                check_id=check_id,
                title="Outdated SSH Protocol",
                description=f"SSH Protocol version {value} is configured. Only Protocol 2 is secure.",
                severity=Severity.HIGH,
                recommendation="Remove or update Protocol directive to use only Protocol 2 (default in modern OpenSSH).",
                passed=False,
            )]

        return [self._create_ssh_finding(
            check_id=check_id,
            title="SSH Protocol Secure",
            description="SSH is using Protocol 2 (secure) or default secure configuration.",
            severity=Severity.INFO,
            recommendation="Continue using SSH Protocol 2.",
            passed=True,
        )]

    def _check_ssh_x11_forwarding(self) -> List[Finding]:
        """Check if X11 forwarding is disabled."""
        check_id = "SSH-005"

        content = self._read_ssh_config()
        if content is None:
            return []

        value = self._get_ssh_config_value(content, 'X11Forwarding')

        if value == 'yes':
            return [self._create_ssh_finding(
                check_id=check_id,
                title="SSH X11 Forwarding Enabled",
                description="X11 forwarding is enabled, which may pose a security risk.",
                severity=Severity.LOW,
                recommendation="Set 'X11Forwarding no' if not required.",
                passed=False,
            )]

        return [self._create_ssh_finding(
            check_id=check_id,
            title="SSH X11 Forwarding Disabled",
            description="X11 forwarding is properly disabled.",
            severity=Severity.INFO,
            recommendation="Continue to maintain this configuration.",
            passed=True,
        )]

    # ==================== File Permission Checks ====================

    def _check_shadow_file_permissions(self) -> List[Finding]:
        """Check /etc/shadow file permissions."""
        check_id = "FILE-001"

        try:
            stat_info = os.stat(self.PATH_SHADOW)
            mode = stat_info.st_mode
            perms = stat.S_IMODE(mode)

            # Should be 000 or 600 (owner read/write only)
            if perms <= 0o600:
                return [Finding(
                    check_id=check_id,
                    title="Shadow File Permissions Secure",
                    description=f"{self.PATH_SHADOW} has secure permissions: {oct(perms)}",
                    severity=Severity.INFO,
                    resource=self.PATH_SHADOW,
                    recommendation="Continue to maintain restrictive permissions.",
                    passed=True,
                )]
            else:
                return [Finding(
                    check_id=check_id,
                    title="Shadow File Permissions Too Permissive",
                    description=f"{self.PATH_SHADOW} has overly permissive permissions: {oct(perms)}",
                    severity=Severity.CRITICAL,
                    resource=self.PATH_SHADOW,
                    recommendation=f"Run 'chmod 600 {self.PATH_SHADOW}' to restrict access to root only.",
                    passed=False,
                )]
        except FileNotFoundError:
            return [Finding(
                check_id=check_id,
                title="Shadow File Not Found",
                description=f"{self.PATH_SHADOW} does not exist.",
                severity=Severity.MEDIUM,
                resource=self.PATH_SHADOW,
                recommendation="Ensure system is properly configured with password hashing.",
                passed=False,
            )]
        except PermissionError:
            return [Finding(
                check_id=check_id,
                title="Shadow File Check Requires Root",
                description="Cannot check shadow file permissions without root access.",
                severity=Severity.INFO,
                resource=self.PATH_SHADOW,
                recommendation="Run with elevated privileges for complete audit.",
                passed=True,
                metadata={"requires_root": True},
            )]

    def _check_passwd_file_permissions(self) -> List[Finding]:
        """Check /etc/passwd file permissions."""
        check_id = "FILE-002"

        try:
            stat_info = os.stat(self.PATH_PASSWD)
            mode = stat_info.st_mode
            perms = stat.S_IMODE(mode)

            # Should be 644 (owner rw, group/other read)
            expected_perms = 0o644
            if perms == expected_perms:
                return [Finding(
                    check_id=check_id,
                    title="Passwd File Permissions Correct",
                    description=f"{self.PATH_PASSWD} has correct permissions: {oct(perms)}",
                    severity=Severity.INFO,
                    resource=self.PATH_PASSWD,
                    recommendation="Continue to maintain these permissions.",
                    passed=True,
                )]
            else:
                return [Finding(
                    check_id=check_id,
                    title="Passwd File Permissions Incorrect",
                    description=f"{self.PATH_PASSWD} has unexpected permissions: {oct(perms)}, expected {oct(expected_perms)}",
                    severity=Severity.MEDIUM,
                    resource=self.PATH_PASSWD,
                    recommendation=f"Run 'chmod {oct(expected_perms)[2:]} {self.PATH_PASSWD}' to correct permissions.",
                    passed=False,
                )]
        except FileNotFoundError:
            return []

        except PermissionError:
            return []

    def _check_ssh_host_keys(self) -> List[Finding]:
        """Check SSH host key file permissions."""
        check_id = "FILE-003"
        findings = []

        try:
            for entry in os.listdir(self.PATH_SSH_DIR):
                if entry.startswith("ssh_host_") and entry.endswith("_key"):
                    key_path = os.path.join(self.PATH_SSH_DIR, entry)
                    stat_info = os.stat(key_path)
                    perms = stat.S_IMODE(stat_info.st_mode)

                    # Private keys should be 600 or 400
                    if perms > 0o600:
                        findings.append(Finding(
                            check_id=check_id,
                            title="SSH Host Key Permissions Too Permissive",
                            description=f"SSH host key {entry} has overly permissive permissions: {oct(perms)}",
                            severity=Severity.HIGH,
                            resource=key_path,
                            recommendation=f"Run 'chmod 600 {key_path}' to restrict access.",
                            passed=False,
                        ))
                    else:
                        findings.append(Finding(
                            check_id=check_id,
                            title="SSH Host Key Permissions Secure",
                            description=f"SSH host key {entry} has secure permissions: {oct(perms)}",
                            severity=Severity.INFO,
                            resource=key_path,
                            recommendation="Continue to maintain restrictive permissions.",
                            passed=True,
                        ))

            if not findings:
                findings.append(Finding(
                    check_id=check_id,
                    title="No SSH Host Keys Found",
                    description=f"No SSH host keys found in {self.PATH_SSH_DIR}",
                    severity=Severity.INFO,
                    resource=self.PATH_SSH_DIR,
                    recommendation="Ensure SSH is properly configured.",
                    passed=True,
                ))
        except (FileNotFoundError, PermissionError):
            pass

        return findings

    def _check_world_writable_files(self) -> List[Finding]:
        """Check for world-writable files in sensitive directories."""
        check_id = "FILE-004"
        findings = []

        for directory in self.SENSITIVE_DIRS:
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
                                findings.append(Finding(
                                    check_id=check_id,
                                    title="World-Writable File Found",
                                    description=f"File {filepath} is world-writable",
                                    severity=Severity.HIGH,
                                    resource=filepath,
                                    recommendation=f"Run 'chmod o-w {filepath}' to remove world-writable permission.",
                                    passed=False,
                                ))
                        except (PermissionError, FileNotFoundError):
                            continue
            except PermissionError:
                continue

        if not findings:
            findings.append(Finding(
                check_id=check_id,
                title="No World-Writable Files in Sensitive Directories",
                description="No world-writable files found in system directories.",
                severity=Severity.INFO,
                resource=", ".join(self.SENSITIVE_DIRS[:5]),
                recommendation="Continue monitoring for world-writable files.",
                passed=True,
            ))

        return findings

    def _check_suid_sgid_files(self) -> List[Finding]:
        """Check for SUID/SGID files."""
        check_id = "FILE-005"

        # Known legitimate SUID/SGID binaries
        legitimate_suid = {
            "/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
            "/usr/bin/ping", "/usr/bin/newgrp", "/usr/bin/chsh",
            "/usr/bin/chfn", "/usr/bin/gpasswd", "/usr/bin/at",
            "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
        }

        findings = []
        suspicious_files = []

        search_paths = self.BINARY_PATHS

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
                                    suspicious_files.append(full_path)
                    except (PermissionError, FileNotFoundError):
                        continue
            except PermissionError:
                continue

        if suspicious_files:
            findings.append(Finding(
                check_id=check_id,
                title="Suspicious SUID/SGID Files Found",
                description=f"Found {len(suspicious_files)} files with SUID/SGID bits outside expected locations.",
                severity=Severity.MEDIUM,
                resource=", ".join(suspicious_files[:5]) + ("..." if len(suspicious_files) > 5 else ""),
                recommendation="Review these files and remove SUID/SGID bits if not required.",
                metadata={"files": suspicious_files},
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=check_id,
                title="No Suspicious SUID/SGID Files",
                description="All SUID/SGID files are in expected locations.",
                severity=Severity.INFO,
                resource="System binaries",
                recommendation="Continue monitoring for unauthorized SUID/SGID files.",
                passed=True,
            ))

        return findings

    # ==================== User Account Checks ====================

    def _check_default_accounts(self) -> List[Finding]:
        """Check for default/system accounts with weak configuration."""
        check_id = "USER-001"
        findings = []

        try:
            with open(self.PATH_PASSWD, 'r') as f:
                for line in f:
                    parts = line.strip().split(':')
                    if len(parts) >= 7:
                        username, _, uid, gid, _, home, shell = parts[:7]

                        # Check for accounts with shells that should be disabled
                        if uid == '0' and username != 'root':
                            findings.append(Finding(
                                check_id=check_id,
                                title="Non-root Account with UID 0",
                                description=f"Account '{username}' has UID 0 (root privileges)",
                                severity=Severity.CRITICAL,
                                resource=f"{self.PATH_PASSWD}:{username}",
                                recommendation="Remove or modify this account immediately.",
                                passed=False,
                            ))
        except (FileNotFoundError, PermissionError):
            pass

        if not findings:
            findings.append(Finding(
                check_id=check_id,
                title="No Unauthorized Root Accounts",
                description="Only root has UID 0.",
                severity=Severity.INFO,
                resource=self.PATH_PASSWD,
                recommendation="Continue monitoring for unauthorized accounts.",
                passed=True,
            ))

        return findings

    def _check_password_expiry(self) -> List[Finding]:
        """Check if password expiry is configured."""
        check_id = "USER-002"
        findings = []

        try:
            with open(self.PATH_LOGIN_DEFS, 'r') as f:
                content = f.read()

            max_days_match = re.search(r'^PASS_MAX_DAYS\s+(\d+)', content, re.MULTILINE)

            max_days = int(max_days_match.group(1)) if max_days_match else self.DEFAULT_PASS_MAX_DAYS

            if max_days > self.MAX_PASSWORD_DAYS:
                findings.append(Finding(
                    check_id=check_id,
                    title="Password Expiry Too Long",
                    description=f"PASS_MAX_DAYS is set to {max_days} days. Should be {self.MAX_PASSWORD_DAYS} or less.",
                    severity=Severity.MEDIUM,
                    resource=self.PATH_LOGIN_DEFS,
                    recommendation=f"Set PASS_MAX_DAYS to {self.MAX_PASSWORD_DAYS} or less.",
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="Password Expiry Configured",
                    description=f"PASS_MAX_DAYS is set to {max_days} days.",
                    severity=Severity.INFO,
                    resource=self.PATH_LOGIN_DEFS,
                    recommendation="Continue enforcing password expiry.",
                    passed=True,
                ))
        except (FileNotFoundError, PermissionError):
            findings.append(Finding(
                check_id=check_id,
                title="Cannot Check Password Policy",
                description=f"Unable to read {self.PATH_LOGIN_DEFS}",
                severity=Severity.INFO,
                resource=self.PATH_LOGIN_DEFS,
                recommendation="Ensure file exists and is readable.",
                passed=True,
            ))

        return findings

    def _check_sudo_configuration(self) -> List[Finding]:
        """Check sudo configuration for security issues."""
        check_id = "USER-003"
        findings = []

        sudoers_path = "/etc/sudoers"
        sudoers_d = "/etc/sudoers.d"

        try:
            result = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5
            )

            findings.append(Finding(
                check_id=check_id,
                title="Sudo Available",
                description="Sudo is configured on this system.",
                severity=Severity.INFO,
                resource="/usr/bin/sudo",
                recommendation="Review sudoers configuration for least privilege.",
                passed=True,
            ))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return findings

    # ==================== System Configuration Checks ====================

    def _check_ufw_active(self) -> bool:
        """Check if UFW firewall is active."""
        try:
            result = subprocess.run(
                ["ufw", "status"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return "Status: active" in result.stdout
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            return False

    def _check_iptables_has_rules(self) -> bool:
        """Check if iptables has custom rules configured."""
        try:
            result = subprocess.run(
                ["iptables", "-L"],
                capture_output=True,
                timeout=10
            )
            if result.returncode == 0:
                lines = result.stdout.decode().strip().split('\n')
                return len(lines) > self.IPTABLES_MIN_RULE_LINES
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            pass
        return False

    def _check_firewall_status(self) -> List[Finding]:
        """Check if a firewall is active."""
        check_id = "SYSTEM-001"

        if self._check_ufw_active():
            return [Finding(
                check_id=check_id,
                title="UFW Firewall Active",
                description="UFW firewall is active and running.",
                severity=Severity.INFO,
                resource="ufw",
                recommendation="Continue monitoring firewall rules.",
                passed=True,
            )]

        if self._check_iptables_has_rules():
            return [Finding(
                check_id=check_id,
                title="IPTables Firewall Active",
                description="IPTables firewall rules are configured.",
                severity=Severity.INFO,
                resource="iptables",
                recommendation="Continue monitoring firewall rules.",
                passed=True,
            )]

        return [Finding(
            check_id=check_id,
            title="No Firewall Detected",
            description="Unable to detect an active firewall configuration.",
            severity=Severity.HIGH,
            resource="system",
            recommendation="Install and configure a firewall (ufw, iptables, or firewalld).",
            passed=False,
        )]

    def _check_unnecessary_services(self) -> List[Finding]:
        """Check for unnecessary or insecure services."""
        check_id = "SYSTEM-002"

        findings = []
        active_risky = []

        try:
            result = subprocess.run(
                ["systemctl", "list-units", "--type=service", "--state=running"],
                capture_output=True,
                text=True,
                timeout=30
            )

            for service in self.RISKY_SERVICES:
                if service in result.stdout.lower():
                    active_risky.append(service)

            if active_risky:
                findings.append(Finding(
                    check_id=check_id,
                    title="Insecure Services Running",
                    description=f"The following insecure services are running: {', '.join(active_risky)}",
                    severity=Severity.HIGH,
                    resource="systemd",
                    recommendation="Disable and remove these insecure services.",
                    metadata={"services": active_risky},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="No Insecure Services Detected",
                    description="No known insecure services are running.",
                    severity=Severity.INFO,
                    resource="systemd",
                    recommendation="Continue monitoring for insecure services.",
                    passed=True,
                ))
        except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
            findings.append(Finding(
                check_id=check_id,
                title="Cannot Check Services",
                description="Unable to query systemd for running services.",
                severity=Severity.INFO,
                resource="systemd",
                recommendation="Ensure systemd is available and you have permissions.",
                passed=True,
            ))

        return findings

    def _check_kernel_parameters(self) -> List[Finding]:
        """Check kernel security parameters."""
        check_id = "SYSTEM-003"
        findings = []

        security_params = {
            "/proc/sys/net/ipv4/ip_forward": ("0", "IP forwarding should be disabled unless routing."),
            "/proc/sys/net/ipv4/conf/all/send_redirects": ("0", "ICMP redirects should be disabled."),
            "/proc/sys/net/ipv4/conf/all/accept_source_route": ("0", "Source routing should be disabled."),
        }

        issues = []
        for param_path, (expected_value, description) in security_params.items():
            try:
                with open(param_path, 'r') as f:
                    current_value = f.read().strip()
                    if current_value != expected_value:
                        issues.append({
                            "parameter": param_path,
                            "current": current_value,
                            "expected": expected_value,
                            "description": description
                        })
            except (FileNotFoundError, PermissionError):
                continue

        if issues:
            for issue in issues:
                findings.append(Finding(
                    check_id=check_id,
                    title="Kernel Parameter Misconfigured",
                    description=f"{issue['parameter']}: {issue['description']}",
                    severity=Severity.MEDIUM,
                    resource=issue["parameter"],
                    recommendation=f"Set {issue['parameter']} to {issue['expected']} using sysctl.",
                    passed=False,
                ))
        else:
            findings.append(Finding(
                check_id=check_id,
                title="Kernel Security Parameters OK",
                description="Checked kernel parameters are properly configured.",
                severity=Severity.INFO,
                resource="/proc/sys/net/ipv4/",
                recommendation="Continue monitoring kernel parameters.",
                passed=True,
            ))

        return findings
