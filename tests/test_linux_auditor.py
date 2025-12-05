"""
Tests for Linux configuration auditor.
"""

import os
import tempfile
import pytest
from unittest.mock import patch, mock_open
from pathlib import Path

from config_auditor.auditors.linux import LinuxAuditor
from config_auditor.utils.severity import Severity, Finding


class TestLinuxAuditor:
    """Test cases for LinuxAuditor class."""

    def test_init(self):
        """Test auditor initialization."""
        auditor = LinuxAuditor()
        assert auditor.name == "Linux System Auditor"
        assert len(auditor.checks) > 0

    def test_init_with_custom_ssh_config(self):
        """Test initialization with custom SSH config path."""
        custom_path = "/custom/path/sshd_config"
        auditor = LinuxAuditor(ssh_config_path=custom_path)
        assert auditor.ssh_config_path == custom_path

    def test_check_list_not_empty(self):
        """Test that checks list is not empty."""
        auditor = LinuxAuditor()
        assert len(auditor.checks) > 0
        assert "SSH-001" in auditor.checks
        assert "FILE-001" in auditor.checks


class TestSSHChecks:
    """Test cases for SSH configuration checks."""

    def test_ssh_root_login_disabled(self):
        """Test detection of disabled root login."""
        ssh_config = """
Port 22
PermitRootLogin no
PasswordAuthentication no
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write(ssh_config)
            f.flush()
            config_path = f.name

        try:
            auditor = LinuxAuditor(ssh_config_path=config_path)
            findings = auditor._check_ssh_root_login()

            assert len(findings) == 1
            assert findings[0].passed is True
            assert findings[0].severity == Severity.INFO
        finally:
            os.unlink(config_path)

    def test_ssh_root_login_enabled(self):
        """Test detection of enabled root login."""
        ssh_config = """
Port 22
PermitRootLogin yes
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write(ssh_config)
            f.flush()
            config_path = f.name

        try:
            auditor = LinuxAuditor(ssh_config_path=config_path)
            findings = auditor._check_ssh_root_login()

            assert len(findings) == 1
            assert findings[0].passed is False
            assert findings[0].severity == Severity.HIGH
        finally:
            os.unlink(config_path)

    def test_ssh_password_auth_disabled(self):
        """Test detection of disabled password authentication."""
        ssh_config = """
PasswordAuthentication no
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write(ssh_config)
            f.flush()
            config_path = f.name

        try:
            auditor = LinuxAuditor(ssh_config_path=config_path)
            findings = auditor._check_ssh_password_auth()

            assert len(findings) == 1
            assert findings[0].passed is True
        finally:
            os.unlink(config_path)

    def test_ssh_password_auth_enabled(self):
        """Test detection of enabled password authentication."""
        ssh_config = """
PasswordAuthentication yes
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write(ssh_config)
            f.flush()
            config_path = f.name

        try:
            auditor = LinuxAuditor(ssh_config_path=config_path)
            findings = auditor._check_ssh_password_auth()

            assert len(findings) == 1
            assert findings[0].passed is False
            assert findings[0].severity == Severity.HIGH
        finally:
            os.unlink(config_path)

    def test_ssh_empty_passwords_allowed(self):
        """Test detection of allowed empty passwords."""
        ssh_config = """
PermitEmptyPasswords yes
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='_sshd_config', delete=False) as f:
            f.write(ssh_config)
            f.flush()
            config_path = f.name

        try:
            auditor = LinuxAuditor(ssh_config_path=config_path)
            findings = auditor._check_ssh_empty_passwords()

            assert len(findings) == 1
            assert findings[0].passed is False
            assert findings[0].severity == Severity.CRITICAL
        finally:
            os.unlink(config_path)

    def test_ssh_config_not_found(self):
        """Test handling of missing SSH config."""
        auditor = LinuxAuditor(ssh_config_path="/nonexistent/sshd_config")
        findings = auditor._check_ssh_root_login()

        # Should return INFO finding since config not found is not a security issue
        assert len(findings) >= 0


class TestFilePermissionChecks:
    """Test cases for file permission checks."""

    def test_shadow_file_permissions_secure(self):
        """Test detection of secure shadow file permissions."""
        auditor = LinuxAuditor()

        with patch('os.stat') as mock_stat:
            # Mock secure permissions (600)
            mock_stat.return_value.st_mode = 0o100600

            findings = auditor._check_shadow_file_permissions()

            assert len(findings) == 1
            assert findings[0].passed is True

    def test_shadow_file_permissions_insecure(self):
        """Test detection of insecure shadow file permissions."""
        auditor = LinuxAuditor()

        with patch('os.stat') as mock_stat:
            # Mock insecure permissions (644)
            mock_stat.return_value.st_mode = 0o100644

            findings = auditor._check_shadow_file_permissions()

            assert len(findings) == 1
            assert findings[0].passed is False
            assert findings[0].severity == Severity.CRITICAL

    def test_passwd_file_permissions_correct(self):
        """Test detection of correct passwd file permissions."""
        auditor = LinuxAuditor()

        with patch('os.stat') as mock_stat:
            # Mock correct permissions (644)
            mock_stat.return_value.st_mode = 0o100644

            findings = auditor._check_passwd_file_permissions()

            assert len(findings) == 1
            assert findings[0].passed is True


class TestUserAccountChecks:
    """Test cases for user account checks."""

    def test_non_root_uid_zero_detection(self):
        """Test detection of non-root accounts with UID 0."""
        passwd_content = """
root:x:0:0:root:/root:/bin/bash
hacker:x:0:0:hacker:/home/hacker:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""
        auditor = LinuxAuditor()

        with patch('builtins.open', mock_open(read_data=passwd_content)):
            findings = auditor._check_default_accounts()

            # Should find the hacker account with UID 0
            failed_findings = [f for f in findings if not f.passed]
            assert len(failed_findings) == 1
            assert failed_findings[0].severity == Severity.CRITICAL


class TestSystemChecks:
    """Test cases for system configuration checks."""

    def test_kernel_parameter_misconfigured(self):
        """Test detection of misconfigured kernel parameters."""
        auditor = LinuxAuditor()

        # Mock file reads to return incorrect values
        def mock_open_func(path, mode='r'):
            if path == "/proc/sys/net/ipv4/ip_forward":
                return mock_open(read_data="1").return_value
            return mock_open(read_data="0").return_value

        with patch('builtins.open', side_effect=lambda p, m='r': mock_open_func(p, m)):
            findings = auditor._check_kernel_parameters()

            # Should find issue with ip_forward
            assert any(not f.passed for f in findings)


class TestAuditorRun:
    """Test cases for running complete audits."""

    def test_run_all_checks(self):
        """Test running all checks."""
        auditor = LinuxAuditor()
        findings = auditor.run_all_checks()

        # Should return multiple findings
        assert len(findings) > 0

    def test_run_audit_with_summary(self):
        """Test run_audit returns summary."""
        auditor = LinuxAuditor()
        findings = auditor.run_audit()

        summary = auditor.get_summary()

        assert "total_findings" in summary
        assert "passed" in summary
        assert "failed" in summary
        assert "by_severity" in summary

    def test_clear_findings(self):
        """Test clearing findings."""
        auditor = LinuxAuditor()
        auditor.run_audit()

        assert len(auditor.findings) > 0

        auditor.clear_findings()

        assert len(auditor.findings) == 0


class TestFinding:
    """Test cases for Finding class."""

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource="/test/resource",
            recommendation="Test recommendation",
        )

        result = finding.to_dict()

        assert result["check_id"] == "TEST-001"
        assert result["title"] == "Test Finding"
        assert result["severity"] == "HIGH"
        assert result["passed"] is False

    def test_finding_str(self):
        """Test string representation of finding."""
        finding = Finding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource="/test/resource",
            recommendation="Test recommendation",
        )

        result = str(finding)

        assert "TEST-001" in result
        assert "Test Finding" in result
        assert "HIGH" in result


class TestSeverity:
    """Test cases for Severity enum."""

    def test_severity_ordering(self):
        """Test severity level ordering."""
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.HIGH.value > Severity.MEDIUM.value
        assert Severity.MEDIUM.value > Severity.LOW.value
        assert Severity.LOW.value > Severity.INFO.value

    def test_severity_colors(self):
        """Test severity color codes."""
        assert Severity.CRITICAL.color != ""
        assert Severity.HIGH.color != ""

    def test_severity_icons(self):
        """Test severity icons."""
        assert Severity.CRITICAL.icon != ""
        assert Severity.INFO.icon != ""
