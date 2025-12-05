"""
Tests for AWS configuration auditor.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone

from config_auditor.auditors.aws import AWSAuditor
from config_auditor.utils.severity import Severity, Finding


# Skip all tests in this module if boto3 is not available
pytest.importorskip("boto3", reason="boto3 not installed")


class TestAWSAuditor:
    """Test cases for AWSAuditor class."""

    def test_init(self):
        """Test auditor initialization."""
        auditor = AWSAuditor()
        assert auditor.name == "AWS Cloud Auditor"
        assert len(auditor.checks) > 0

    def test_init_with_region(self):
        """Test initialization with custom region."""
        auditor = AWSAuditor(region="us-west-2")
        assert auditor.region == "us-west-2"

    def test_init_with_profile(self):
        """Test initialization with profile."""
        auditor = AWSAuditor(profile="production")
        assert auditor.profile == "production"

    def test_check_list_not_empty(self):
        """Test that checks list is not empty."""
        auditor = AWSAuditor()
        assert len(auditor.checks) > 0
        assert "S3-001" in auditor.checks
        assert "IAM-001" in auditor.checks


class TestS3Checks:
    """Test cases for S3 bucket checks."""

    @patch('boto3.Session')
    def test_check_s3_public_access_via_acl(self, mock_session):
        """Test detection of public S3 bucket via ACL."""
        from botocore.exceptions import ClientError

        mock_s3_client = Mock()
        mock_session.return_value.client.return_value = mock_s3_client

        # Mock list_buckets response
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [{'Name': 'test-bucket', 'CreationDate': datetime.now(timezone.utc)}]
        }

        # Mock get_bucket_acl response with public access
        mock_s3_client.get_bucket_acl.return_value = {
            'Grants': [{
                'Grantee': {
                    'URI': 'http://acs.amazonaws.com/groups/global/AllUsers',
                    'Type': 'Group'
                },
                'Permission': 'READ'
            }]
        }

        # Mock get_bucket_policy to raise NoSuchBucketPolicy error
        error_response = {'Error': {'Code': 'NoSuchBucketPolicy'}}
        mock_s3_client.get_bucket_policy.side_effect = ClientError(error_response, 'GetBucketPolicy')

        # Mock get_caller_identity
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_session.return_value.client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_s3_client

        auditor = AWSAuditor()

        # Need to patch _get_client properly
        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_s3_client
            findings = auditor._check_s3_public_access()

        # Should find public bucket
        assert any(f.severity == Severity.CRITICAL and not f.passed for f in findings)

    @patch('boto3.Session')
    def test_check_s3_encryption_missing(self, mock_session):
        """Test detection of missing S3 encryption."""
        from botocore.exceptions import ClientError

        mock_s3_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [{'Name': 'test-bucket', 'CreationDate': datetime.now(timezone.utc)}]
        }

        # Mock get_bucket_encryption to raise exception
        error_response = {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}
        mock_s3_client.get_bucket_encryption.side_effect = ClientError(error_response, 'GetBucketEncryption')

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_s3_client
            findings = auditor._check_s3_encryption()

        # Should find unencrypted bucket
        assert any(f.severity == Severity.HIGH and not f.passed for f in findings)

    @patch('boto3.Session')
    def test_check_s3_versioning_disabled(self, mock_session):
        """Test detection of disabled S3 versioning."""
        mock_s3_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_s3_client.list_buckets.return_value = {
            'Buckets': [{'Name': 'test-bucket', 'CreationDate': datetime.now(timezone.utc)}]
        }
        mock_s3_client.get_bucket_versioning.return_value = {'Status': 'Suspended'}

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_s3_client
            findings = auditor._check_s3_versioning()

        # Should find non-versioned bucket
        assert any(f.severity == Severity.MEDIUM and not f.passed for f in findings)


class TestIAMChecks:
    """Test cases for IAM checks."""

    @patch('boto3.Session')
    def test_check_iam_users_without_mfa(self, mock_session):
        """Test detection of IAM users without MFA."""
        mock_iam_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_iam_client.list_users.return_value = {
            'Users': [{'UserName': 'test-user', 'UserId': 'AIDA123456789'}]
        }
        mock_iam_client.get_login_profile.return_value = {'LoginProfile': {'UserName': 'test-user'}}
        mock_iam_client.list_mfa_devices.return_value = {'MFADevices': []}

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_iam_client
            findings = auditor._check_iam_mfa()

        # Should find user without MFA
        assert any(f.severity == Severity.HIGH and not f.passed for f in findings)

    @patch('boto3.Session')
    def test_check_password_policy_weak(self, mock_session):
        """Test detection of weak password policy."""
        from botocore.exceptions import ClientError

        mock_iam_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_iam_client.get_account_password_policy.return_value = {
            'PasswordPolicy': {
                'MinimumPasswordLength': 8,
                'RequireUppercaseCharacters': False,
                'RequireLowercaseCharacters': False,
                'RequireSymbols': False,
                'RequireNumbers': False,
            }
        }

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_iam_client
            findings = auditor._check_iam_password_policy()

        # Should find weak password policy
        assert any(f.severity == Severity.MEDIUM and not f.passed for f in findings)


class TestSecurityGroupChecks:
    """Test cases for security group checks."""

    @patch('boto3.Session')
    def test_check_ssh_open_to_world(self, mock_session):
        """Test detection of SSH open to world."""
        mock_ec2_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_ec2_client.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-12345',
                'GroupName': 'default',
                'IpPermissions': [{
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            }]
        }

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_ec2_client
            findings = auditor._check_security_group_ssh()

        # Should find SSH open to world
        assert any(f.severity == Severity.HIGH and not f.passed for f in findings)

    @patch('boto3.Session')
    def test_check_rdp_open_to_world(self, mock_session):
        """Test detection of RDP open to world."""
        mock_ec2_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_ec2_client.describe_security_groups.return_value = {
            'SecurityGroups': [{
                'GroupId': 'sg-12345',
                'GroupName': 'default',
                'IpPermissions': [{
                    'FromPort': 3389,
                    'ToPort': 3389,
                    'IpProtocol': 'tcp',
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            }]
        }

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_ec2_client
            findings = auditor._check_security_group_rdp()

        # Should find RDP open to world (critical)
        assert any(f.severity == Severity.CRITICAL and not f.passed for f in findings)


class TestRootAccountChecks:
    """Test cases for root account checks."""

    @patch('boto3.Session')
    def test_check_root_mfa_not_enabled(self, mock_session):
        """Test detection of root MFA not enabled."""
        mock_iam_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_iam_client.get_account_summary.return_value = {
            'SummaryMap': {'AccountMFAEnabled': 0}
        }

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_iam_client
            findings = auditor._check_root_mfa()

        # Should find root without MFA
        assert any(f.severity == Severity.CRITICAL and not f.passed for f in findings)

    @patch('boto3.Session')
    def test_check_root_mfa_enabled(self, mock_session):
        """Test detection of root MFA enabled."""
        mock_iam_client = Mock()
        mock_sts_client = Mock()

        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_iam_client.get_account_summary.return_value = {
            'SummaryMap': {'AccountMFAEnabled': 1}
        }

        auditor = AWSAuditor()

        with patch.object(auditor, '_get_client') as mock_get_client:
            mock_get_client.side_effect = lambda service: mock_sts_client if service == 'sts' else mock_iam_client
            findings = auditor._check_root_mfa()

        # Should pass
        assert any(f.passed for f in findings)


class TestAWSAuditorRun:
    """Test cases for running complete AWS audits."""

    @patch('boto3.Session')
    def test_run_all_checks_no_credentials(self, mock_session):
        """Test running all checks without credentials."""
        from botocore.exceptions import NoCredentialsError

        mock_session.return_value.client.side_effect = NoCredentialsError()

        auditor = AWSAuditor()
        findings = auditor.run_all_checks()

        # Should return info finding about credentials
        assert len(findings) >= 1
        assert any("Credentials" in f.title for f in findings)
