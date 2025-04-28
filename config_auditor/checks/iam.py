"""
AWS IAM security checks.

Provides reusable check functions for IAM policy and user validation.
"""

import json
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from ..utils.severity import Finding, Severity

try:
    import boto3
    from botocore.exceptions import ClientError
    IAM_AVAILABLE = True
except ImportError:
    IAM_AVAILABLE = False


class IAMChecks:
    """
    Collection of IAM security check functions.

    These checks validate IAM configurations against
    security best practices.
    """

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        """
        Initialize IAM checks.

        Args:
            region: AWS region
            profile: AWS credentials profile
        """
        if not IAM_AVAILABLE:
            raise ImportError("boto3 is required for IAM checks")

        self.region = region
        self.profile = profile
        self._iam_client = None

    @property
    def iam(self):
        """Get or create IAM client."""
        if self._iam_client is None:
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
            else:
                session = boto3.Session()
            self._iam_client = session.client('iam')
        return self._iam_client

    def check_user_mfa(self, username: str) -> Finding:
        """
        Check if an IAM user has MFA enabled.

        Args:
            username: IAM username

        Returns:
            Finding with check result
        """
        check_id = f"IAM-MFA-{username}"

        try:
            # Check if user has console access
            try:
                self.iam.get_login_profile(UserName=username)
                has_console_access = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchEntity':
                    has_console_access = False
                else:
                    raise

            if not has_console_access:
                return Finding(
                    check_id=check_id,
                    title=f"User '{username}' No Console Access",
                    description="User does not have console access, MFA not required.",
                    severity=Severity.INFO,
                    resource=f"IAM User: {username}",
                    recommendation="MFA only needed for console users.",
                    passed=True,
                )

            # Check MFA devices
            mfa_devices = self.iam.list_mfa_devices(UserName=username)['MFADevices']

            if mfa_devices:
                return Finding(
                    check_id=check_id,
                    title=f"User '{username}' Has MFA",
                    description=f"MFA enabled with {len(mfa_devices)} device(s).",
                    severity=Severity.INFO,
                    resource=f"IAM User: {username}",
                    recommendation="Continue enforcing MFA.",
                    passed=True,
                )
            else:
                return Finding(
                    check_id=check_id,
                    title=f"User '{username}' Missing MFA",
                    description="Console user does not have MFA enabled.",
                    severity=Severity.HIGH,
                    resource=f"IAM User: {username}",
                    recommendation="Enable MFA immediately.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_virtual.html"],
                    passed=False,
                )

        except ClientError as e:
            return Finding(
                check_id=check_id,
                title=f"Cannot Check User '{username}'",
                description=f"Error: {e.response['Error']['Code']}",
                severity=Severity.INFO,
                resource=f"IAM User: {username}",
                recommendation="Verify user exists and permissions.",
                passed=True,
            )

    def check_access_key_age(
        self,
        username: str,
        max_age_days: int = 90
    ) -> Finding:
        """
        Check age of access keys.

        Args:
            username: IAM username
            max_age_days: Maximum recommended key age

        Returns:
            Finding with check result
        """
        check_id = f"IAM-KEY-AGE-{username}"

        try:
            keys = self.iam.list_access_keys(UserName=username)['AccessKeyMetadata']

            old_keys = []
            for key in keys:
                create_date = key['CreateDate']
                age_days = (datetime.now(timezone.utc) - create_date).days

                if age_days > max_age_days:
                    old_keys.append({
                        "key_id": key['AccessKeyId'][-4:].rjust(20, '*'),
                        "status": key['Status'],
                        "age_days": age_days
                    })

            if old_keys:
                return Finding(
                    check_id=check_id,
                    title=f"User '{username}' Has Old Access Keys",
                    description=f"Found {len(old_keys)} key(s) older than {max_age_days} days.",
                    severity=Severity.MEDIUM,
                    resource=f"IAM User: {username}",
                    recommendation="Rotate access keys regularly.",
                    metadata={"keys": old_keys},
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title=f"User '{username}' Keys Are Recent",
                description="All access keys are within recommended age.",
                severity=Severity.INFO,
                resource=f"IAM User: {username}",
                recommendation="Continue rotating keys regularly.",
                passed=True,
            )

        except ClientError:
            return Finding(
                check_id=check_id,
                title=f"User '{username}' Has No Access Keys",
                description="No access keys found.",
                severity=Severity.INFO,
                resource=f"IAM User: {username}",
                recommendation="Access keys not always required.",
                passed=True,
            )

    def check_password_policy(self) -> Finding:
        """
        Check IAM password policy strength.

        Returns:
            Finding with check result
        """
        check_id = "IAM-PASSWORD-POLICY"

        try:
            policy = self.iam.get_account_password_policy()['PasswordPolicy']

            issues = []

            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("Missing uppercase requirement")
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append("Missing lowercase requirement")
            if not policy.get('RequireSymbols', False):
                issues.append("Missing symbol requirement")
            if not policy.get('RequireNumbers', False):
                issues.append("Missing number requirement")
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append(f"Min length {policy.get('MinimumPasswordLength', 6)}, should be 14+")
            max_age = policy.get('MaxPasswordAge', 0)
            if max_age > 90 or max_age == 0:
                issues.append("Password expiry not properly configured")

            if issues:
                return Finding(
                    check_id=check_id,
                    title="Weak Password Policy",
                    description=f"Issues: {'; '.join(issues)}",
                    severity=Severity.MEDIUM,
                    resource="IAM Password Policy",
                    recommendation="Strengthen password policy.",
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title="Strong Password Policy",
                description="Password policy meets security requirements.",
                severity=Severity.INFO,
                resource="IAM Password Policy",
                recommendation="Continue enforcing strong passwords.",
                passed=True,
            )

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                return Finding(
                    check_id=check_id,
                    title="No Custom Password Policy",
                    description="Using AWS default password policy.",
                    severity=Severity.MEDIUM,
                    resource="IAM Password Policy",
                    recommendation="Configure a custom password policy.",
                    passed=False,
                )
            raise

    def check_policy_for_wildcards(
        self,
        policy_name: str,
        policy_arn: str
    ) -> Finding:
        """
        Check if an IAM policy has overly permissive wildcards.

        Args:
            policy_name: Name of the policy
            policy_arn: ARN of the policy

        Returns:
            Finding with check result
        """
        check_id = f"IAM-POLICY-{policy_name}"

        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)['Policy']
            version_id = policy['DefaultVersionId']

            version = self.iam.get_policy_version(
                PolicyArn=policy_arn,
                VersionId=version_id
            )['PolicyVersion']

            doc = version['Document']
            statements = doc.get('Statement', [])
            if isinstance(statements, dict):
                statements = [statements]

            wildcard_issues = []

            for statement in statements:
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])

                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]

                    # Check for Action: * with Resource: *
                    if '*' in actions and '*' in resources:
                        wildcard_issues.append("Allows all actions on all resources")
                        break
                    # Check for Action: * on specific resource
                    elif '*' in actions:
                        wildcard_issues.append("Allows all actions")
                    # Check for Resource: * with sensitive actions
                    elif '*' in resources:
                        sensitive_actions = ['iam:', 'kms:', 'secretsmanager:', 's3:']
                        for action in actions:
                            if any(s in action for s in sensitive_actions):
                                wildcard_issues.append(f"Allows {action} on all resources")
                                break

            if wildcard_issues:
                return Finding(
                    check_id=check_id,
                    title=f"Policy '{policy_name}' Too Permissive",
                    description=f"Issues: {'; '.join(wildcard_issues[:3])}",
                    severity=Severity.HIGH,
                    resource=policy_arn,
                    recommendation="Apply principle of least privilege.",
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title=f"Policy '{policy_name}' OK",
                description="Policy follows least privilege principles.",
                severity=Severity.INFO,
                resource=policy_arn,
                recommendation="Continue following least privilege.",
                passed=True,
            )

        except ClientError:
            return Finding(
                check_id=check_id,
                title=f"Cannot Check Policy '{policy_name}'",
                description="Unable to analyze policy.",
                severity=Severity.INFO,
                resource=policy_arn,
                recommendation="Verify policy exists.",
                passed=True,
            )

    def check_root_mfa(self) -> Finding:
        """
        Check if root account has MFA enabled.

        Returns:
            Finding with check result
        """
        check_id = "IAM-ROOT-MFA"

        try:
            summary = self.iam.get_account_summary()['SummaryMap']

            if summary.get('AccountMFAEnabled', 0) == 1:
                return Finding(
                    check_id=check_id,
                    title="Root Account MFA Enabled",
                    description="AWS root account has MFA enabled.",
                    severity=Severity.INFO,
                    resource="AWS Root Account",
                    recommendation="Continue protecting root with MFA.",
                    passed=True,
                )
            else:
                return Finding(
                    check_id=check_id,
                    title="Root Account MFA Not Enabled",
                    description="AWS root account does not have MFA enabled.",
                    severity=Severity.CRITICAL,
                    resource="AWS Root Account",
                    recommendation="Enable MFA on root account immediately.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"],
                    passed=False,
                )

        except ClientError:
            return Finding(
                check_id=check_id,
                title="Cannot Check Root MFA",
                description="Unable to verify root MFA status.",
                severity=Severity.INFO,
                resource="AWS Root Account",
                recommendation="Verify IAM permissions.",
                passed=True,
            )
