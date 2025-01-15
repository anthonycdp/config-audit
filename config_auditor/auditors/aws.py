"""
AWS cloud environment configuration auditor.

Performs security checks on AWS resources including S3 buckets,
IAM policies, EC2 instances, and network configurations.
"""

import re
import json
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from .base import BaseAuditor
from ..utils.severity import Finding, Severity

# boto3 is optional - only required for AWS audits
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError, BotoCoreError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


class AWSAuditor(BaseAuditor):
    """
    Auditor for AWS cloud security configurations.

    Checks include:
    - S3 bucket security (public access, encryption, versioning)
    - IAM policy analysis (overly permissive policies)
    - Security group rules (open ports, unrestricted access)
    - EC2 instance security
    - Root account security
    """

    # IAM configuration constants
    CREDENTIAL_UNUSED_DAYS_THRESHOLD = 90
    MIN_PASSWORD_LENGTH = 14
    MAX_PASSWORD_AGE_DAYS = 90

    # Common ports
    PORT_SSH = 22
    PORT_RDP = 3389
    PORT_RANGE_ALL = -1
    PORT_MAX = 65535

    # CIDR for "anywhere"
    CIDR_ANYWHERE = "0.0.0.0/0"

    def __init__(
        self,
        verbose: bool = False,
        region: str = "us-east-1",
        profile: Optional[str] = None
    ):
        """
        Initialize the AWS auditor.

        Args:
            verbose: Enable verbose output
            region: AWS region to audit
            profile: AWS credentials profile to use
        """
        super().__init__(verbose)
        self.region = region
        self.profile = profile
        self._session = None
        self._clients: Dict[str, Any] = {}

        if not AWS_AVAILABLE:
            raise ImportError(
                "boto3 is required for AWS audits. "
                "Install with: pip install boto3"
            )

    @property
    def name(self) -> str:
        return "AWS Cloud Auditor"

    @property
    def checks(self) -> List[str]:
        return [
            "S3-001", "S3-002", "S3-003", "S3-004",
            "IAM-001", "IAM-002", "IAM-003", "IAM-004",
            "SG-001", "SG-002", "SG-003",
            "EC2-001", "EC2-002",
            "ROOT-001",
        ]

    def _get_session(self):
        """Get or create boto3 session."""
        if self._session is None:
            if self.profile:
                self._session = boto3.Session(profile_name=self.profile, region_name=self.region)
            else:
                self._session = boto3.Session(region_name=self.region)
        return self._session

    def _get_client(self, service: str):
        """Get or create boto3 client for a service."""
        if service not in self._clients:
            self._clients[service] = self._get_session().client(service)
        return self._clients[service]

    def run_all_checks(self) -> List[Finding]:
        """Run all AWS security checks."""
        findings = []

        # Verify credentials first
        try:
            sts = self._get_client('sts')
            sts.get_caller_identity()
        except (NoCredentialsError, ClientError, BotoCoreError) as e:
            findings.append(Finding(
                check_id="AWS-CREDS",
                title="AWS Credentials Not Available",
                description=f"Unable to authenticate with AWS: {str(e)}",
                severity=Severity.INFO,
                resource="AWS",
                recommendation="Configure AWS credentials via environment variables, ~/.aws/credentials, or IAM role.",
                passed=True,
            ))
            return findings

        # S3 Bucket Checks
        findings.extend(self._check_s3_public_access())
        findings.extend(self._check_s3_encryption())
        findings.extend(self._check_s3_versioning())
        findings.extend(self._check_s3_logging())

        # IAM Checks
        findings.extend(self._check_iam_unused_credentials())
        findings.extend(self._check_iam_mfa())
        findings.extend(self._check_iam_password_policy())
        findings.extend(self._check_iam_overly_permissive_policies())

        # Security Group Checks
        findings.extend(self._check_security_group_ssh())
        findings.extend(self._check_security_group_rdp())
        findings.extend(self._check_security_group_open_ports())

        # EC2 Checks
        findings.extend(self._check_ec2_instance_profiles())
        findings.extend(self._check_ec2_public_ips())

        # Root Account Checks
        findings.extend(self._check_root_mfa())

        return findings

    # ==================== S3 Bucket Helper ====================

    def _list_s3_buckets(self) -> List[str]:
        """List all S3 bucket names in the account.

        Returns:
            List of bucket names, or empty list on error.
        """
        try:
            s3 = self._get_client('s3')
            return [b['Name'] for b in s3.list_buckets().get('Buckets', [])]
        except ClientError:
            return []

    # ==================== S3 Bucket Checks ====================

    def _check_s3_public_access(self) -> List[Finding]:
        """Check for public S3 buckets."""
        check_id = "S3-001"
        findings = []

        bucket_names = self._list_s3_buckets()
        if not bucket_names:
            return findings

        s3 = self._get_client('s3')

        for bucket_name in bucket_names:
            try:
                # Check bucket ACL
                acl = s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        findings.append(Finding(
                            check_id=check_id,
                            title="S3 Bucket Public via ACL",
                            description=f"Bucket '{bucket_name}' has public read access via ACL.",
                            severity=Severity.CRITICAL,
                            resource=f"s3://{bucket_name}",
                            recommendation="Remove public access from bucket ACL or enable S3 Block Public Access.",
                            references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/configuring-block-public-access-bucket.html"],
                            passed=False,
                        ))
                        break

                # Check bucket policy for public access
                try:
                    policy = s3.get_bucket_policy(Bucket=bucket_name)
                    policy_doc = json.loads(policy['Policy'])

                    for statement in policy_doc.get('Statement', []):
                        principal = statement.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            if statement.get('Effect') == 'Allow':
                                findings.append(Finding(
                                    check_id=check_id,
                                    title="S3 Bucket Public via Policy",
                                    description=f"Bucket '{bucket_name}' allows public access via bucket policy.",
                                    severity=Severity.CRITICAL,
                                    resource=f"s3://{bucket_name}",
                                    recommendation="Review and restrict bucket policy principals.",
                                    passed=False,
                                ))
                                break
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        pass  # No policy is fine

            except ClientError as e:
                findings.append(Finding(
                    check_id=check_id,
                    title="S3 Bucket Check Failed",
                    description=f"Could not check bucket '{bucket_name}': {e.response['Error']['Code']}",
                    severity=Severity.INFO,
                    resource=f"s3://{bucket_name}",
                    recommendation="Verify bucket exists and you have permissions.",
                    passed=True,
                ))

        if not any(not f.passed for f in findings):
            findings.append(Finding(
                check_id=check_id,
                title="No Public S3 Buckets",
                description="All S3 buckets are private.",
                severity=Severity.INFO,
                resource="S3",
                recommendation="Continue monitoring bucket access.",
                passed=True,
            ))

        return findings

    def _check_s3_encryption(self) -> List[Finding]:
        """Check for S3 bucket default encryption."""
        check_id = "S3-002"
        findings = []
        unencrypted_buckets = []

        bucket_names = self._list_s3_buckets()
        if not bucket_names:
            return findings

        s3 = self._get_client('s3')

        for bucket_name in bucket_names:
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
            except ClientError as e:
                if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                    unencrypted_buckets.append(bucket_name)

        if unencrypted_buckets:
            findings.append(Finding(
                check_id=check_id,
                title="S3 Buckets Without Default Encryption",
                description=f"{len(unencrypted_buckets)} buckets do not have default encryption enabled.",
                severity=Severity.HIGH,
                resource=f"S3 buckets: {', '.join(unencrypted_buckets[:5])}",
                recommendation="Enable default encryption (SSE-S3 or SSE-KMS) for all buckets.",
                metadata={"buckets": unencrypted_buckets},
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=check_id,
                title="All S3 Buckets Encrypted",
                description="All S3 buckets have default encryption enabled.",
                severity=Severity.INFO,
                resource="S3",
                recommendation="Continue enforcing encryption.",
                passed=True,
            ))

        return findings

    def _check_s3_versioning(self) -> List[Finding]:
        """Check for S3 bucket versioning."""
        check_id = "S3-003"
        findings = []
        non_versioned_buckets = []

        bucket_names = self._list_s3_buckets()
        if not bucket_names:
            return findings

        s3 = self._get_client('s3')

        for bucket_name in bucket_names:
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get('Status') != 'Enabled':
                    non_versioned_buckets.append(bucket_name)
            except ClientError:
                non_versioned_buckets.append(bucket_name)

        if non_versioned_buckets:
            findings.append(Finding(
                check_id=check_id,
                title="S3 Buckets Without Versioning",
                description=f"{len(non_versioned_buckets)} buckets do not have versioning enabled.",
                severity=Severity.MEDIUM,
                resource=f"S3 buckets: {', '.join(non_versioned_buckets[:5])}",
                recommendation="Enable versioning for data protection and recovery.",
                metadata={"buckets": non_versioned_buckets},
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=check_id,
                title="All S3 Buckets Have Versioning",
                description="All S3 buckets have versioning enabled.",
                severity=Severity.INFO,
                resource="S3",
                recommendation="Continue maintaining versioning.",
                passed=True,
            ))

        return findings

    def _check_s3_logging(self) -> List[Finding]:
        """Check for S3 bucket logging."""
        check_id = "S3-004"
        findings = []
        non_logging_buckets = []

        bucket_names = self._list_s3_buckets()
        if not bucket_names:
            return findings

        s3 = self._get_client('s3')

        for bucket_name in bucket_names:
            try:
                logging = s3.get_bucket_logging(Bucket=bucket_name)
                if not logging.get('LoggingEnabled'):
                    non_logging_buckets.append(bucket_name)
            except ClientError:
                non_logging_buckets.append(bucket_name)

        if non_logging_buckets:
            findings.append(Finding(
                check_id=check_id,
                title="S3 Buckets Without Access Logging",
                description=f"{len(non_logging_buckets)} buckets do not have access logging enabled.",
                severity=Severity.MEDIUM,
                resource=f"S3 buckets: {', '.join(non_logging_buckets[:5])}",
                recommendation="Enable server access logging for audit trails.",
                metadata={"buckets": non_logging_buckets},
                passed=False,
            ))
        else:
            findings.append(Finding(
                check_id=check_id,
                title="All S3 Buckets Have Logging",
                description="All S3 buckets have access logging enabled.",
                severity=Severity.INFO,
                resource="S3",
                recommendation="Continue maintaining logging.",
                passed=True,
            ))

        return findings

    # ==================== IAM Checks ====================

    def _check_iam_unused_credentials(self) -> List[Finding]:
        """Check for unused IAM credentials."""
        check_id = "IAM-001"
        findings = []
        unused_users = []

        try:
            iam = self._get_client('iam')
            users = iam.list_users()['Users']

            for user in users:
                username = user['UserName']

                # Check access keys
                try:
                    keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    for key in keys:
                        last_used = key.get('LastUsedDate') or key.get('CreateDate')
                        if last_used:
                            days_unused = (datetime.now(timezone.utc) - last_used).days
                            if days_unused > self.CREDENTIAL_UNUSED_DAYS_THRESHOLD:
                                unused_users.append({
                                    "username": username,
                                    "key_id": key['AccessKeyId'][-4:].rjust(20, '*'),
                                    "days_unused": days_unused
                                })
                except ClientError:
                    pass

            if unused_users:
                findings.append(Finding(
                    check_id=check_id,
                    title="Unused IAM Credentials Found",
                    description=f"Found {len(unused_users)} access keys unused for more than 90 days.",
                    severity=Severity.MEDIUM,
                    resource="IAM",
                    recommendation="Rotate or remove unused credentials.",
                    metadata={"unused_credentials": unused_users},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="No Unused IAM Credentials",
                    description="All IAM credentials have been used recently.",
                    severity=Severity.INFO,
                    resource="IAM",
                    recommendation="Continue monitoring credential usage.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    def _check_iam_mfa(self) -> List[Finding]:
        """Check for IAM users without MFA."""
        check_id = "IAM-002"
        findings = []
        users_without_mfa = []

        try:
            iam = self._get_client('iam')
            users = iam.list_users()['Users']

            for user in users:
                username = user['UserName']

                # Check if user has password (console access)
                try:
                    login_profile = iam.get_login_profile(UserName=username)
                    has_console_access = True
                except ClientError:
                    has_console_access = False

                if has_console_access:
                    # Check MFA devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        users_without_mfa.append(username)

            if users_without_mfa:
                findings.append(Finding(
                    check_id=check_id,
                    title="IAM Users Without MFA",
                    description=f"{len(users_without_mfa)} console users do not have MFA enabled.",
                    severity=Severity.HIGH,
                    resource="IAM",
                    recommendation="Enable MFA for all users with console access.",
                    metadata={"users": users_without_mfa},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="All IAM Users Have MFA",
                    description="All users with console access have MFA enabled.",
                    severity=Severity.INFO,
                    resource="IAM",
                    recommendation="Continue enforcing MFA.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    def _check_iam_password_policy(self) -> List[Finding]:
        """Check IAM password policy strength."""
        check_id = "IAM-003"
        findings = []

        try:
            iam = self._get_client('iam')
            policy = iam.get_account_password_policy()['PasswordPolicy']

            issues = []

            if not policy.get('RequireUppercaseCharacters', False):
                issues.append("Missing uppercase character requirement")
            if not policy.get('RequireLowercaseCharacters', False):
                issues.append("Missing lowercase character requirement")
            if not policy.get('RequireSymbols', False):
                issues.append("Missing symbol requirement")
            if not policy.get('RequireNumbers', False):
                issues.append("Missing number requirement")
            if policy.get('MinimumPasswordLength', 0) < self.MIN_PASSWORD_LENGTH:
                issues.append(f"Minimum password length is {policy.get('MinimumPasswordLength', 6)}, should be {self.MIN_PASSWORD_LENGTH}+")
            if policy.get('MaxPasswordAge', 0) > self.MAX_PASSWORD_AGE_DAYS or policy.get('MaxPasswordAge', 0) == 0:
                issues.append(f"Password expiry not set or too long (should be {self.MAX_PASSWORD_AGE_DAYS} days or less)")

            if issues:
                findings.append(Finding(
                    check_id=check_id,
                    title="Weak IAM Password Policy",
                    description=f"Password policy has issues: {'; '.join(issues)}",
                    severity=Severity.MEDIUM,
                    resource="IAM Password Policy",
                    recommendation="Strengthen password policy with complexity and expiry requirements.",
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="Strong IAM Password Policy",
                    description="Password policy meets security requirements.",
                    severity=Severity.INFO,
                    resource="IAM Password Policy",
                    recommendation="Continue enforcing strong passwords.",
                    passed=True,
                ))

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchEntity':
                findings.append(Finding(
                    check_id=check_id,
                    title="No IAM Password Policy",
                    description="No custom password policy is configured.",
                    severity=Severity.MEDIUM,
                    resource="IAM Password Policy",
                    recommendation="Configure a strong password policy.",
                    passed=False,
                ))

        return findings

    def _check_iam_overly_permissive_policies(self) -> List[Finding]:
        """Check for overly permissive IAM policies."""
        check_id = "IAM-004"
        findings = []

        try:
            iam = self._get_client('iam')

            # Check for policies with Action: * and Resource: *
            policies = iam.list_policies(Scope='Local')['Policies']

            for policy in policies:
                policy_arn = policy['Arn']

                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy_arn,
                        VersionId=policy['DefaultVersionId']
                    )

                    doc = version['PolicyVersion']['Document']

                    statements = doc.get('Statement', [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for statement in statements:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])

                            if not isinstance(actions, list):
                                actions = [actions]
                            if not isinstance(resources, list):
                                resources = [resources]

                            if '*' in actions and '*' in resources:
                                findings.append(Finding(
                                    check_id=check_id,
                                    title="Overly Permissive IAM Policy",
                                    description=f"Policy '{policy['PolicyName']}' allows all actions on all resources.",
                                    severity=Severity.HIGH,
                                    resource=policy_arn,
                                    recommendation="Apply principle of least privilege to this policy.",
                                    passed=False,
                                ))
                                break

                except ClientError:
                    continue

            if not any(not f.passed for f in findings):
                findings.append(Finding(
                    check_id=check_id,
                    title="No Overly Permissive Policies",
                    description="All IAM policies follow least privilege principles.",
                    severity=Severity.INFO,
                    resource="IAM",
                    recommendation="Continue reviewing policies regularly.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    # ==================== Security Group Checks ====================

    def _check_security_group_ssh(self) -> List[Finding]:
        """Check for SSH open to the world."""
        check_id = "SG-001"
        findings = []
        open_ssh_groups = []

        try:
            ec2 = self._get_client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    if rule.get('FromPort') == self.PORT_SSH and rule.get('ToPort') == self.PORT_SSH:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == self.CIDR_ANYWHERE:
                                open_ssh_groups.append({
                                    "group_id": sg['GroupId'],
                                    "group_name": sg['GroupName']
                                })

            if open_ssh_groups:
                findings.append(Finding(
                    check_id=check_id,
                    title="SSH Open to the World",
                    description=f"{len(open_ssh_groups)} security groups allow SSH (22) from anywhere.",
                    severity=Severity.HIGH,
                    resource="EC2 Security Groups",
                    recommendation="Restrict SSH access to known IP ranges or use AWS Systems Manager.",
                    metadata={"security_groups": open_ssh_groups},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="SSH Properly Restricted",
                    description="No security groups allow unrestricted SSH access.",
                    severity=Severity.INFO,
                    resource="EC2 Security Groups",
                    recommendation="Continue restricting SSH access.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    def _check_security_group_rdp(self) -> List[Finding]:
        """Check for RDP open to the world."""
        check_id = "SG-002"
        findings = []
        open_rdp_groups = []

        try:
            ec2 = self._get_client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    if rule.get('FromPort') == self.PORT_RDP and rule.get('ToPort') == self.PORT_RDP:
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == self.CIDR_ANYWHERE:
                                open_rdp_groups.append({
                                    "group_id": sg['GroupId'],
                                    "group_name": sg['GroupName']
                                })

            if open_rdp_groups:
                findings.append(Finding(
                    check_id=check_id,
                    title="RDP Open to the World",
                    description=f"{len(open_rdp_groups)} security groups allow RDP (3389) from anywhere.",
                    severity=Severity.CRITICAL,
                    resource="EC2 Security Groups",
                    recommendation="Restrict RDP access to known IP ranges immediately.",
                    metadata={"security_groups": open_rdp_groups},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="RDP Properly Restricted",
                    description="No security groups allow unrestricted RDP access.",
                    severity=Severity.INFO,
                    resource="EC2 Security Groups",
                    recommendation="Continue restricting RDP access.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    def _check_security_group_open_ports(self) -> List[Finding]:
        """Check for security groups with all ports open."""
        check_id = "SG-003"
        findings = []
        open_all_groups = []

        try:
            ec2 = self._get_client('ec2')
            security_groups = ec2.describe_security_groups()['SecurityGroups']

            for sg in security_groups:
                for rule in sg.get('IpPermissions', []):
                    from_port = rule.get('FromPort', 0)
                    to_port = rule.get('ToPort', self.PORT_MAX)

                    if from_port == self.PORT_RANGE_ALL or (from_port == 0 and to_port == self.PORT_MAX):
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == self.CIDR_ANYWHERE:
                                open_all_groups.append({
                                    "group_id": sg['GroupId'],
                                    "group_name": sg['GroupName']
                                })

            if open_all_groups:
                findings.append(Finding(
                    check_id=check_id,
                    title="All Ports Open to the World",
                    description=f"{len(open_all_groups)} security groups allow all ports from anywhere.",
                    severity=Severity.CRITICAL,
                    resource="EC2 Security Groups",
                    recommendation="Restrict to specific ports required by your application.",
                    metadata={"security_groups": open_all_groups},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="Port Ranges Properly Restricted",
                    description="No security groups have all ports open to the world.",
                    severity=Severity.INFO,
                    resource="EC2 Security Groups",
                    recommendation="Continue following least privilege for network access.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    # ==================== EC2 Checks ====================

    def _check_ec2_instance_profiles(self) -> List[Finding]:
        """Check for EC2 instances without IAM profiles."""
        check_id = "EC2-001"
        findings = []

        try:
            ec2 = self._get_client('ec2')
            instances = ec2.describe_instances()['Reservations']

            instances_without_profile = []

            for reservation in instances:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        if 'IamInstanceProfile' not in instance:
                            instances_without_profile.append(instance['InstanceId'])

            if instances_without_profile:
                findings.append(Finding(
                    check_id=check_id,
                    title="EC2 Instances Without IAM Profiles",
                    description=f"{len(instances_without_profile)} running instances have no IAM instance profile.",
                    severity=Severity.LOW,
                    resource="EC2",
                    recommendation="Attach IAM instance profiles for proper credential management.",
                    metadata={"instances": instances_without_profile},
                    passed=False,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="All EC2 Instances Have IAM Profiles",
                    description="All running EC2 instances have IAM instance profiles.",
                    severity=Severity.INFO,
                    resource="EC2",
                    recommendation="Continue using IAM profiles for credential management.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    def _check_ec2_public_ips(self) -> List[Finding]:
        """Check for EC2 instances with public IPs."""
        check_id = "EC2-002"
        findings = []

        try:
            ec2 = self._get_client('ec2')
            instances = ec2.describe_instances()['Reservations']

            public_instances = []

            for reservation in instances:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        public_ip = instance.get('PublicIpAddress')
                        if public_ip:
                            public_instances.append({
                                "instance_id": instance['InstanceId'],
                                "public_ip": public_ip
                            })

            if public_instances:
                findings.append(Finding(
                    check_id=check_id,
                    title="EC2 Instances With Public IPs",
                    description=f"{len(public_instances)} running instances have public IP addresses.",
                    severity=Severity.INFO,
                    resource="EC2",
                    recommendation="Review if public IPs are necessary for each instance.",
                    metadata={"instances": public_instances},
                    passed=True,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="No EC2 Instances With Public IPs",
                    description="No running EC2 instances have public IP addresses.",
                    severity=Severity.INFO,
                    resource="EC2",
                    recommendation="Continue using private networking where possible.",
                    passed=True,
                ))

        except ClientError:
            pass

        return findings

    # ==================== Root Account Checks ====================

    def _check_root_mfa(self) -> List[Finding]:
        """Check if root account has MFA enabled."""
        check_id = "ROOT-001"
        findings = []

        try:
            iam = self._get_client('iam')
            summary = iam.get_account_summary()['SummaryMap']

            if summary.get('AccountMFAEnabled', 0) == 1:
                findings.append(Finding(
                    check_id=check_id,
                    title="Root Account MFA Enabled",
                    description="The AWS root account has MFA enabled.",
                    severity=Severity.INFO,
                    resource="AWS Root Account",
                    recommendation="Continue protecting root account with MFA.",
                    passed=True,
                ))
            else:
                findings.append(Finding(
                    check_id=check_id,
                    title="Root Account MFA Not Enabled",
                    description="The AWS root account does not have MFA enabled.",
                    severity=Severity.CRITICAL,
                    resource="AWS Root Account",
                    recommendation="Enable MFA on the root account immediately.",
                    references=["https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html#id_root-user_manage_mfa"],
                    passed=False,
                ))

        except ClientError:
            pass

        return findings
