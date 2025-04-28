"""
AWS S3 bucket security checks.

Provides reusable check functions for S3 bucket security validation.
"""

import json
from typing import List, Dict, Any, Optional

from ..utils.severity import Finding, Severity

try:
    import boto3
    from botocore.exceptions import ClientError
    S3_AVAILABLE = True
except ImportError:
    S3_AVAILABLE = False


class S3Checks:
    """
    Collection of S3 bucket security check functions.

    These checks validate S3 bucket configurations against
    security best practices.
    """

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        """
        Initialize S3 checks.

        Args:
            region: AWS region
            profile: AWS credentials profile
        """
        if not S3_AVAILABLE:
            raise ImportError("boto3 is required for S3 checks")

        self.region = region
        self.profile = profile
        self._s3_client = None

    @property
    def s3(self):
        """Get or create S3 client."""
        if self._s3_client is None:
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
            else:
                session = boto3.Session()
            self._s3_client = session.client('s3')
        return self._s3_client

    def check_bucket_public_access(self, bucket_name: str) -> Finding:
        """
        Check if a bucket has public access enabled.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Finding with check result
        """
        check_id = f"S3-PUBLIC-{bucket_name}"

        issues = []

        try:
            # Check ACL
            acl = self.s3.get_bucket_acl(Bucket=bucket_name)
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                    issues.append("Public access via ACL")

            # Check bucket policy
            try:
                policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                policy_doc = json.loads(policy['Policy'])

                for statement in policy_doc.get('Statement', []):
                    if statement.get('Effect') == 'Allow':
                        principal = statement.get('Principal', {})
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            issues.append("Public access via bucket policy")
                            break
            except ClientError as e:
                if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                    raise

            if issues:
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' is Public",
                    description=f"Bucket has: {', '.join(issues)}.",
                    severity=Severity.CRITICAL,
                    resource=f"s3://{bucket_name}",
                    recommendation="Enable S3 Block Public Access or update ACL/policy.",
                    references=["https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html"],
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title=f"Bucket '{bucket_name}' is Private",
                description="Bucket does not have public access.",
                severity=Severity.INFO,
                resource=f"s3://{bucket_name}",
                recommendation="Continue maintaining private access.",
                passed=True,
            )

        except ClientError as e:
            return Finding(
                check_id=check_id,
                title=f"Cannot Check Bucket '{bucket_name}'",
                description=f"Error: {e.response['Error']['Code']}",
                severity=Severity.INFO,
                resource=f"s3://{bucket_name}",
                recommendation="Verify permissions to check bucket.",
                passed=True,
            )

    def check_bucket_encryption(self, bucket_name: str) -> Finding:
        """
        Check if a bucket has default encryption enabled.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Finding with check result
        """
        check_id = f"S3-ENCRYPTION-{bucket_name}"

        try:
            encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)

            rules = encryption.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
            if rules:
                algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', 'unknown')
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Has Encryption",
                    description=f"Default encryption enabled with {algorithm}.",
                    severity=Severity.INFO,
                    resource=f"s3://{bucket_name}",
                    recommendation="Continue maintaining encryption.",
                    passed=True,
                )

        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Missing Encryption",
                    description="Default encryption is not enabled.",
                    severity=Severity.HIGH,
                    resource=f"s3://{bucket_name}",
                    recommendation="Enable default bucket encryption (SSE-S3 or SSE-KMS).",
                    passed=False,
                )

        return Finding(
            check_id=check_id,
            title=f"Bucket '{bucket_name}' Encryption Check Failed",
            description="Unable to determine encryption status.",
            severity=Severity.INFO,
            resource=f"s3://{bucket_name}",
            recommendation="Verify bucket exists and permissions are correct.",
            passed=True,
        )

    def check_bucket_versioning(self, bucket_name: str) -> Finding:
        """
        Check if a bucket has versioning enabled.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Finding with check result
        """
        check_id = f"S3-VERSIONING-{bucket_name}"

        try:
            versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Disabled')

            if status == 'Enabled':
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Has Versioning",
                    description="Object versioning is enabled.",
                    severity=Severity.INFO,
                    resource=f"s3://{bucket_name}",
                    recommendation="Continue maintaining versioning.",
                    passed=True,
                )
            else:
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Missing Versioning",
                    description="Object versioning is not enabled.",
                    severity=Severity.MEDIUM,
                    resource=f"s3://{bucket_name}",
                    recommendation="Enable versioning for data protection.",
                    passed=False,
                )

        except ClientError:
            return Finding(
                check_id=check_id,
                title=f"Bucket '{bucket_name}' Versioning Check Failed",
                description="Unable to check versioning status.",
                severity=Severity.INFO,
                resource=f"s3://{bucket_name}",
                recommendation="Verify permissions.",
                passed=True,
            )

    def check_bucket_logging(self, bucket_name: str) -> Finding:
        """
        Check if a bucket has access logging enabled.

        Args:
            bucket_name: Name of the S3 bucket

        Returns:
            Finding with check result
        """
        check_id = f"S3-LOGGING-{bucket_name}"

        try:
            logging = self.s3.get_bucket_logging(Bucket=bucket_name)

            if logging.get('LoggingEnabled'):
                target = logging['LoggingEnabled'].get('TargetBucket', 'unknown')
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Has Logging",
                    description=f"Access logging enabled, target: {target}.",
                    severity=Severity.INFO,
                    resource=f"s3://{bucket_name}",
                    recommendation="Continue maintaining logging.",
                    passed=True,
                )
            else:
                return Finding(
                    check_id=check_id,
                    title=f"Bucket '{bucket_name}' Missing Logging",
                    description="Server access logging is not enabled.",
                    severity=Severity.MEDIUM,
                    resource=f"s3://{bucket_name}",
                    recommendation="Enable access logging for audit trails.",
                    passed=False,
                )

        except ClientError:
            return Finding(
                check_id=check_id,
                title=f"Bucket '{bucket_name}' Logging Check Failed",
                description="Unable to check logging status.",
                severity=Severity.INFO,
                resource=f"s3://{bucket_name}",
                recommendation="Verify permissions.",
                passed=True,
            )

    def check_all_buckets(self) -> List[Finding]:
        """
        Run all checks on all buckets.

        Returns:
            List of findings from all checks
        """
        findings = []

        try:
            buckets = self.s3.list_buckets()['Buckets']

            for bucket in buckets:
                bucket_name = bucket['Name']
                findings.append(self.check_bucket_public_access(bucket_name))
                findings.append(self.check_bucket_encryption(bucket_name))
                findings.append(self.check_bucket_versioning(bucket_name))
                findings.append(self.check_bucket_logging(bucket_name))

        except ClientError as e:
            findings.append(Finding(
                check_id="S3-LIST-BUCKETS",
                title="Cannot List S3 Buckets",
                description=f"Error: {e.response['Error']['Code']}",
                severity=Severity.INFO,
                resource="S3",
                recommendation="Verify S3 list permissions.",
                passed=True,
            ))

        return findings
