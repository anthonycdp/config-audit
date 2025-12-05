# Configuration Audit Tool

A comprehensive security configuration auditor for Linux systems and AWS cloud environments. This tool identifies insecure configurations and generates prioritized remediation reports to help secure your infrastructure.

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-active-brightgreen)

## Features

- **Linux System Auditing**
  - SSH configuration hardening checks
  - File and directory permission validation
  - User account security verification
  - System service configuration review
  - Kernel parameter security checks

- **AWS Cloud Auditing**
  - S3 bucket security (public access, encryption, versioning)
  - IAM policy analysis (overly permissive policies)
  - Security group validation (open ports, unrestricted access)
  - EC2 instance security review
  - Root account security checks

- **Flexible Reporting**
  - Multiple output formats: JSON, Markdown, HTML, Terminal
  - Prioritized findings by severity
  - Risk scoring and executive summaries
  - Actionable remediation recommendations

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/example/config-audit.git
cd config-audit

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install the package
pip install -e .

# For AWS auditing support
pip install -e ".[aws]"

# For development
pip install -e ".[dev]"
```

### Using pip

```bash
pip install config-audit
pip install "config-audit[aws]"  # With AWS support
```

## Quick Start

### Linux System Audit

```bash
# Run all Linux checks
config-audit linux

# Run specific checks
config-audit linux --checks SSH-001,SSH-002,FILE-001

# Generate HTML report
config-audit linux --output report.html --format html
```

### AWS Cloud Audit

```bash
# Run AWS audit (requires AWS credentials)
config-audit aws --region us-east-1

# Use specific AWS profile
config-audit aws --profile production --region us-west-2

# Generate JSON report
config-audit aws --output audit-report.json --format json
```

### Complete Audit

```bash
# Run all audits (Linux + AWS)
config-audit all --output full-report.html --format html
```

## Security Checks Reference

### Linux Checks

| Check ID | Title | Description | Severity |
|----------|-------|-------------|----------|
| SSH-001 | SSH Root Login | Checks if root login via SSH is disabled | HIGH |
| SSH-002 | SSH Password Auth | Checks if password authentication is disabled | HIGH |
| SSH-003 | SSH Empty Passwords | Checks if empty passwords are disabled | CRITICAL |
| SSH-004 | SSH Protocol | Checks SSH protocol version | HIGH |
| SSH-005 | SSH X11 Forwarding | Checks if X11 forwarding is disabled | LOW |
| FILE-001 | Shadow File Permissions | Checks /etc/shadow permissions (should be 600) | CRITICAL |
| FILE-002 | Passwd File Permissions | Checks /etc/passwd permissions (should be 644) | MEDIUM |
| FILE-003 | SSH Host Keys | Checks SSH host key file permissions | HIGH |
| FILE-004 | World-Writable Files | Checks for world-writable files in system directories | HIGH |
| FILE-005 | SUID/SGID Files | Checks for suspicious SUID/SGID binaries | MEDIUM |
| USER-001 | Default Accounts | Checks for unauthorized root accounts | CRITICAL |
| USER-002 | Password Expiry | Checks password expiry configuration | MEDIUM |
| USER-003 | Sudo Configuration | Checks sudo configuration | MEDIUM |
| SYSTEM-001 | Firewall Status | Checks if a firewall is active | HIGH |
| SYSTEM-002 | Unnecessary Services | Checks for insecure services running | HIGH |
| SYSTEM-003 | Kernel Parameters | Checks kernel security parameters | MEDIUM |

### AWS Checks

| Check ID | Title | Description | Severity |
|----------|-------|-------------|----------|
| S3-001 | S3 Public Access | Checks for public S3 buckets via ACL or policy | CRITICAL |
| S3-002 | S3 Encryption | Checks for default bucket encryption | HIGH |
| S3-003 | S3 Versioning | Checks if bucket versioning is enabled | MEDIUM |
| S3-004 | S3 Logging | Checks if server access logging is enabled | MEDIUM |
| IAM-001 | Unused Credentials | Checks for unused IAM credentials (>90 days) | MEDIUM |
| IAM-002 | IAM MFA | Checks if console users have MFA enabled | HIGH |
| IAM-003 | Password Policy | Checks IAM password policy strength | MEDIUM |
| IAM-004 | Permissive Policies | Checks for overly permissive IAM policies | HIGH |
| SG-001 | SSH Open | Checks if SSH (22) is open to the world | HIGH |
| SG-002 | RDP Open | Checks if RDP (3389) is open to the world | CRITICAL |
| SG-003 | All Ports Open | Checks if all ports are open to the world | CRITICAL |
| EC2-001 | Instance Profiles | Checks for EC2 instances without IAM profiles | LOW |
| EC2-002 | Public IPs | Checks for EC2 instances with public IPs | INFO |
| ROOT-001 | Root MFA | Checks if root account has MFA enabled | CRITICAL |

## Usage Examples

### Programmatic Usage

```python
from config_auditor import LinuxAuditor, AWSAuditor, ReportGenerator

# Run Linux audit
linux_auditor = LinuxAuditor()
linux_findings = linux_auditor.run_audit()

# Run AWS audit
aws_auditor = AWSAuditor(region="us-east-1", profile="production")
aws_findings = aws_auditor.run_audit()

# Combine findings
all_findings = linux_findings + aws_findings

# Generate report
generator = ReportGenerator(title="Security Audit Report")
print(generator.generate_terminal_report(all_findings))

# Save HTML report
generator.save_report(all_findings, "report.html", format="html")
```

### Custom Check Selection

```python
from config_auditor import LinuxAuditor

# Run only SSH checks
auditor = LinuxAuditor()
ssh_checks = ["SSH-001", "SSH-002", "SSH-003", "SSH-004", "SSH-005"]
findings = auditor.run_audit(checks=ssh_checks)

for finding in findings:
    print(f"[{finding.severity.name}] {finding.title}: {finding.description}")
```

### Using Individual Check Modules

```python
from config_auditor.checks import SSHChecks, FilePermissionChecks

# Check SSH configuration
ssh_checker = SSHChecks("/etc/ssh/sshd_config")
ssh_findings = ssh_checker.check_all()

# Check file permissions
file_checker = FilePermissionChecks()
critical_file_findings = file_checker.check_critical_files()
```

## Output Formats

### Terminal Output

```
============================================================
           Configuration Security Audit Report
============================================================

Generated: 2024-01-15 10:30:00 UTC

Executive Summary
----------------------------------------
  Total Checks:  25
  Passed:        18
  Failed:        7
  Pass Rate:     72.0%
  Risk Score:    28
  Risk Level:    HIGH

By Severity:
  ● CRITICAL: 2
  ● HIGH: 3
  ● MEDIUM: 2

Detailed Findings
----------------------------------------

[CRITICAL]
  ✗ FAIL S3-001: S3 Bucket Public via ACL
         Resource: s3://my-public-bucket
         Bucket has public read access via ACL.
```

### JSON Output

```json
{
  "title": "Configuration Security Audit Report",
  "generated_at": "2024-01-15T10:30:00",
  "summary": {
    "total_checks": 25,
    "passed": 18,
    "failed": 7,
    "risk_score": 28,
    "risk_level": "HIGH"
  },
  "findings": {
    "CRITICAL": [...],
    "HIGH": [...],
    "MEDIUM": [...]
  }
}
```

## Configuration

### AWS Credentials

The AWS auditor requires valid AWS credentials. Configure them using one of these methods:

1. **Environment Variables**
   ```bash
   export AWS_ACCESS_KEY_ID=your-access-key
   export AWS_SECRET_ACCESS_KEY=your-secret-key
   export AWS_DEFAULT_REGION=us-east-1
   ```

2. **AWS Credentials File** (`~/.aws/credentials`)
   ```ini
   [default]
   aws_access_key_id = your-access-key
   aws_secret_access_key = your-secret-key

   [production]
   aws_access_key_id = prod-access-key
   aws_secret_access_key = prod-secret-key
   ```

3. **IAM Role** (for EC2 instances)
   - Attach an IAM role with appropriate permissions to your EC2 instance

### Required AWS Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketLogging",
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Project Structure

```
config-audit/
├── README.md                   # This file
├── setup.py                    # Package setup
├── pyproject.toml              # Modern Python packaging config
├── requirements.txt            # Dependencies
├── requirements-dev.txt        # Development dependencies
├── config_auditor/             # Main package
│   ├── __init__.py
│   ├── main.py                 # CLI entry point
│   ├── auditors/               # Auditor implementations
│   │   ├── __init__.py
│   │   ├── base.py             # Base auditor class
│   │   ├── linux.py            # Linux system auditor
│   │   └── aws.py              # AWS cloud auditor
│   ├── checks/                 # Individual check modules
│   │   ├── __init__.py
│   │   ├── ssh.py              # SSH configuration checks
│   │   ├── file_permissions.py # File permission checks
│   │   ├── s3.py               # S3 bucket checks
│   │   ├── iam.py              # IAM policy checks
│   │   └── network.py          # Network security checks
│   ├── reporters/              # Report generation
│   │   ├── __init__.py
│   │   └── report_generator.py
│   └── utils/                  # Utility classes
│       ├── __init__.py
│       └── severity.py         # Severity levels and Finding class
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── test_linux_auditor.py
│   ├── test_aws_auditor.py
│   └── test_reporters.py
└── examples/                   # Example files
    ├── sample_report.json
    └── sample_report.md
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=config_auditor --cov-report=html

# Run specific test file
pytest tests/test_linux_auditor.py -v
```

### Code Quality

```bash
# Format code
black config_auditor tests

# Lint code
flake8 config_auditor tests

# Type checking
mypy config_auditor
```

## Security Considerations

- **Least Privilege**: Always use the minimum required permissions for AWS audits
- **Sensitive Data**: Reports may contain resource identifiers; handle them appropriately
- **Root Access**: Some Linux checks require root/sudo access
- **Network Access**: AWS audits require internet connectivity to AWS APIs

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Make your changes
4. Run tests (`pytest`)
5. Commit your changes (`git commit -am 'Add new security check'`)
6. Push to the branch (`git push origin feature/new-check`)
7. Create a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Security best practices from CIS Benchmarks
- AWS Well-Architected Framework Security Pillar
- NIST Cybersecurity Framework

## Changelog

### v1.0.0 (2024-01-15)
- Initial release
- Linux system auditing (16 checks)
- AWS cloud auditing (14 checks)
- Multiple report formats (JSON, Markdown, HTML, Terminal)
- Risk scoring and prioritization
