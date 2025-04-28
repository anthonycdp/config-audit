"""
Network security checks.

Provides reusable check functions for network configuration validation.
"""

from typing import List, Dict, Any, Optional

from ..utils.severity import Finding, Severity

try:
    import boto3
    from botocore.exceptions import ClientError
    NETWORK_AVAILABLE = True
except ImportError:
    NETWORK_AVAILABLE = False


class NetworkChecks:
    """
    Collection of network security check functions.

    These checks validate network configurations against
    security best practices.
    """

    # Sensitive ports that should not be open to the world
    SENSITIVE_PORTS = {
        22: {'name': 'SSH', 'severity': Severity.HIGH},
        23: {'name': 'Telnet', 'severity': Severity.CRITICAL},
        25: {'name': 'SMTP', 'severity': Severity.MEDIUM},
        53: {'name': 'DNS', 'severity': Severity.MEDIUM},
        110: {'name': 'POP3', 'severity': Severity.MEDIUM},
        135: {'name': 'RPC', 'severity': Severity.HIGH},
        139: {'name': 'NetBIOS', 'severity': Severity.HIGH},
        143: {'name': 'IMAP', 'severity': Severity.MEDIUM},
        161: {'name': 'SNMP', 'severity': Severity.HIGH},
        389: {'name': 'LDAP', 'severity': Severity.HIGH},
        445: {'name': 'SMB', 'severity': Severity.CRITICAL},
        1433: {'name': 'MSSQL', 'severity': Severity.HIGH},
        1521: {'name': 'Oracle', 'severity': Severity.HIGH},
        3306: {'name': 'MySQL', 'severity': Severity.HIGH},
        3389: {'name': 'RDP', 'severity': Severity.CRITICAL},
        5432: {'name': 'PostgreSQL', 'severity': Severity.HIGH},
        5900: {'name': 'VNC', 'severity': Severity.CRITICAL},
        6379: {'name': 'Redis', 'severity': Severity.HIGH},
        8080: {'name': 'HTTP-Alt', 'severity': Severity.LOW},
        27017: {'name': 'MongoDB', 'severity': Severity.HIGH},
    }

    def __init__(self, region: str = "us-east-1", profile: Optional[str] = None):
        """
        Initialize network checks.

        Args:
            region: AWS region
            profile: AWS credentials profile
        """
        if not NETWORK_AVAILABLE:
            raise ImportError("boto3 is required for AWS network checks")

        self.region = region
        self.profile = profile
        self._ec2_client = None

    @property
    def ec2(self):
        """Get or create EC2 client."""
        if self._ec2_client is None:
            if self.profile:
                session = boto3.Session(profile_name=self.profile)
            else:
                session = boto3.Session(region_name=self.region)
            self._ec2_client = session.client('ec2', region_name=self.region)
        return self._ec2_client

    def check_security_group_port(
        self,
        port: int,
        protocol: str = 'tcp'
    ) -> Finding:
        """
        Check if a specific port is open to the world.

        Args:
            port: Port number to check
            protocol: Protocol (tcp/udp)

        Returns:
            Finding with check result
        """
        check_id = f"SG-PORT-{port}"

        try:
            sgs = self.ec2.describe_security_groups()['SecurityGroups']

            open_groups = []

            for sg in sgs:
                for rule in sg.get('IpPermissions', []):
                    if rule.get('IpProtocol') == protocol:
                        from_port = rule.get('FromPort', 0)
                        to_port = rule.get('ToPort', 0)

                        # Check if port is in range
                        if from_port <= port <= to_port or (from_port == -1):
                            for ip_range in rule.get('IpRanges', []):
                                if ip_range.get('CidrIp') == '0.0.0.0/0':
                                    port_info = self.SENSITIVE_PORTS.get(port, {})
                                    open_groups.append({
                                        'group_id': sg['GroupId'],
                                        'group_name': sg['GroupName'],
                                        'port_name': port_info.get('name', f'Port {port}')
                                    })

            if open_groups:
                port_info = self.SENSITIVE_PORTS.get(port, {})
                severity = port_info.get('severity', Severity.MEDIUM)
                port_name = port_info.get('name', f'Port {port}')

                return Finding(
                    check_id=check_id,
                    title=f"{port_name} ({port}) Open to World",
                    description=f"{len(open_groups)} security group(s) allow unrestricted access.",
                    severity=severity,
                    resource="EC2 Security Groups",
                    recommendation=f"Restrict {port_name} access to known IP ranges.",
                    metadata={"security_groups": open_groups},
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title=f"Port {port} Properly Restricted",
                description="No security groups allow unrestricted access.",
                severity=Severity.INFO,
                resource="EC2 Security Groups",
                recommendation="Continue restricting access.",
                passed=True,
            )

        except ClientError as e:
            return Finding(
                check_id=check_id,
                title=f"Cannot Check Port {port}",
                description=f"Error: {e.response['Error']['Code']}",
                severity=Severity.INFO,
                resource="EC2 Security Groups",
                recommendation="Verify EC2 permissions.",
                passed=True,
            )

    def check_all_sensitive_ports(self) -> List[Finding]:
        """
        Check all sensitive ports.

        Returns:
            List of findings from all checks
        """
        findings = []

        for port in self.SENSITIVE_PORTS:
            findings.append(self.check_security_group_port(port))

        return findings

    def check_default_security_groups(self) -> Finding:
        """
        Check that default security groups are not in use.

        Returns:
            Finding with check result
        """
        check_id = "SG-DEFAULT-USAGE"

        try:
            sgs = self.ec2.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': ['default']}]
            )['SecurityGroups']

            # Check if any instances use default security groups
            instances_using_default = []

            for sg in sgs:
                # Get network interfaces using this security group
                enis = self.ec2.describe_network_interfaces(
                    Filters=[{'Name': 'group-id', 'Values': [sg['GroupId']]}]
                )['NetworkInterfaces']

                if enis:
                    instances_using_default.append({
                        'group_id': sg['GroupId'],
                        'vpc_id': sg.get('VpcId', 'N/A'),
                        'interfaces': len(enis)
                    })

            if instances_using_default:
                return Finding(
                    check_id=check_id,
                    title="Default Security Groups in Use",
                    description=f"{len(instances_using_default)} default security group(s) have resources attached.",
                    severity=Severity.MEDIUM,
                    resource="EC2 Security Groups",
                    recommendation="Create custom security groups and avoid using defaults.",
                    metadata={"groups": instances_using_default},
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title="Default Security Groups Not in Use",
                description="No resources are using default security groups.",
                severity=Severity.INFO,
                resource="EC2 Security Groups",
                recommendation="Continue using custom security groups.",
                passed=True,
            )

        except ClientError:
            return Finding(
                check_id=check_id,
                title="Cannot Check Default Security Groups",
                description="Unable to check security group usage.",
                severity=Severity.INFO,
                resource="EC2 Security Groups",
                recommendation="Verify EC2 permissions.",
                passed=True,
            )

    def check_network_acls(self) -> Finding:
        """
        Check Network ACLs for overly permissive rules.

        Returns:
            Finding with check result
        """
        check_id = "NACL-OPEN"

        try:
            nacls = self.ec2.describe_network_acls()['NetworkAcls']

            open_nacls = []

            for nacl in nacls:
                for entry in nacl.get('Entries', []):
                    if entry.get('RuleAction') == 'allow':
                        cidr = entry.get('CidrBlock', '')
                        port_range = entry.get('PortRange', {})

                        # Check for 0.0.0.0/0 with all ports
                        if cidr == '0.0.0.0/0':
                            from_port = port_range.get('From', 0)
                            to_port = port_range.get('To', 65535)

                            if from_port == 0 and to_port == 65535:
                                open_nacls.append({
                                    'nacl_id': nacl['NetworkAclId'],
                                    'vpc_id': nacl['VpcId'],
                                    'rule_number': entry.get('RuleNumber'),
                                    'egress': entry.get('Egress', False)
                                })

            if open_nacls:
                return Finding(
                    check_id=check_id,
                    title="Network ACLs Allow All Traffic",
                    description=f"{len(open_nacls)} NACL rule(s) allow all traffic from anywhere.",
                    severity=Severity.MEDIUM,
                    resource="VPC Network ACLs",
                    recommendation="Restrict NACL rules to necessary traffic only.",
                    metadata={"nacls": open_nacls},
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title="Network ACLs Properly Configured",
                description="No NACLs allow unrestricted all-port access.",
                severity=Severity.INFO,
                resource="VPC Network ACLs",
                recommendation="Continue following least privilege.",
                passed=True,
            )

        except ClientError:
            return Finding(
                check_id=check_id,
                title="Cannot Check Network ACLs",
                description="Unable to check NACL configuration.",
                severity=Severity.INFO,
                resource="VPC Network ACLs",
                recommendation="Verify EC2 permissions.",
                passed=True,
            )

    def check_vpc_flow_logs(self) -> Finding:
        """
        Check if VPC Flow Logs are enabled.

        Returns:
            Finding with check result
        """
        check_id = "VPC-FLOW-LOGS"

        try:
            vpcs = self.ec2.describe_vpcs()['Vpcs']
            flow_logs = self.ec2.describe_flow_logs()['FlowLogs']

            vpcs_with_flow_logs = {fl['ResourceId'] for fl in flow_logs if fl.get('FlowLogStatus') == 'ACTIVE'}
            vpcs_without_flow_logs = [vpc['VpcId'] for vpc in vpcs if vpc['VpcId'] not in vpcs_with_flow_logs]

            if vpcs_without_flow_logs:
                return Finding(
                    check_id=check_id,
                    title="VPCs Without Flow Logs",
                    description=f"{len(vpcs_without_flow_logs)} VPC(s) do not have Flow Logs enabled.",
                    severity=Severity.MEDIUM,
                    resource="VPC",
                    recommendation="Enable VPC Flow Logs for network monitoring.",
                    metadata={"vpcs": vpcs_without_flow_logs},
                    passed=False,
                )

            return Finding(
                check_id=check_id,
                title="All VPCs Have Flow Logs",
                description="All VPCs have Flow Logs enabled.",
                severity=Severity.INFO,
                resource="VPC",
                recommendation="Continue maintaining Flow Logs.",
                passed=True,
            )

        except ClientError:
            return Finding(
                check_id=check_id,
                title="Cannot Check VPC Flow Logs",
                description="Unable to check Flow Log status.",
                severity=Severity.INFO,
                resource="VPC",
                recommendation="Verify EC2 permissions.",
                passed=True,
            )
