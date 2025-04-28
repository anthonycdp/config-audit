"""
SSH configuration security checks.

Provides reusable check functions for SSH hardening validation.
"""

import re
from pathlib import Path
from typing import List, Dict, Any, Optional

from ..utils.severity import Finding, Severity


class SSHChecks:
    """
    Collection of SSH security check functions.

    These checks validate SSH daemon configuration against
    security best practices.
    """

    # Recommended SSH settings
    RECOMMENDED_SETTINGS = {
        'PermitRootLogin': {'recommended': 'no', 'severity': Severity.HIGH},
        'PasswordAuthentication': {'recommended': 'no', 'severity': Severity.HIGH},
        'PermitEmptyPasswords': {'recommended': 'no', 'severity': Severity.CRITICAL},
        'PubkeyAuthentication': {'recommended': 'yes', 'severity': Severity.MEDIUM},
        'X11Forwarding': {'recommended': 'no', 'severity': Severity.LOW},
        'AllowTcpForwarding': {'recommended': 'no', 'severity': Severity.LOW},
        'MaxAuthTries': {'recommended': '4', 'severity': Severity.MEDIUM},
        'ClientAliveInterval': {'recommended': '300', 'severity': Severity.LOW},
        'ClientAliveCountMax': {'recommended': '2', 'severity': Severity.LOW},
        'LoginGraceTime': {'recommended': '60', 'severity': Severity.LOW},
        'StrictModes': {'recommended': 'yes', 'severity': Severity.MEDIUM},
        'Protocol': {'recommended': '2', 'severity': Severity.HIGH},
    }

    def __init__(self, config_path: str = "/etc/ssh/sshd_config"):
        """
        Initialize SSH checks.

        Args:
            config_path: Path to sshd_config file
        """
        self.config_path = Path(config_path)

    def parse_config(self) -> Dict[str, str]:
        """
        Parse SSH configuration file into a dictionary.

        Returns:
            Dictionary of configuration key-value pairs
        """
        config = {}

        if not self.config_path.exists():
            return config

        try:
            with open(self.config_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse key-value pairs
                    match = re.match(r'^(\S+)\s+(.+)$', line)
                    if match:
                        key = match.group(1)
                        value = match.group(2).strip()
                        # Store last occurrence (ssh behavior)
                        config[key] = value
        except (PermissionError, IOError):
            pass

        return config

    def check_setting(
        self,
        setting: str,
        config: Optional[Dict[str, str]] = None
    ) -> Finding:
        """
        Check a specific SSH configuration setting.

        Args:
            setting: The configuration setting to check
            config: Optional pre-parsed configuration dict

        Returns:
            Finding with check result
        """
        if config is None:
            config = self.parse_config()

        check_id = f"SSH-{setting.upper()}"
        setting_info = self.RECOMMENDED_SETTINGS.get(setting)

        if not setting_info:
            return Finding(
                check_id=check_id,
                title=f"Unknown SSH Setting: {setting}",
                description=f"Check for {setting} is not implemented.",
                severity=Severity.INFO,
                resource=str(self.config_path),
                recommendation="Review manually.",
                passed=True,
            )

        current_value = config.get(setting)
        recommended_value = setting_info['recommended']
        severity = setting_info['severity']

        if current_value is None:
            return Finding(
                check_id=check_id,
                title=f"SSH {setting} Not Configured",
                description=f"{setting} is not explicitly set in configuration.",
                severity=Severity.MEDIUM,
                resource=str(self.config_path),
                recommendation=f"Set '{setting} {recommended_value}' explicitly.",
                passed=False,
            )

        # Normalize values for comparison
        current_normalized = current_value.lower().strip()
        recommended_normalized = recommended_value.lower().strip()

        if current_normalized == recommended_normalized:
            return Finding(
                check_id=check_id,
                title=f"SSH {setting} Secure",
                description=f"{setting} is correctly set to '{current_value}'.",
                severity=Severity.INFO,
                resource=str(self.config_path),
                recommendation="Continue maintaining this configuration.",
                passed=True,
            )
        else:
            return Finding(
                check_id=check_id,
                title=f"SSH {setting} Misconfigured",
                description=f"{setting} is set to '{current_value}', should be '{recommended_value}'.",
                severity=severity,
                resource=str(self.config_path),
                recommendation=f"Set '{setting} {recommended_value}' in {self.config_path}.",
                passed=False,
            )

    def check_all(self) -> List[Finding]:
        """
        Run all SSH configuration checks.

        Returns:
            List of findings from all checks
        """
        config = self.parse_config()
        findings = []

        for setting in self.RECOMMENDED_SETTINGS:
            findings.append(self.check_setting(setting, config))

        return findings

    def check_ciphers(self) -> Finding:
        """Check for weak SSH ciphers."""
        check_id = "SSH-CIPHERS"
        config = self.parse_config()

        ciphers = config.get('Ciphers', '')

        # Strong ciphers (ChaCha20, AES-GCM)
        strong_ciphers = [
            'chacha20-poly1305',
            'aes256-gcm',
            'aes128-gcm',
            'aes256-ctr',
            'aes192-ctr',
            'aes128-ctr',
        ]

        # Weak ciphers that should be avoided
        weak_ciphers = ['arcfour', 'blowfish', 'cast128', '3des']

        if not ciphers:
            return Finding(
                check_id=check_id,
                title="SSH Ciphers Not Explicitly Configured",
                description="No explicit cipher configuration. Using system defaults.",
                severity=Severity.LOW,
                resource=str(self.config_path),
                recommendation="Configure strong ciphers explicitly.",
                passed=True,
            )

        cipher_list = [c.strip().lower() for c in ciphers.split(',')]
        found_weak = [c for c in cipher_list if any(w in c for w in weak_ciphers)]

        if found_weak:
            return Finding(
                check_id=check_id,
                title="Weak SSH Ciphers Enabled",
                description=f"Weak ciphers found: {', '.join(found_weak)}",
                severity=Severity.HIGH,
                resource=str(self.config_path),
                recommendation="Remove weak ciphers and use only strong encryption.",
                passed=False,
            )

        return Finding(
            check_id=check_id,
            title="SSH Ciphers Secure",
            description="Configured ciphers appear to use strong encryption.",
            severity=Severity.INFO,
            resource=str(self.config_path),
            recommendation="Continue using strong ciphers.",
            passed=True,
        )
