"""
Report generator for configuration audit findings.

Generates prioritized, actionable reports in multiple formats.
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..utils.severity import Finding, Severity


class ReportGenerator:
    """
    Generates audit reports from findings with prioritization.

    Supports multiple output formats:
    - JSON (machine-readable)
    - Markdown (documentation)
    - HTML (visual reports)
    - Plain text (terminal output)
    """

    def __init__(self, title: str = "Configuration Security Audit Report"):
        """
        Initialize the report generator.

        Args:
            title: Report title
        """
        self.title = title
        self.generated_at = datetime.now(timezone.utc)

    def prioritize_findings(
        self,
        findings: List[Finding],
        include_passed: bool = False
    ) -> Dict[str, List[Finding]]:
        """
        Sort and group findings by severity.

        Args:
            findings: List of findings to prioritize
            include_passed: Include passed checks in results

        Returns:
            Dictionary of findings grouped by severity
        """
        # Filter out passed checks if not included
        if not include_passed:
            findings = [f for f in findings if not f.passed]

        # Sort by severity (highest first)
        sorted_findings = sorted(
            findings,
            key=lambda f: f.severity.value,
            reverse=True
        )

        # Group by severity
        grouped = {}
        for finding in sorted_findings:
            severity_name = finding.severity.name
            if severity_name not in grouped:
                grouped[severity_name] = []
            grouped[severity_name].append(finding)

        return grouped

    def generate_summary(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Generate a summary of findings.

        Args:
            findings: List of findings

        Returns:
            Summary dictionary
        """
        total = len(findings)
        passed = sum(1 for f in findings if f.passed)
        failed = total - passed

        by_severity = {}
        for severity in Severity:
            count = sum(1 for f in findings if f.severity == severity and not f.passed)
            if count > 0:
                by_severity[severity.name] = count

        # Calculate risk score
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }

        risk_score = sum(
            severity_weights.get(f.severity, 0)
            for f in findings if not f.passed
        )

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "pass_rate": f"{(passed / total * 100):.1f}%" if total > 0 else "N/A",
            "by_severity": by_severity,
            "risk_score": risk_score,
            "risk_level": self._calculate_risk_level(risk_score),
        }

    def _calculate_risk_level(self, score: int) -> str:
        """Calculate overall risk level from score."""
        if score >= 50:
            return "CRITICAL"
        elif score >= 30:
            return "HIGH"
        elif score >= 15:
            return "MEDIUM"
        elif score >= 5:
            return "LOW"
        else:
            return "MINIMAL"

    def generate_json_report(
        self,
        findings: List[Finding],
        include_passed: bool = False,
        pretty: bool = True
    ) -> str:
        """
        Generate a JSON report.

        Args:
            findings: List of findings
            include_passed: Include passed checks
            pretty: Pretty-print JSON

        Returns:
            JSON string
        """
        report = {
            "title": self.title,
            "generated_at": self.generated_at.isoformat(),
            "summary": self.generate_summary(findings),
            "findings": self.prioritize_findings(findings, include_passed),
        }

        # Convert findings to dict
        report["findings"] = {
            severity: [f.to_dict() for f in findings_list]
            for severity, findings_list in report["findings"].items()
        }

        indent = 2 if pretty else None
        return json.dumps(report, indent=indent, default=str)

    def generate_markdown_report(
        self,
        findings: List[Finding],
        include_passed: bool = False
    ) -> str:
        """
        Generate a Markdown report.

        Args:
            findings: List of findings
            include_passed: Include passed checks

        Returns:
            Markdown string
        """
        summary = self.generate_summary(findings)
        prioritized = self.prioritize_findings(findings, include_passed)

        lines = [
            f"# {self.title}",
            "",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            "## Executive Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Total Checks | {summary['total_checks']} |",
            f"| Passed | {summary['passed']} |",
            f"| Failed | {summary['failed']} |",
            f"| Pass Rate | {summary['pass_rate']} |",
            f"| Risk Score | {summary['risk_score']} |",
            f"| Risk Level | **{summary['risk_level']}** |",
            "",
        ]

        # Severity breakdown
        if summary['by_severity']:
            lines.extend([
                "### Findings by Severity",
                "",
            ])
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in summary['by_severity']:
                    lines.append(f"- **{severity}:** {summary['by_severity'][severity]}")

            lines.append("")

        # Detailed findings
        lines.extend([
            "## Detailed Findings",
            "",
        ])

        severity_icons = {
            'CRITICAL': '🔴',
            'HIGH': '🟠',
            'MEDIUM': '🟡',
            'LOW': '🟢',
            'INFO': 'ℹ️',
        }

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in prioritized and prioritized[severity]:
                icon = severity_icons.get(severity, '•')
                lines.extend([
                    f"### {icon} {severity}",
                    "",
                ])

                for finding in prioritized[severity]:
                    status = "✅" if finding.passed else "❌"
                    lines.extend([
                        f"#### {status} {finding.check_id}: {finding.title}",
                        "",
                        f"**Resource:** `{finding.resource}`",
                        "",
                        f"**Description:** {finding.description}",
                        "",
                        f"**Recommendation:** {finding.recommendation}",
                        "",
                    ])

                    if finding.references:
                        lines.append("**References:**")
                        for ref in finding.references:
                            lines.append(f"- [{ref}]({ref})")
                        lines.append("")

                    lines.append("---")
                    lines.append("")

        return "\n".join(lines)

    _SEVERITY_COLORS = {
        'CRITICAL': '#dc2626',
        'HIGH': '#ea580c',
        'MEDIUM': '#ca8a04',
        'LOW': '#16a34a',
        'INFO': '#6b7280',
    }

    _SEVERITY_BG_COLORS = {
        'CRITICAL': '#fef2f2',
        'HIGH': '#fff7ed',
        'MEDIUM': '#fefce8',
        'LOW': '#f0fdf4',
        'INFO': '#f9fafb',
    }

    def _get_html_styles(self) -> str:
        """Return CSS styles for HTML report."""
        return """
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1f2937; background: #f3f4f6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        h1 { font-size: 2rem; margin-bottom: 0.5rem; color: #111827; }
        h2 { font-size: 1.5rem; margin: 2rem 0 1rem; color: #374151; border-bottom: 2px solid #e5e7eb; padding-bottom: 0.5rem; }
        h3 { font-size: 1.25rem; margin: 1.5rem 0 1rem; }
        h4 { font-size: 1rem; margin: 1rem 0 0.5rem; }
        .meta { color: #6b7280; margin-bottom: 2rem; }
        .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .summary-card { background: white; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .summary-card h3 { margin: 0 0 0.5rem; font-size: 0.875rem; color: #6b7280; text-transform: uppercase; }
        .summary-card .value { font-size: 2rem; font-weight: bold; color: #111827; }
        .severity-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; color: white; }
        .finding { background: white; margin-bottom: 1rem; padding: 1.5rem; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border-left: 4px solid; }
        .finding.passed { border-color: #16a34a; }
        .finding.failed { border-color: var(--severity-color); }
        .finding h4 { display: flex; align-items: center; gap: 0.5rem; }
        .finding .resource { font-family: monospace; background: #f3f4f6; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }
        .finding .description { margin: 0.5rem 0; color: #4b5563; }
        .finding .recommendation { background: #f9fafb; padding: 0.75rem; border-radius: 4px; margin-top: 0.5rem; }
        .finding .references { margin-top: 0.5rem; }
        .finding .references a { color: #2563eb; text-decoration: none; }
        .finding .references a:hover { text-decoration: underline; }
        .status-pass { color: #16a34a; }
        .status-fail { color: #dc2626; }
        .risk-critical { background: #dc2626 !important; color: white !important; }
        .risk-high { background: #ea580c !important; color: white !important; }
        .risk-medium { background: #ca8a04 !important; color: white !important; }
        .risk-low { background: #16a34a !important; color: white !important; }
    """

    def _build_html_header(self) -> str:
        """Build HTML document header."""
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{self.title}</title>
    <style>{self._get_html_styles()}</style>
</head>
<body>
    <div class="container">
        <h1>{self.title}</h1>
        <p class="meta">Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
"""

    def _build_summary_cards(self, summary: Dict[str, Any]) -> str:
        """Build summary cards HTML."""
        return f"""
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="summary-card"><h3>Total Checks</h3><div class="value">{summary['total_checks']}</div></div>
            <div class="summary-card"><h3>Passed</h3><div class="value status-pass">{summary['passed']}</div></div>
            <div class="summary-card"><h3>Failed</h3><div class="value status-fail">{summary['failed']}</div></div>
            <div class="summary-card"><h3>Risk Score</h3><div class="value">{summary['risk_score']}</div></div>
            <div class="summary-card"><h3>Risk Level</h3><div class="value risk-{summary['risk_level'].lower()}">{summary['risk_level']}</div></div>
        </div>
"""

    def _build_severity_breakdown(self, by_severity: Dict[str, int]) -> str:
        """Build severity breakdown HTML."""
        if not by_severity:
            return ""

        cards = ""
        for severity, count in by_severity.items():
            color = self._SEVERITY_COLORS.get(severity, '#6b7280')
            cards += f"""
            <div class="summary-card">
                <span class="severity-badge" style="background: {color}">{severity}</span>
                <div class="value">{count}</div>
            </div>
"""
        return f"""
        <h3>Findings by Severity</h3>
        <div class="summary-grid">{cards}        </div>
"""

    def _build_finding_html(self, finding: Finding, color: str) -> str:
        """Build HTML for a single finding."""
        status_class = "passed" if finding.passed else "failed"
        status_text = "✅ PASS" if finding.passed else "❌ FAIL"

        html = f"""
            <div class="finding {status_class}" style="--severity-color: {color}">
                <h4><span>{status_text}</span><span>{finding.check_id}:</span><span>{finding.title}</span></h4>
                <p><strong>Resource:</strong> <span class="resource">{finding.resource}</span></p>
                <p class="description">{finding.description}</p>
                <div class="recommendation"><strong>Recommendation:</strong> {finding.recommendation}</div>
"""
        if finding.references:
            refs = "".join(f'<li><a href="{ref}" target="_blank">{ref}</a></li>' for ref in finding.references)
            html += f"""
                <div class="references"><strong>References:</strong><ul>{refs}</ul></div>
"""
        return html + "            </div>\n"

    def _build_findings_section(self, prioritized: Dict[str, List[Finding]]) -> str:
        """Build detailed findings section."""
        html = "        <h2>Detailed Findings</h2>\n"

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity not in prioritized or not prioritized[severity]:
                continue

            color = self._SEVERITY_COLORS.get(severity, '#6b7280')
            bg_color = self._SEVERITY_BG_COLORS.get(severity, '#f9fafb')

            html += f"""
        <div style="background: {bg_color}; padding: 1rem; border-radius: 8px; margin-bottom: 1rem;">
            <h3><span class="severity-badge" style="background: {color}">{severity}</span></h3>
"""
            for finding in prioritized[severity]:
                html += self._build_finding_html(finding, color)

            html += "        </div>\n"

        return html

    def generate_html_report(
        self,
        findings: List[Finding],
        include_passed: bool = False
    ) -> str:
        """
        Generate an HTML report.

        Args:
            findings: List of findings
            include_passed: Include passed checks

        Returns:
            HTML string
        """
        summary = self.generate_summary(findings)
        prioritized = self.prioritize_findings(findings, include_passed)

        html = self._build_html_header()
        html += self._build_summary_cards(summary)
        html += self._build_severity_breakdown(summary['by_severity'])
        html += self._build_findings_section(prioritized)
        html += """
    </div>
</body>
</html>
"""
        return html

    def generate_terminal_report(
        self,
        findings: List[Finding],
        include_passed: bool = False,
        use_colors: bool = True
    ) -> str:
        """
        Generate a terminal-friendly report.

        Args:
            findings: List of findings
            include_passed: Include passed checks
            use_colors: Use ANSI color codes

        Returns:
            Terminal-formatted string
        """
        summary = self.generate_summary(findings)
        prioritized = self.prioritize_findings(findings, include_passed)

        # ANSI color codes
        if use_colors:
            colors = {
                'reset': '\033[0m',
                'bold': '\033[1m',
                'red': '\033[91m',
                'orange': '\033[93m',
                'yellow': '\033[94m',
                'green': '\033[92m',
                'gray': '\033[90m',
                'cyan': '\033[96m',
            }
        else:
            colors = {k: '' for k in ['reset', 'bold', 'red', 'orange', 'yellow', 'green', 'gray', 'cyan']}

        severity_colors = {
            'CRITICAL': colors['red'],
            'HIGH': colors['orange'],
            'MEDIUM': colors['yellow'],
            'LOW': colors['green'],
            'INFO': colors['gray'],
        }

        lines = [
            f"{colors['bold']}{colors['cyan']}{'='*60}{colors['reset']}",
            f"{colors['bold']}{self.title:^60}{colors['reset']}",
            f"{colors['cyan']}{'='*60}{colors['reset']}",
            "",
            f"Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "",
            f"{colors['bold']}Executive Summary{colors['reset']}",
            "-" * 40,
            f"  Total Checks:  {summary['total_checks']}",
            f"  Passed:        {colors['green']}{summary['passed']}{colors['reset']}",
            f"  Failed:        {colors['red']}{summary['failed']}{colors['reset']}",
            f"  Pass Rate:     {summary['pass_rate']}",
            f"  Risk Score:    {summary['risk_score']}",
            f"  Risk Level:    {severity_colors.get(summary['risk_level'], '')}{summary['risk_level']}{colors['reset']}",
            "",
        ]

        if summary['by_severity']:
            lines.append(f"{colors['bold']}By Severity:{colors['reset']}")
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if severity in summary['by_severity']:
                    color = severity_colors.get(severity, '')
                    lines.append(f"  {color}●{colors['reset']} {severity}: {summary['by_severity'][severity]}")
            lines.append("")

        lines.extend([
            f"{colors['bold']}Detailed Findings{colors['reset']}",
            "-" * 40,
            "",
        ])

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if severity in prioritized and prioritized[severity]:
                color = severity_colors.get(severity, '')
                lines.append(f"{colors['bold']}{color}[{severity}]{colors['reset']}")

                for finding in prioritized[severity]:
                    status = f"{colors['green']}✓ PASS{colors['reset']}" if finding.passed else f"{colors['red']}✗ FAIL{colors['reset']}"
                    lines.extend([
                        f"  {status} {finding.check_id}: {finding.title}",
                        f"         Resource: {finding.resource}",
                        f"         {finding.description}",
                        "",
                    ])

                lines.append("")

        lines.append(f"{colors['cyan']}{'='*60}{colors['reset']}")

        return "\n".join(lines)

    def save_report(
        self,
        findings: List[Finding],
        output_path: str,
        format: str = "json",
        include_passed: bool = False
    ) -> None:
        """
        Save report to a file.

        Args:
            findings: List of findings
            output_path: Path to save the report
            format: Output format (json, markdown, html, text)
            include_passed: Include passed checks
        """
        format_generators = {
            'json': self.generate_json_report,
            'markdown': self.generate_markdown_report,
            'md': self.generate_markdown_report,
            'html': self.generate_html_report,
            'text': self.generate_terminal_report,
        }

        generator = format_generators.get(format.lower())
        if not generator:
            raise ValueError(f"Unsupported format: {format}")

        # Generate report
        kwargs = {'findings': findings, 'include_passed': include_passed}
        if format == 'text':
            kwargs['use_colors'] = False
        elif format == 'json':
            kwargs['pretty'] = True

        content = generator(**kwargs)

        # Write to file
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding='utf-8')

        print(f"Report saved to: {output_path}")
