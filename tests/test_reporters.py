"""
Tests for report generator.
"""

import json
import pytest
from datetime import datetime
from pathlib import Path
import tempfile

from config_auditor.reporters.report_generator import ReportGenerator
from config_auditor.utils.severity import Severity, Finding


class TestReportGenerator:
    """Test cases for ReportGenerator class."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        return [
            Finding(
                check_id="TEST-001",
                title="Critical Finding",
                description="A critical security issue",
                severity=Severity.CRITICAL,
                resource="/test/critical",
                recommendation="Fix immediately",
                passed=False,
            ),
            Finding(
                check_id="TEST-002",
                title="High Finding",
                description="A high severity issue",
                severity=Severity.HIGH,
                resource="/test/high",
                recommendation="Fix soon",
                passed=False,
            ),
            Finding(
                check_id="TEST-003",
                title="Medium Finding",
                description="A medium severity issue",
                severity=Severity.MEDIUM,
                resource="/test/medium",
                recommendation="Fix eventually",
                passed=False,
            ),
            Finding(
                check_id="TEST-004",
                title="Passed Check",
                description="This check passed",
                severity=Severity.INFO,
                resource="/test/passed",
                recommendation="No action needed",
                passed=True,
            ),
        ]

    @pytest.fixture
    def generator(self):
        """Create a report generator."""
        return ReportGenerator(title="Test Report")

    def test_init(self, generator):
        """Test generator initialization."""
        assert generator.title == "Test Report"
        assert generator.generated_at is not None

    def test_prioritize_findings(self, generator, sample_findings):
        """Test prioritization of findings."""
        prioritized = generator.prioritize_findings(sample_findings)

        # Should only include failed findings by default
        assert "CRITICAL" in prioritized
        assert "HIGH" in prioritized
        assert "MEDIUM" in prioritized
        assert "INFO" not in prioritized  # Passed check, excluded

        # Should be sorted by severity
        severities = list(prioritized.keys())
        assert severities[0] == "CRITICAL"
        assert severities[1] == "HIGH"
        assert severities[2] == "MEDIUM"

    def test_prioritize_findings_with_passed(self, generator, sample_findings):
        """Test prioritization including passed checks."""
        prioritized = generator.prioritize_findings(sample_findings, include_passed=True)

        # Should include INFO (passed check)
        assert "INFO" in prioritized

    def test_generate_summary(self, generator, sample_findings):
        """Test summary generation."""
        summary = generator.generate_summary(sample_findings)

        assert summary["total_checks"] == 4
        assert summary["passed"] == 1
        assert summary["failed"] == 3
        assert summary["pass_rate"] == "25.0%"
        assert summary["risk_score"] > 0
        assert summary["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "MINIMAL"]

    def test_generate_summary_empty(self, generator):
        """Test summary generation with no findings."""
        summary = generator.generate_summary([])

        assert summary["total_checks"] == 0
        assert summary["passed"] == 0
        assert summary["failed"] == 0
        assert summary["risk_score"] == 0

    def test_calculate_risk_level(self, generator):
        """Test risk level calculation."""
        assert generator._calculate_risk_level(100) == "CRITICAL"
        assert generator._calculate_risk_level(50) == "CRITICAL"
        assert generator._calculate_risk_level(30) == "HIGH"
        assert generator._calculate_risk_level(15) == "MEDIUM"
        assert generator._calculate_risk_level(5) == "LOW"
        assert generator._calculate_risk_level(0) == "MINIMAL"

    def test_generate_json_report(self, generator, sample_findings):
        """Test JSON report generation."""
        json_report = generator.generate_json_report(sample_findings)

        # Should be valid JSON
        parsed = json.loads(json_report)

        assert parsed["title"] == "Test Report"
        assert "generated_at" in parsed
        assert "summary" in parsed
        assert "findings" in parsed

    def test_generate_json_report_pretty(self, generator, sample_findings):
        """Test pretty JSON report generation."""
        json_pretty = generator.generate_json_report(sample_findings, pretty=True)
        json_compact = generator.generate_json_report(sample_findings, pretty=False)

        # Pretty should have more whitespace
        assert len(json_pretty) > len(json_compact)

    def test_generate_markdown_report(self, generator, sample_findings):
        """Test Markdown report generation."""
        md_report = generator.generate_markdown_report(sample_findings)

        assert "# Test Report" in md_report
        assert "Executive Summary" in md_report
        assert "Detailed Findings" in md_report
        assert "Critical Finding" in md_report

    def test_generate_markdown_report_with_passed(self, generator, sample_findings):
        """Test Markdown report with passed checks."""
        md_report = generator.generate_markdown_report(sample_findings, include_passed=True)

        assert "Passed Check" in md_report

    def test_generate_html_report(self, generator, sample_findings):
        """Test HTML report generation."""
        html_report = generator.generate_html_report(sample_findings)

        assert "<!DOCTYPE html>" in html_report
        assert "<title>Test Report</title>" in html_report
        assert "Critical Finding" in html_report

    def test_generate_terminal_report(self, generator, sample_findings):
        """Test terminal report generation."""
        term_report = generator.generate_terminal_report(sample_findings)

        assert "Test Report" in term_report
        assert "Executive Summary" in term_report

    def test_generate_terminal_report_no_colors(self, generator, sample_findings):
        """Test terminal report without colors."""
        term_report = generator.generate_terminal_report(sample_findings, use_colors=False)

        # Should not contain ANSI codes
        assert "\033[" not in term_report

    def test_save_report_json(self, generator, sample_findings):
        """Test saving JSON report to file."""
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            output_path = f.name

        try:
            generator.save_report(sample_findings, output_path, format="json")

            # File should exist and contain valid JSON
            assert Path(output_path).exists()
            with open(output_path, 'r') as f:
                parsed = json.load(f)
            assert parsed["title"] == "Test Report"
        finally:
            Path(output_path).unlink()

    def test_save_report_markdown(self, generator, sample_findings):
        """Test saving Markdown report to file."""
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False) as f:
            output_path = f.name

        try:
            generator.save_report(sample_findings, output_path, format="markdown")

            assert Path(output_path).exists()
            content = Path(output_path).read_text(encoding='utf-8')
            assert "# Test Report" in content
        finally:
            Path(output_path).unlink()

    def test_save_report_html(self, generator, sample_findings):
        """Test saving HTML report to file."""
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            generator.save_report(sample_findings, output_path, format="html")

            assert Path(output_path).exists()
            content = Path(output_path).read_text(encoding='utf-8')
            assert "<!DOCTYPE html>" in content
        finally:
            Path(output_path).unlink()

    def test_save_report_invalid_format(self, generator, sample_findings):
        """Test saving with invalid format."""
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            output_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported format"):
                generator.save_report(sample_findings, output_path, format="invalid")
        finally:
            Path(output_path).unlink()

    def test_save_report_creates_directories(self, generator, sample_findings):
        """Test that save_report creates parent directories."""
        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "subdir" / "report.json"

            generator.save_report(sample_findings, str(output_path), format="json")

            assert output_path.exists()


class TestFindingSerialization:
    """Test cases for Finding serialization."""

    def test_finding_to_dict(self):
        """Test converting finding to dictionary."""
        finding = Finding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource="/test/resource",
            recommendation="Test recommendation",
            references=["https://example.com"],
            metadata={"key": "value"},
            passed=False,
        )

        result = finding.to_dict()

        assert isinstance(result["timestamp"], str)  # Should be ISO format string
        assert result["check_id"] == "TEST-001"
        assert result["severity"] == "HIGH"
        assert result["references"] == ["https://example.com"]
        assert result["metadata"] == {"key": "value"}

    def test_finding_str(self):
        """Test string representation."""
        finding = Finding(
            check_id="TEST-001",
            title="Test Finding",
            description="Test description",
            severity=Severity.HIGH,
            resource="/test/resource",
            recommendation="Test recommendation",
            passed=False,
        )

        result = str(finding)

        assert "TEST-001" in result
        assert "Test Finding" in result
        assert "FAIL" in result


class TestSeverity:
    """Test cases for Severity enum."""

    def test_severity_ordering(self):
        """Test severity ordering."""
        assert Severity.CRITICAL.value > Severity.HIGH.value
        assert Severity.HIGH.value > Severity.MEDIUM.value
        assert Severity.MEDIUM.value > Severity.LOW.value
        assert Severity.LOW.value > Severity.INFO.value

    def test_severity_str(self):
        """Test severity string representation."""
        assert str(Severity.CRITICAL) == "CRITICAL"
        assert str(Severity.HIGH) == "HIGH"

    def test_severity_color(self):
        """Test severity colors."""
        assert Severity.CRITICAL.color != ""
        assert Severity.INFO.color != ""

    def test_severity_icon(self):
        """Test severity icons."""
        assert Severity.CRITICAL.icon != ""
        assert Severity.INFO.icon != ""
