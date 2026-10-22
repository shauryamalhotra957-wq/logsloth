"""
Tests for LogSloth — parser, analyzer, schemas, and ollama_client.
"""

from __future__ import annotations

import json
import os
import pathlib
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import asdict

# -----------------------------------------------------------------------
# Fixtures & helpers
# -----------------------------------------------------------------------

SAMPLE_LOG_PATH = pathlib.Path(__file__).parent.parent / "sample_data" / "synthetic_auth.log"


def _sample_text() -> str:
    return SAMPLE_LOG_PATH.read_text(encoding="utf-8")


# -----------------------------------------------------------------------
# Parser tests
# -----------------------------------------------------------------------

from logsloth.parser import parse_logs
from logsloth.schemas import EventType, ParseSummary


class TestParserBasics:
    """Deterministic parsing — no LLM involved."""

    def test_sample_log_loads(self):
        text = _sample_text()
        assert len(text) > 100

    def test_parse_returns_summary(self):
        summary = parse_logs(_sample_text())
        assert isinstance(summary, ParseSummary)
        assert summary.total_lines > 0
        assert summary.parsed_events > 0

    def test_total_line_accounting(self):
        """parsed + unrecognized + blank == total."""
        summary = parse_logs(_sample_text())
        assert (
            summary.parsed_events + summary.unrecognized_lines + summary.blank_lines
            == summary.total_lines
        )

    def test_event_ids_are_unique(self):
        summary = parse_logs(_sample_text())
        ids = [ev.event_id for ev in summary.events]
        assert len(ids) == len(set(ids))

    def test_event_ids_sequential(self):
        summary = parse_logs(_sample_text())
        for i, ev in enumerate(summary.events, 1):
            assert ev.event_id == f"E{i:03d}"

    def test_line_numbers_are_positive(self):
        summary = parse_logs(_sample_text())
        for ev in summary.events:
            assert ev.line_number >= 1


class TestParserEventTypes:
    """Check that specific event types are correctly recognised."""

    def test_failed_password(self):
        line = 'Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2'
        summary = parse_logs(line)
        assert summary.parsed_events == 1
        assert summary.events[0].event_type == EventType.FAILED_PASSWORD
        assert summary.events[0].username == "admin"
        assert summary.events[0].source_ip == "203.0.113.10"

    def test_failed_password_invalid_user(self):
        line = 'Oct 21 06:12:01 srv sshd[100]: Failed password for invalid user root from 203.0.113.10 port 42210 ssh2'
        summary = parse_logs(line)
        assert summary.parsed_events == 1
        assert summary.events[0].event_type == EventType.FAILED_PASSWORD
        assert summary.events[0].username == "root"

    def test_accepted_password(self):
        line = 'Oct 21 09:00:00 srv sshd[100]: Accepted password for alice from 192.0.2.100 port 55200 ssh2'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.ACCEPTED_PASSWORD
        assert summary.events[0].username == "alice"

    def test_accepted_publickey(self):
        line = 'Oct 21 06:25:01 srv sshd[100]: Accepted publickey for deploy from 192.0.2.50 port 55100 ssh2'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.ACCEPTED_PUBLICKEY
        assert summary.events[0].username == "deploy"

    def test_invalid_user(self):
        line = 'Oct 21 08:15:01 srv sshd[100]: Invalid user nagios from 203.0.113.45 port 44000'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.INVALID_USER
        assert summary.events[0].username == "nagios"

    def test_connection_closed(self):
        line = 'Oct 21 07:01:00 srv sshd[100]: Connection closed by 198.51.100.25 port 33136 [preauth]'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.CONNECTION_CLOSED

    def test_pam_session_open(self):
        line = 'Oct 21 06:25:02 srv sshd[100]: pam_unix(sshd:session): session opened for user deploy(uid=1001) by (uid=0)'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.PAM_SESSION_OPEN
        assert summary.events[0].username == "deploy(uid=1001)"

    def test_pam_session_close(self):
        line = 'Oct 21 06:30:15 srv sshd[100]: pam_unix(sshd:session): session closed for user deploy'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.PAM_SESSION_CLOSE

    def test_too_many_failures(self):
        line = 'Oct 21 07:00:50 srv sshd[100]: Disconnecting authenticating user root: too many authentication failures for root from 198.51.100.25 port 33136 ssh2'
        summary = parse_logs(line)
        assert summary.events[0].event_type == EventType.TOO_MANY_FAILURES
        assert summary.events[0].username == "root"


class TestParserEdgeCases:
    """Malformed, empty, and unsupported inputs."""

    def test_empty_input(self):
        summary = parse_logs("")
        assert summary.total_lines == 0
        assert summary.parsed_events == 0

    def test_blank_lines_only(self):
        summary = parse_logs("\n\n\n")
        assert summary.blank_lines == 3
        assert summary.parsed_events == 0

    def test_nonsense_lines(self):
        summary = parse_logs("hello world\nfoo bar baz\n")
        assert summary.parsed_events == 0
        assert summary.unrecognized_lines == 2

    def test_mixed_valid_invalid(self):
        text = (
            "Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2\n"
            "this is garbage\n"
            "Oct 21 09:00:00 srv sshd[100]: Accepted password for alice from 192.0.2.100 port 55200 ssh2\n"
        )
        summary = parse_logs(text)
        assert summary.parsed_events == 2
        assert summary.unrecognized_lines == 1
        assert summary.total_lines == 3

    def test_large_input_generates_sequential_ids(self):
        line = 'Oct 21 06:12:01 srv sshd[100]: Failed password for root from 203.0.113.10 port 42210 ssh2\n'
        text = line * 150
        summary = parse_logs(text)
        assert summary.parsed_events == 150
        assert summary.events[-1].event_id == "E150"


class TestParserSampleDataset:
    """Verify the bundled sample dataset parses correctly."""

    def test_sample_has_multiple_event_types(self):
        summary = parse_logs(_sample_text())
        types = {ev.event_type for ev in summary.events}
        assert EventType.FAILED_PASSWORD in types
        assert EventType.ACCEPTED_PASSWORD in types or EventType.ACCEPTED_PUBLICKEY in types

    def test_sample_has_multiple_ips(self):
        summary = parse_logs(_sample_text())
        ips = {ev.source_ip for ev in summary.events if ev.source_ip}
        assert len(ips) >= 3

    def test_sample_has_multiple_users(self):
        summary = parse_logs(_sample_text())
        users = {ev.username for ev in summary.events if ev.username}
        assert len(users) >= 3


# -----------------------------------------------------------------------
# Schema tests
# -----------------------------------------------------------------------

from logsloth.schemas import AnalysisReport, Finding, FullReport


class TestSchemas:
    def test_analysis_report_to_json(self):
        report = AnalysisReport(
            executive_summary="Test summary.",
            review_priority="Low",
            findings=[Finding(title="Test", description="Desc", evidence_ids=["E001"])],
            recommendations=["Do something."],
            limitations="None.",
        )
        j = report.to_json()
        data = json.loads(j)
        assert data["executive_summary"] == "Test summary."
        assert len(data["findings"]) == 1

    def test_full_report_to_markdown(self):
        fr = FullReport(
            app_version="0.1.0",
            parse_summary_stats={"total_lines": 10, "parsed_events": 5, "unrecognized_lines": 3, "blank_lines": 2},
            events=[],
            analysis={"executive_summary": "OK", "review_priority": "Low", "findings": [], "recommendations": [], "limitations": ""},
        )
        md = fr.to_markdown()
        assert "LogSloth" in md
        assert "0.1.0" in md
        assert "Privacy" in md

    def test_full_report_to_json(self):
        fr = FullReport(app_version="0.1.0")
        j = fr.to_json()
        data = json.loads(j)
        assert data["app_version"] == "0.1.0"


# -----------------------------------------------------------------------
# Ollama client tests (mocked)
# -----------------------------------------------------------------------

from logsloth.ollama_client import OllamaClient, OllamaStatus


class TestOllamaClientMocked:
    """Unit tests with mocked HTTP — no live Ollama needed."""

    @patch("logsloth.ollama_client.requests.get")
    def test_check_status_server_down(self, mock_get):
        mock_get.side_effect = Exception("Connection refused")
        client = OllamaClient()
        status = client.check_status()
        assert not status.server_reachable
        assert status.error

    @patch("logsloth.ollama_client.requests.get")
    def test_check_status_model_missing(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "/api/tags" in url:
                resp.json.return_value = {"models": [{"name": "other-model:latest"}]}
            else:
                resp.text = "Ollama is running"
            return resp
        mock_get.side_effect = side_effect
        client = OllamaClient(model="qwen2.5:7b")
        status = client.check_status()
        assert status.server_reachable
        assert not status.model_available

    @patch("logsloth.ollama_client.requests.get")
    def test_check_status_all_good(self, mock_get):
        def side_effect(url, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            if "/api/tags" in url:
                resp.json.return_value = {"models": [{"name": "qwen2.5:7b"}]}
            else:
                resp.text = "Ollama is running"
            return resp
        mock_get.side_effect = side_effect
        client = OllamaClient(model="qwen2.5:7b")
        status = client.check_status()
        assert status.server_reachable
        assert status.model_available

    @patch("logsloth.ollama_client.requests.post")
    def test_generate_success(self, mock_post):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"response": '{"result": "ok"}'}
        mock_post.return_value = resp
        client = OllamaClient()
        text, elapsed = client.generate("test prompt")
        assert text == '{"result": "ok"}'
        assert elapsed >= 0

    @patch("logsloth.ollama_client.requests.post")
    def test_generate_connection_error(self, mock_post):
        import requests as req
        mock_post.side_effect = req.ConnectionError("refused")
        client = OllamaClient()
        with pytest.raises(RuntimeError, match="Cannot reach Ollama"):
            client.generate("test prompt")

    @patch("logsloth.ollama_client.requests.post")
    def test_generate_empty_response(self, mock_post):
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"response": ""}
        mock_post.return_value = resp
        client = OllamaClient()
        with pytest.raises(RuntimeError, match="empty response"):
            client.generate("test prompt")


# -----------------------------------------------------------------------
# Analyzer tests (mocked model)
# -----------------------------------------------------------------------

from logsloth.analyzer import analyze, build_full_report, _extract_json, _validate_report


class TestExtractJson:
    def test_plain_json(self):
        assert _extract_json('{"a": 1}') == '{"a": 1}'

    def test_markdown_fenced(self):
        raw = '```json\n{"a": 1}\n```'
        assert _extract_json(raw) == '{"a": 1}'

    def test_text_before_json(self):
        raw = 'Here is the analysis:\n{"a": 1}'
        assert _extract_json(raw) == '{"a": 1}'


class TestValidateReport:
    def test_valid_evidence_ids(self):
        data = {
            "executive_summary": "ok",
            "review_priority": "Low",
            "findings": [{"title": "F1", "description": "d", "evidence_ids": ["E001"], "severity": "low"}],
            "recommendations": [],
            "limitations": "",
        }
        report, warnings = _validate_report(data, {"E001", "E002"})
        assert len(warnings) == 0
        assert report.findings[0].evidence_ids == ["E001"]

    def test_invalid_evidence_ids_removed(self):
        data = {
            "executive_summary": "ok",
            "review_priority": "Low",
            "findings": [{"title": "F1", "description": "d", "evidence_ids": ["E001", "E999"], "severity": "low"}],
            "recommendations": [],
            "limitations": "",
        }
        report, warnings = _validate_report(data, {"E001"})
        assert len(warnings) == 1
        assert "E999" in warnings[0]
        assert report.findings[0].evidence_ids == ["E001"]

    def test_all_fabricated_ids_removed(self):
        data = {
            "findings": [{"title": "F1", "description": "d", "evidence_ids": ["E900", "E901"]}],
        }
        report, warnings = _validate_report(data, {"E001"})
        assert report.findings[0].evidence_ids == []
        assert len(warnings) == 1

    def test_invalid_priority_defaults(self):
        data = {"review_priority": "CRITICAL", "executive_summary": "Some summary"}
        report, warnings = _validate_report(data, set())
        assert report.review_priority == "Medium"
        assert len(warnings) == 1

    def test_malformed_missing_summary_and_findings_raises(self):
        data = {"unexpected_key": "unexpected_value"}
        with pytest.raises(RuntimeError, match="malformed"):
            _validate_report(data, set())


class TestAnalyzerMocked:
    """Full analyze() with mocked model output."""

    def _mock_client(self, response_json: dict):
        client = MagicMock()
        client.model = "test-model"
        client.generate.return_value = (json.dumps(response_json), 1.23)
        return client

    def test_analyze_success(self):
        summary = parse_logs(
            "Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2\n"
            "Oct 21 06:12:05 srv sshd[101]: Accepted password for alice from 192.0.2.100 port 55200 ssh2\n"
        )
        model_output = {
            "executive_summary": "One failed login and one success.",
            "review_priority": "Low",
            "findings": [
                {
                    "title": "Failed login",
                    "description": "One failed attempt.",
                    "evidence_ids": ["E001"],
                    "severity": "low",
                }
            ],
            "recommendations": ["Monitor."],
            "limitations": "Limited data.",
        }
        client = self._mock_client(model_output)
        report = analyze(summary, client)
        assert report.executive_summary == "One failed login and one success."
        assert report.review_priority == "Low"
        assert len(report.findings) == 1
        assert report.model_used == "test-model"

    def test_analyze_malformed_json(self):
        summary = parse_logs(
            "Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2\n"
        )
        client = MagicMock()
        client.model = "test-model"
        client.generate.return_value = ("This is not JSON at all!!!", 0.5)
        with pytest.raises(RuntimeError, match="not valid JSON"):
            analyze(summary, client)

    def test_analyze_model_unreachable(self):
        summary = parse_logs(
            "Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2\n"
        )
        client = MagicMock()
        client.model = "test-model"
        client.generate.side_effect = RuntimeError("Cannot reach Ollama")
        with pytest.raises(RuntimeError, match="Cannot reach Ollama"):
            analyze(summary, client)


class TestBuildFullReport:
    def test_full_report_round_trip(self):
        summary = parse_logs(
            "Oct 21 06:12:01 srv sshd[100]: Failed password for admin from 203.0.113.10 port 42210 ssh2\n"
        )
        report = AnalysisReport(
            executive_summary="Test.",
            review_priority="Low",
        )
        full = build_full_report(summary, report, "0.1.0")
        j = full.to_json()
        data = json.loads(j)
        assert data["app_version"] == "0.1.0"
        assert data["parse_summary_stats"]["parsed_events"] == 1

        md = full.to_markdown()
        assert "LogSloth" in md
        assert "Privacy" in md


# -----------------------------------------------------------------------
# Privacy & safety invariant tests
# -----------------------------------------------------------------------

class TestPrivacySafety:
    """Verify no data leaks or dangerous actions in design."""

    def test_no_telemetry_env_vars(self):
        """No telemetry endpoint configured in environment."""
        for key in os.environ:
            key_lower = key.lower()
            assert "telemetry" not in key_lower or "logsloth" not in key_lower

    def test_parser_does_not_execute(self):
        """Parser must not execute commands from logs."""
        malicious = (
            "Oct 21 06:12:01 srv sshd[100]: Failed password for `rm -rf /` from 203.0.113.10 port 42210 ssh2\n"
        )
        # Should parse safely without side effects
        summary = parse_logs(malicious)
        assert summary.total_lines == 1

    def test_sample_uses_rfc5737_ips(self):
        """All IPs in sample data should be documentation-only (RFC 5737)."""
        import re
        text = _sample_text()
        ips = set(re.findall(r"\d+\.\d+\.\d+\.\d+", text))
        rfc5737_prefixes = ("192.0.2.", "198.51.100.", "203.0.113.")
        for ip in ips:
            assert any(ip.startswith(p) for p in rfc5737_prefixes), (
                f"IP {ip} is not in an RFC 5737 documentation range"
            )

    def test_ollama_client_uses_localhost(self):
        """Default client should only talk to localhost."""
        client = OllamaClient()
        assert "localhost" in client.base_url or "127.0.0.1" in client.base_url


# -----------------------------------------------------------------------
# Export tests
# -----------------------------------------------------------------------

class TestExport:
    def test_markdown_export_contains_sections(self):
        fr = FullReport(
            app_version="0.1.0",
            parse_summary_stats={"total_lines": 10, "parsed_events": 5, "unrecognized_lines": 3, "blank_lines": 2},
            analysis={
                "executive_summary": "Summary.",
                "review_priority": "Medium",
                "findings": [{"title": "F1", "description": "D1", "evidence_ids": ["E001"], "severity": "medium"}],
                "recommendations": ["R1"],
                "limitations": "L1",
            },
        )
        md = fr.to_markdown()
        assert "## Parse Summary" in md
        assert "## Executive Summary" in md
        assert "## Findings" in md
        assert "## Recommendations" in md
        assert "## Privacy Notice" in md

    def test_json_export_is_valid(self):
        fr = FullReport(app_version="0.1.0")
        data = json.loads(fr.to_json())
        assert "privacy_note" in data
