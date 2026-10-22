"""
Data models for LogSloth parsed events and analysis reports.

All structures are plain dataclasses so they serialize cleanly to JSON
and remain independent of any UI or AI framework.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Parsed-event types
# ---------------------------------------------------------------------------

class EventType(str, Enum):
    """Recognised SSH / auth-log event categories."""
    FAILED_PASSWORD = "failed_password"
    ACCEPTED_PASSWORD = "accepted_password"
    ACCEPTED_PUBLICKEY = "accepted_publickey"
    INVALID_USER = "invalid_user"
    CONNECTION_CLOSED = "connection_closed"
    DISCONNECTED = "disconnected"
    PAM_SESSION_OPEN = "pam_session_open"
    PAM_SESSION_CLOSE = "pam_session_close"
    TOO_MANY_FAILURES = "too_many_failures"
    OTHER = "other"


@dataclass
class ParsedEvent:
    """A single recognized authentication event extracted from one log line."""
    event_id: str              # e.g. "E001"
    line_number: int           # 1-based line number in the original input
    timestamp: Optional[str]   # raw timestamp string from the log line
    hostname: Optional[str]
    service: Optional[str]     # e.g. "sshd"
    event_type: EventType
    username: Optional[str] = None
    source_ip: Optional[str] = None
    port: Optional[int] = None
    raw_line: str = ""
    details: str = ""          # human-readable one-liner


@dataclass
class ParseSummary:
    """Aggregate statistics from the parsing phase."""
    total_lines: int = 0
    parsed_events: int = 0
    unrecognized_lines: int = 0
    blank_lines: int = 0
    events: list[ParsedEvent] = field(default_factory=list)
    unrecognized: list[dict] = field(default_factory=list)  # [{line_number, raw_line}]


# ---------------------------------------------------------------------------
# AI-analysis report
# ---------------------------------------------------------------------------

class ReviewPriority(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"


@dataclass
class Finding:
    """One observed pattern with evidence."""
    title: str
    description: str
    evidence_ids: list[str] = field(default_factory=list)
    severity: str = "informational"  # informational / low / medium / high


@dataclass
class AnalysisReport:
    """Structured security briefing produced by the AI model."""
    executive_summary: str = ""
    review_priority: str = "Medium"
    findings: list[Finding] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    limitations: str = ""
    model_used: str = ""
    raw_model_output: str = ""
    validation_warnings: list[str] = field(default_factory=list)
    generation_time_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)


@dataclass
class FullReport:
    """Combined parse + analysis report for export."""
    app_version: str = ""
    parse_summary_stats: dict = field(default_factory=dict)
    events: list[dict] = field(default_factory=list)
    analysis: dict = field(default_factory=dict)
    privacy_note: str = (
        "This report was generated entirely on your local machine using a "
        "local open-weight language model. No log data was transmitted to "
        "any external service. You are responsible for securing this device "
        "and any exported reports."
    )

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, default=str)

    def to_markdown(self) -> str:
        lines: list[str] = []
        lines.append("# 🦥 LogSloth Security Briefing\n")
        lines.append(f"**App version:** {self.app_version}\n")

        # Parse stats
        stats = self.parse_summary_stats
        lines.append("## Parse Summary\n")
        lines.append(f"| Metric | Count |")
        lines.append(f"|--------|-------|")
        lines.append(f"| Total lines examined | {stats.get('total_lines', 0)} |")
        lines.append(f"| Events parsed | {stats.get('parsed_events', 0)} |")
        lines.append(f"| Unrecognized lines | {stats.get('unrecognized_lines', 0)} |")
        lines.append(f"| Blank lines | {stats.get('blank_lines', 0)} |")
        lines.append("")

        # Analysis
        a = self.analysis
        if a:
            lines.append("## Executive Summary\n")
            lines.append(a.get("executive_summary", "_No summary available._"))
            lines.append("")
            lines.append(f"**Review Priority:** {a.get('review_priority', 'N/A')}\n")

            findings = a.get("findings", [])
            if findings:
                lines.append("## Findings\n")
                for i, f in enumerate(findings, 1):
                    lines.append(f"### {i}. {f.get('title', 'Untitled')}\n")
                    lines.append(f"{f.get('description', '')}\n")
                    ev = f.get("evidence_ids", [])
                    if ev:
                        lines.append(f"**Evidence:** {', '.join(ev)}\n")
                    lines.append(f"**Severity:** {f.get('severity', 'informational')}\n")

            recs = a.get("recommendations", [])
            if isinstance(recs, str):
                recs = [recs]
            if recs:
                lines.append("## Recommendations\n")
                for r in recs:
                    if str(r).strip():
                        lines.append(f"- {str(r).strip()}")
                lines.append("")

            lim = a.get("limitations", "")
            if lim:
                lines.append("## Limitations & Uncertainty\n")
                lines.append(lim)
                lines.append("")

        lines.append("## Privacy Notice\n")
        lines.append(self.privacy_note)
        lines.append("")
        lines.append("---\n")
        lines.append("*Generated by LogSloth — local-first SSH log analysis.*\n")
        return "\n".join(lines)
