"""
AI-powered analysis of parsed authentication log events.

Takes deterministic ParseSummary data, builds a structured prompt,
sends it to the local Ollama model, and validates the response.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import asdict
from typing import Optional

from logsloth.schemas import (
    AnalysisReport,
    EventType,
    Finding,
    FullReport,
    ParsedEvent,
    ParseSummary,
)
from logsloth.ollama_client import OllamaClient


# ---------------------------------------------------------------------------
# Prompt construction
# ---------------------------------------------------------------------------

_SYSTEM_PROMPT = """\
You are LogSloth, a local security-log analyst. Your job is to review \
pre-parsed SSH authentication events and produce an evidence-grounded \
security briefing.

RULES:
1. Base your analysis ONLY on the events provided. Do not invent events.
2. Reference events by their event_id (e.g. E001, E042).
3. Distinguish OBSERVED FACTS from POSSIBLE EXPLANATIONS. Repeated \
   failed logins are not proof of a successful breach.
4. Be concise — two or three sentences for the executive summary.
5. Provide actionable but SAFE recommendations. Never recommend \
   running commands, blocking IPs automatically, or modifying firewalls \
   without human review.
6. Acknowledge limitations and uncertainty.

OUTPUT FORMAT — reply ONLY with valid JSON matching this schema:
{
  "executive_summary": "string (2-3 sentences)",
  "review_priority": "Low | Medium | High",
  "findings": [
    {
      "title": "string",
      "description": "string",
      "evidence_ids": ["E001", "E005"],
      "severity": "informational | low | medium | high"
    }
  ],
  "recommendations": ["string"],
  "limitations": "string"
}

Do NOT wrap the JSON in markdown code fences. Return raw JSON only.\
"""


def _build_event_table(summary: ParseSummary) -> str:
    """Create a compact textual representation of events for the prompt."""
    lines = []
    lines.append(f"Total lines examined: {summary.total_lines}")
    lines.append(f"Events parsed: {summary.parsed_events}")
    lines.append(f"Unrecognized lines: {summary.unrecognized_lines}")
    lines.append(f"Blank lines: {summary.blank_lines}")
    lines.append("")

    # Event-type counts
    type_counts: Counter = Counter()
    for ev in summary.events:
        type_counts[ev.event_type.value] += 1
    lines.append("Event-type counts:")
    for etype, count in type_counts.most_common():
        lines.append(f"  {etype}: {count}")
    lines.append("")

    # IP summary
    ip_counts: Counter = Counter()
    for ev in summary.events:
        if ev.source_ip:
            ip_counts[ev.source_ip] += 1
    if ip_counts:
        lines.append("Source-IP frequency (top 20):")
        for ip, count in ip_counts.most_common(20):
            lines.append(f"  {ip}: {count} events")
        lines.append("")

    # Username summary
    user_counts: Counter = Counter()
    for ev in summary.events:
        if ev.username:
            user_counts[ev.username] += 1
    if user_counts:
        lines.append("Username frequency (top 20):")
        for user, count in user_counts.most_common(20):
            lines.append(f"  {user}: {count} events")
        lines.append("")

    # Full event list (limit to 200 for prompt size)
    event_list = summary.events[:200]
    lines.append(f"Events (showing {len(event_list)} of {summary.parsed_events}):")
    for ev in event_list:
        lines.append(
            f"  {ev.event_id} | line {ev.line_number} | {ev.timestamp} | "
            f"{ev.event_type.value} | user={ev.username} | ip={ev.source_ip} | "
            f"{ev.details}"
        )

    return "\n".join(lines)


def _build_prompt(summary: ParseSummary) -> str:
    """Assemble the full user prompt."""
    event_table = _build_event_table(summary)
    return (
        "Analyze the following pre-parsed SSH authentication log events and "
        "produce a structured security briefing.\n\n"
        f"{event_table}\n\n"
        "Respond with ONLY the JSON object described in your instructions."
    )


# ---------------------------------------------------------------------------
# Response parsing & validation
# ---------------------------------------------------------------------------

def _extract_json(raw: str) -> str:
    """Try to extract a JSON object from possibly-wrapped model output."""
    # Strip markdown code fences if present
    cleaned = re.sub(r"^```(?:json)?\s*", "", raw.strip())
    cleaned = re.sub(r"\s*```$", "", cleaned)

    # Find the outermost { … }
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start != -1 and end != -1 and end > start:
        return cleaned[start : end + 1]
    return cleaned


def _validate_report(
    data: dict, valid_ids: set[str]
) -> tuple[AnalysisReport, list[str]]:
    """
    Build an AnalysisReport from parsed JSON, validating evidence IDs.
    Returns (report, warnings).
    """
    warnings: list[str] = []

    report = AnalysisReport(
        executive_summary=data.get("executive_summary", ""),
        review_priority=data.get("review_priority", "Medium"),
    )

    # Validate review_priority
    if report.review_priority not in ("Low", "Medium", "High"):
        warnings.append(
            f"Invalid review_priority '{report.review_priority}'; defaulting to Medium."
        )
        report.review_priority = "Medium"

    # Parse findings
    for fd in data.get("findings", []):
        evidence = fd.get("evidence_ids", [])
        bad_ids = [eid for eid in evidence if eid not in valid_ids]
        if bad_ids:
            warnings.append(
                f"Finding '{fd.get('title', '?')}' cites non-existent event(s): "
                f"{', '.join(bad_ids)} — removed."
            )
            evidence = [eid for eid in evidence if eid in valid_ids]

        report.findings.append(
            Finding(
                title=fd.get("title", "Untitled"),
                description=fd.get("description", ""),
                evidence_ids=evidence,
                severity=fd.get("severity", "informational"),
            )
        )

    report.recommendations = data.get("recommendations", [])
    report.limitations = data.get("limitations", "")

    return report, warnings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze(
    summary: ParseSummary,
    client: Optional[OllamaClient] = None,
) -> AnalysisReport:
    """
    Send parsed events to the local model for analysis.

    Returns a validated AnalysisReport. Raises RuntimeError if the
    model is unreachable or returns completely unparsable output.
    """
    if client is None:
        client = OllamaClient()

    prompt = _build_prompt(summary)
    raw_output, elapsed = client.generate(prompt, system=_SYSTEM_PROMPT)

    # Try to parse JSON
    json_str = _extract_json(raw_output)
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Model output is not valid JSON. Parse error: {exc}\n\n"
            f"Raw output (first 1000 chars):\n{raw_output[:1000]}"
        )

    valid_ids = {ev.event_id for ev in summary.events}
    report, warnings = _validate_report(data, valid_ids)
    report.model_used = client.model
    report.raw_model_output = raw_output
    report.validation_warnings = warnings
    report.generation_time_seconds = round(elapsed, 2)

    return report


def build_full_report(
    summary: ParseSummary,
    analysis: AnalysisReport,
    app_version: str = "",
) -> FullReport:
    """Combine parse summary and analysis into an exportable FullReport."""
    return FullReport(
        app_version=app_version,
        parse_summary_stats={
            "total_lines": summary.total_lines,
            "parsed_events": summary.parsed_events,
            "unrecognized_lines": summary.unrecognized_lines,
            "blank_lines": summary.blank_lines,
        },
        events=[asdict(ev) for ev in summary.events],
        analysis=analysis.to_dict() if analysis else {},
    )
