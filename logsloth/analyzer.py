"""
AI-powered analysis of parsed authentication log events.

Takes deterministic ParseSummary data, builds a structured prompt,
sends it to the local Ollama model, and validates the response.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
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
1. Base your analysis ONLY on the events and verified facts provided. Do not invent events.
2. Reference events by their event_id (e.g. E001, E042).
3. The parser HAS ALREADY EXTRACTED source IPs, usernames, and failure/success totals. \
   In your findings, explicitly name the specific source IPs and targeted usernames. \
   DO NOT claim that the logs or system fail to provide source IP or username information.
4. Distinguish OBSERVED FACTS from POSSIBLE EXPLANATIONS. Repeated \
   failed logins are not proof of a successful breach.
5. In 'limitations', state only genuine analytical boundaries (e.g., cannot confirm if source IPs \
   are spoofed, cannot inspect encrypted SSH session contents, cannot confirm user actions after \
   login without host-level shell audit logs).
6. Be concise — two or three sentences for the executive summary.
7. Provide actionable but SAFE recommendations. Never recommend \
   running commands, blocking IPs automatically, or modifying firewalls \
   without human review. Each recommendation must be a clean, actionable sentence.

OUTPUT FORMAT — reply ONLY with valid JSON matching this schema:
{
  "executive_summary": "string (2-3 sentences)",
  "review_priority": "Low | Medium | High",
  "findings": [
    {
      "title": "string",
      "description": "string citing specific IPs and usernames",
      "evidence_ids": ["E001", "E005"],
      "severity": "informational | low | medium | high"
    }
  ],
  "recommendations": ["Safe practical recommendation sentence 1", "Safe practical recommendation sentence 2"],
  "limitations": "string describing genuine investigative boundaries"
}

Do NOT wrap the JSON in markdown code fences. Return raw JSON only.\
"""


def _build_event_table(summary: ParseSummary) -> str:
    """Create a structured, evidence-grounded textual representation of events for the prompt."""
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
    lines.append("Event-type breakdown:")
    for etype, count in type_counts.most_common():
        lines.append(f"  {etype}: {count}")
    lines.append("")

    # Correlated Source IP analysis (failures vs successes and targeted users)
    ip_stats: dict[str, dict] = defaultdict(
        lambda: {"failures": 0, "successes": 0, "users": set(), "eids": []}
    )
    user_stats: dict[str, dict] = defaultdict(
        lambda: {"failures": 0, "successes": 0, "ips": set(), "eids": []}
    )

    for ev in summary.events:
        if ev.source_ip:
            entry = ip_stats[ev.source_ip]
            entry["eids"].append(ev.event_id)
            if ev.username:
                entry["users"].add(ev.username)
            if ev.event_type in (
                EventType.FAILED_PASSWORD,
                EventType.INVALID_USER,
                EventType.TOO_MANY_FAILURES,
            ):
                entry["failures"] += 1
            elif ev.event_type in (
                EventType.ACCEPTED_PASSWORD,
                EventType.ACCEPTED_PUBLICKEY,
            ):
                entry["successes"] += 1

        if ev.username:
            uentry = user_stats[ev.username]
            uentry["eids"].append(ev.event_id)
            if ev.source_ip:
                uentry["ips"].add(ev.source_ip)
            if ev.event_type in (
                EventType.FAILED_PASSWORD,
                EventType.INVALID_USER,
                EventType.TOO_MANY_FAILURES,
            ):
                uentry["failures"] += 1
            elif ev.event_type in (
                EventType.ACCEPTED_PASSWORD,
                EventType.ACCEPTED_PUBLICKEY,
            ):
                uentry["successes"] += 1

    # High-failure source IPs
    failing_ips = [(ip, s) for ip, s in ip_stats.items() if s["failures"] > 0]
    failing_ips.sort(key=lambda x: x[1]["failures"], reverse=True)
    if failing_ips:
        lines.append("Verified Source IPs with Failed Authentication Attempts:")
        for ip, s in failing_ips[:15]:
            target_users = ", ".join(sorted(s["users"])) or "unknown"
            sample_ids = ", ".join(s["eids"][:5])
            lines.append(
                f"  * IP {ip}: {s['failures']} failure(s) targeting [{target_users}] (evidence: {sample_ids})"
            )
        lines.append("")

    # Successful authentications
    success_events = [
        ev for ev in summary.events
        if ev.event_type in (EventType.ACCEPTED_PASSWORD, EventType.ACCEPTED_PUBLICKEY)
    ]
    if success_events:
        lines.append("Verified Successful Authentication Events:")
        for ev in success_events[:10]:
            lines.append(
                f"  * User '{ev.username}' from {ev.source_ip} via {ev.event_type.value} at {ev.timestamp} (evidence: {ev.event_id})"
            )
        lines.append("")

    # Most targeted usernames
    targeted = [(u, s) for u, s in user_stats.items() if s["failures"] > 0]
    targeted.sort(key=lambda x: x[1]["failures"], reverse=True)
    if targeted:
        lines.append("Most Targeted Usernames (by failure count):")
        for user, s in targeted[:15]:
            ips_str = ", ".join(sorted(s["ips"]))
            lines.append(
                f"  * User '{user}': {s['failures']} failure(s) from IPs: [{ips_str}]"
            )
        lines.append("")

    # Compact chronological event list (up to 80 events)
    event_list = summary.events[:80]
    lines.append(f"Chronological Events (showing {len(event_list)} of {summary.parsed_events}):")
    for ev in event_list:
        lines.append(
            f"  {ev.event_id} | L{ev.line_number} | {ev.timestamp} | "
            f"{ev.event_type.value} | user={ev.username or '?'} | ip={ev.source_ip or '?'}"
        )

    return "\n".join(lines)


def _build_prompt(summary: ParseSummary) -> str:
    """Assemble the full user prompt."""
    event_table = _build_event_table(summary)
    return (
        "Analyze the following pre-parsed SSH authentication log events and produce a structured security briefing.\n\n"
        f"{event_table}\n\n"
        "EVIDENCE-GROUNDING INSTRUCTIONS:\n"
        "1. All source IP addresses, targeted usernames, and timestamps above have ALREADY been extracted by the parser.\n"
        "2. Your findings MUST reference the specific source IPs (e.g. 203.0.113.10, 198.51.100.25) and targeted usernames (e.g. root, admin, alice, deploy) observed in the evidence above.\n"
        "3. Do NOT state that the logs lack source IP or username information when they are clearly present in the tables above.\n"
        "4. Distinguish observed facts from interpretations. Mention both attack patterns AND legitimate successful logins.\n"
        "5. In 'limitations', describe genuine investigative boundaries (e.g. cannot verify if source IPs are spoofed/proxied, cannot inspect encrypted payloads, cannot verify user activities performed after login without shell audit logs).\n"
        "6. In 'recommendations', provide a JSON array of concise, actionable, and safe guidance sentences.\n\n"
        "CRITICAL: You MUST respond with ONLY a valid JSON object matching this structure:\n"
        "{\n"
        '  "executive_summary": "2-3 sentences summarizing key security observations",\n'
        '  "review_priority": "Low" | "Medium" | "High",\n'
        '  "findings": [\n'
        "    {\n"
        '      "title": "Short title describing the observed pattern",\n'
        '      "description": "Why this pattern matters and what was observed, citing specific IPs and usernames",\n'
        '      "evidence_ids": ["E001", "E002"],\n'
        '      "severity": "informational" | "low" | "medium" | "high"\n'
        "    }\n"
        "  ],\n"
        '  "recommendations": ["Safe practical recommended step 1", "Safe practical recommended step 2"],\n'
        '  "limitations": "Explicit uncertainty and what cannot be confirmed"\n'
        "}\n\n"
        "Do not output markdown fences or explanatory text. Return the JSON object directly."
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


def _normalize_recommendations(raw_recs) -> list[str]:
    """Ensure recommendations are returned as a list of distinct clean sentence strings."""
    if isinstance(raw_recs, str):
        # Could be multi-line text or a single sentence
        lines = [
            re.sub(r"^[\s\-*•\d\.\)]+", "", line).strip()
            for line in raw_recs.splitlines()
            if line.strip()
        ]
        if len(lines) > 1:
            return [l for l in lines if l]
        stripped = re.sub(r"^[\s\-*•\d\.\)]+", "", raw_recs).strip()
        return [stripped] if stripped else []
    elif isinstance(raw_recs, list):
        cleaned = []
        for item in raw_recs:
            if isinstance(item, str):
                c = re.sub(r"^[\s\-*•\d\.\)]+", "", item).strip()
                if c:
                    cleaned.append(c)
            elif isinstance(item, dict):
                text = item.get("recommendation") or item.get("text") or item.get("action") or str(item)
                c = re.sub(r"^[\s\-*•\d\.\)]+", "", str(text)).strip()
                if c:
                    cleaned.append(c)
            elif item is not None:
                c = re.sub(r"^[\s\-*•\d\.\)]+", "", str(item)).strip()
                if c:
                    cleaned.append(c)
        return cleaned
    return []


def _validate_report(
    data: dict, valid_ids: set[str]
) -> tuple[AnalysisReport, list[str]]:
    """
    Build an AnalysisReport from parsed JSON, validating evidence IDs.
    Returns (report, warnings).
    """
    if not isinstance(data, dict):
        raise RuntimeError(f"Model output must be a JSON object, got {type(data).__name__}")

    exec_sum = data.get("executive_summary")
    findings = data.get("findings")
    if not exec_sum and not findings:
        raise RuntimeError(
            "Model response was malformed (missing 'executive_summary' and 'findings'). "
            "Please retry analysis."
        )

    warnings: list[str] = []

    report = AnalysisReport(
        executive_summary=str(data.get("executive_summary", "")).strip(),
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
        if isinstance(evidence, str):
            evidence = [evidence]
        bad_ids = [eid for eid in evidence if eid not in valid_ids]
        if bad_ids:
            warnings.append(
                f"Finding '{fd.get('title', '?')}' cites non-existent event(s): "
                f"{', '.join(bad_ids)} — removed."
            )
            evidence = [eid for eid in evidence if eid in valid_ids]

        report.findings.append(
            Finding(
                title=str(fd.get("title", "Untitled")).strip(),
                description=str(fd.get("description", "")).strip(),
                evidence_ids=evidence,
                severity=str(fd.get("severity", "informational")).lower(),
            )
        )

    report.recommendations = _normalize_recommendations(data.get("recommendations", []))

    raw_lim = data.get("limitations", "")
    if isinstance(raw_lim, list):
        raw_lim = " ".join(str(x) for x in raw_lim)
    lim_str = str(raw_lim).strip()

    # Guard against contradictory canned model disclaimers when IPs and usernames were supplied
    if valid_ids:
        lim_str = re.sub(
            r"(?i)the logs do not provide (?:any )?information on (?:the )?source ip(?:s)? (?:or|and) username(?:s)?(?: of the attacker)?(?:,\s*nor can|\.\s*)?",
            "While source IPs and usernames are recorded in these logs, they cannot confirm the true physical identity of the human operator, nor can ",
            lim_str,
        )
        lim_str = re.sub(
            r"(?i)the system does not provide detailed information on failed attempts and connection closures,?\s*making it difficult to pinpoint the specific cause",
            "While individual failed attempts are logged, external authentication logs alone cannot determine whether attackers possess valid credentials elsewhere",
            lim_str,
        )
    report.limitations = lim_str

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
