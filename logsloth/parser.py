"""
Deterministic parser for SSH / Linux authentication logs.

Extracts structured events from syslog-formatted auth.log lines.
All counting and fact extraction is deterministic — no LLM is used here.
"""

from __future__ import annotations

import re
from typing import Optional

from logsloth.schemas import EventType, ParsedEvent, ParseSummary


# ---------------------------------------------------------------------------
# Compiled patterns for common sshd / auth events
# ---------------------------------------------------------------------------

# Syslog header: "Oct 21 08:15:01 server sshd[12345]: …"
_SYSLOG_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_FAILED_PW = re.compile(
    r"Failed password for (?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

_ACCEPTED_PW = re.compile(
    r"Accepted password for (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

_ACCEPTED_KEY = re.compile(
    r"Accepted publickey for (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?:\s+port\s+(?P<port>\d+))?"
)

_CONN_CLOSED = re.compile(
    r"Connection closed by (?:authenticating user\s+(?P<user>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

_DISCONNECTED = re.compile(
    r"Disconnected from (?:authenticating user\s+(?P<user>\S+)\s+)?(?:invalid user\s+(?P<user2>\S+)\s+)?(?P<ip>\d+\.\d+\.\d+\.\d+)\s+port\s+(?P<port>\d+)"
)

_PAM_OPEN = re.compile(
    r"pam_unix\(\S+\):?\s+session opened for user (?P<user>\S+)"
)

_PAM_CLOSE = re.compile(
    r"pam_unix\(\S+\):?\s+session closed for user (?P<user>\S+)"
)

_TOO_MANY = re.compile(
    r"(?:Disconnecting|Disconnected from).*?too many authentication failures for (?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"
)

# Ordered list: try most specific patterns first
_PATTERNS: list[tuple[re.Pattern, EventType]] = [
    (_TOO_MANY,     EventType.TOO_MANY_FAILURES),
    (_FAILED_PW,    EventType.FAILED_PASSWORD),
    (_ACCEPTED_PW,  EventType.ACCEPTED_PASSWORD),
    (_ACCEPTED_KEY, EventType.ACCEPTED_PUBLICKEY),
    (_INVALID_USER, EventType.INVALID_USER),
    (_CONN_CLOSED,  EventType.CONNECTION_CLOSED),
    (_DISCONNECTED, EventType.DISCONNECTED),
    (_PAM_OPEN,     EventType.PAM_SESSION_OPEN),
    (_PAM_CLOSE,    EventType.PAM_SESSION_CLOSE),
]


def _extract_event(message: str) -> Optional[tuple[EventType, dict]]:
    """Return (EventType, captured groups) for the first matching pattern."""
    for regex, etype in _PATTERNS:
        m = regex.search(message)
        if m:
            groups = m.groupdict()
            # Merge user2 into user for disconnected pattern
            if "user2" in groups and groups.get("user2"):
                groups["user"] = groups.pop("user2")
            else:
                groups.pop("user2", None)
            return etype, groups
    return None


def _make_detail(etype: EventType, groups: dict) -> str:
    """Build a human-readable one-liner for this event."""
    user = groups.get("user", "?")
    ip = groups.get("ip", "?")
    port = groups.get("port", "?")

    templates = {
        EventType.FAILED_PASSWORD:    f"Failed password for '{user}' from {ip}:{port}",
        EventType.ACCEPTED_PASSWORD:  f"Accepted password for '{user}' from {ip}:{port}",
        EventType.ACCEPTED_PUBLICKEY: f"Accepted publickey for '{user}' from {ip}:{port}",
        EventType.INVALID_USER:       f"Invalid user '{user}' from {ip}",
        EventType.CONNECTION_CLOSED:  f"Connection closed by {ip}:{port}" + (f" (user '{user}')" if user != "?" else ""),
        EventType.DISCONNECTED:       f"Disconnected from {ip}:{port}" + (f" (user '{user}')" if user != "?" else ""),
        EventType.PAM_SESSION_OPEN:   f"PAM session opened for '{user}'",
        EventType.PAM_SESSION_CLOSE:  f"PAM session closed for '{user}'",
        EventType.TOO_MANY_FAILURES:  f"Too many auth failures for '{user}' from {ip}",
    }
    return templates.get(etype, str(groups))


def parse_logs(raw_text: str) -> ParseSummary:
    """
    Parse raw syslog-formatted authentication log text.

    Returns a ParseSummary with deterministic counts and structured events.
    Every event carries a stable event_id (E001, E002, …) that the AI
    analysis can reference as evidence.
    """
    summary = ParseSummary()
    event_counter = 0

    for line_no, line in enumerate(raw_text.splitlines(), start=1):
        summary.total_lines += 1
        stripped = line.strip()

        if not stripped:
            summary.blank_lines += 1
            continue

        header = _SYSLOG_RE.match(stripped)
        if not header:
            summary.unrecognized_lines += 1
            summary.unrecognized.append({"line_number": line_no, "raw_line": stripped})
            continue

        timestamp = header.group("timestamp")
        hostname = header.group("hostname")
        service = header.group("service")
        message = header.group("message")

        result = _extract_event(message)
        if result is None:
            # Valid syslog line but not a recognised auth event
            summary.unrecognized_lines += 1
            summary.unrecognized.append({"line_number": line_no, "raw_line": stripped})
            continue

        etype, groups = result
        event_counter += 1
        eid = f"E{event_counter:03d}"

        port_str = groups.get("port")
        port_int = int(port_str) if port_str and port_str.isdigit() else None

        event = ParsedEvent(
            event_id=eid,
            line_number=line_no,
            timestamp=timestamp,
            hostname=hostname,
            service=service,
            event_type=etype,
            username=groups.get("user"),
            source_ip=groups.get("ip"),
            port=port_int,
            raw_line=stripped,
            details=_make_detail(etype, groups),
        )
        summary.events.append(event)

    summary.parsed_events = len(summary.events)
    return summary
