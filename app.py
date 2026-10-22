"""
LogSloth — Streamlit application entry point.

Stop reading authentication logs line by line.
Get a useful security briefing locally.
"""

from __future__ import annotations

import os
import pathlib
import time
from dataclasses import asdict

import streamlit as st

from logsloth import __version__, __app_name__, __tagline__
from logsloth.parser import parse_logs
from logsloth.schemas import ParseSummary, AnalysisReport, EventType
from logsloth.analyzer import analyze, build_full_report
from logsloth.ollama_client import OllamaClient


# ---------------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------------

st.set_page_config(
    page_title=f"{__app_name__} — Local SSH Log Analyzer",
    page_icon="🦥",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------------------------
# Custom CSS
# ---------------------------------------------------------------------------

st.markdown("""
<style>
    /* Brand colors */
    :root {
        --logsloth-green: #2e7d32;
        --logsloth-green-light: #4caf50;
        --logsloth-bg: #1e1e1e;
        --logsloth-card: rgba(255, 255, 255, 0.05);
    }

    /* Header */
    .logsloth-header {
        text-align: center;
        padding: 1rem 0 0.5rem 0;
    }
    .logsloth-header h1 {
        font-size: 2.4rem;
        margin-bottom: 0.2rem;
    }
    .logsloth-tagline {
        color: #a0aec0;
        font-size: 1.05rem;
        margin-bottom: 0.5rem;
    }

    /* Status badges */
    .status-badge {
        display: inline-block;
        padding: 0.3rem 0.85rem;
        border-radius: 1rem;
        font-size: 0.85rem;
        font-weight: 600;
    }
    .badge-connected {
        background: rgba(46, 125, 50, 0.25);
        color: #81c784 !important;
        border: 1px solid rgba(76, 175, 80, 0.5);
    }
    .badge-disconnected {
        background: rgba(198, 40, 40, 0.25);
        color: #ef9a9a !important;
        border: 1px solid rgba(229, 115, 115, 0.5);
    }

    /* Priority badges */
    .priority-low {
        background: rgba(46, 125, 50, 0.25);
        color: #81c784 !important;
        border: 1px solid rgba(76, 175, 80, 0.5);
        padding: 0.35rem 1rem;
        border-radius: 0.5rem;
        font-weight: 700;
        display: inline-block;
    }
    .priority-medium {
        background: rgba(230, 81, 0, 0.25);
        color: #ffb74d !important;
        border: 1px solid rgba(255, 167, 38, 0.5);
        padding: 0.35rem 1rem;
        border-radius: 0.5rem;
        font-weight: 700;
        display: inline-block;
    }
    .priority-high {
        background: rgba(198, 40, 40, 0.25);
        color: #ef9a9a !important;
        border: 1px solid rgba(229, 115, 115, 0.5);
        padding: 0.35rem 1rem;
        border-radius: 0.5rem;
        font-weight: 700;
        display: inline-block;
    }

    /* Privacy & Info notice box - accessible in dark and light themes */
    .privacy-notice {
        background: rgba(46, 125, 50, 0.18);
        border: 1px solid rgba(76, 175, 80, 0.4);
        border-left: 4px solid #4caf50;
        color: #e2f1e4 !important;
        padding: 0.85rem 1.15rem;
        border-radius: 0 0.5rem 0.5rem 0;
        font-size: 0.92rem;
        line-height: 1.6;
        margin-top: 0.5rem;
    }
    .privacy-notice strong {
        color: #81c784 !important;
    }
    .privacy-notice em {
        color: #c8e6c9 !important;
    }

    /* Recommendations list readability */
    .recommendations-box ul {
        padding-left: 1.5rem;
        margin-top: 0.5rem;
    }
    .recommendations-box li {
        margin-bottom: 0.55rem;
        line-height: 1.65;
        white-space: normal;
        word-break: normal;
        overflow-wrap: break-word;
    }

    /* Footer */
    .logsloth-footer {
        text-align: center;
        color: #888;
        font-size: 0.82rem;
        padding: 2rem 0 1rem 0;
        border-top: 1px solid rgba(255, 255, 255, 0.1);
        margin-top: 2rem;
        line-height: 1.6;
    }

    /* Light theme overrides */
    @media (prefers-color-scheme: light) {
        .logsloth-tagline { color: #555; }
        .privacy-notice {
            background: #e8f5e9;
            border: 1px solid #c8e6c9;
            border-left: 4px solid #2e7d32;
            color: #1b5e20 !important;
        }
        .privacy-notice strong { color: #0b3d11 !important; }
        .privacy-notice em { color: #1b5e20 !important; }
        .badge-connected { background: #e8f5e9; color: #2e7d32 !important; border-color: #a5d6a7; }
        .badge-disconnected { background: #ffebee; color: #c62828 !important; border-color: #ffcdd2; }
        .priority-low { background: #e8f5e9; color: #2e7d32 !important; border-color: #a5d6a7; }
        .priority-medium { background: #fff3e0; color: #e65100 !important; border-color: #ffe0b2; }
        .priority-high { background: #ffebee; color: #c62828 !important; border-color: #ffcdd2; }
        .logsloth-footer { border-top: 1px solid #e0e0e0; color: #666; }
    }
</style>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Session state defaults
# ---------------------------------------------------------------------------

if "parse_summary" not in st.session_state:
    st.session_state.parse_summary = None
if "analysis_report" not in st.session_state:
    st.session_state.analysis_report = None
if "raw_logs" not in st.session_state:
    st.session_state.raw_logs = None
if "analysis_error" not in st.session_state:
    st.session_state.analysis_error = None


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

SAMPLE_LOG_PATH = pathlib.Path(__file__).parent / "sample_data" / "synthetic_auth.log"


def load_sample() -> str:
    """Load the bundled synthetic sample log."""
    return SAMPLE_LOG_PATH.read_text(encoding="utf-8")


def get_ollama_client() -> OllamaClient:
    base_url = st.session_state.get("ollama_url", "http://localhost:11434")
    model = st.session_state.get("ollama_model", "qwen2.5:1.5b")
    return OllamaClient(base_url=base_url, model=model)


def render_priority_badge(priority: str) -> str:
    cls = {
        "Low": "priority-low",
        "Medium": "priority-medium",
        "High": "priority-high",
    }.get(priority, "priority-medium")
    return f'<span class="{cls}">⚡ {priority} Priority</span>'


def severity_emoji(sev: str) -> str:
    return {"high": "🔴", "medium": "🟠", "low": "🟡"}.get(sev, "🔵")


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------

with st.sidebar:
    st.markdown("## ⚙️ Configuration")

    ollama_url = st.text_input(
        "Ollama URL",
        value=st.session_state.get("ollama_url", "http://localhost:11434"),
        help="Local Ollama API endpoint. Default: http://localhost:11434",
    )
    st.session_state.ollama_url = ollama_url

    # Check server status to detect available models
    temp_client = OllamaClient(base_url=ollama_url)
    init_status = temp_client.check_status()
    available = init_status.available_models or []

    if available:
        # Prefer qwen2.5:1.5b if present, then qwen2.5:7b, then any qwen2.5, else first
        default_idx = 0
        if "qwen2.5:1.5b" in available:
            default_idx = available.index("qwen2.5:1.5b")
        elif "qwen2.5:7b" in available:
            default_idx = available.index("qwen2.5:7b")
        else:
            qwen_matches = [i for i, m in enumerate(available) if m.startswith("qwen2.5")]
            if qwen_matches:
                default_idx = qwen_matches[0]

        selected_option = st.selectbox(
            "Model",
            options=available + ["Custom model..."],
            index=default_idx,
            help="Select an installed local model or enter a custom identifier.",
        )
        if selected_option == "Custom model...":
            model_name = st.text_input("Custom Model Identifier", value="qwen2.5:1.5b")
        else:
            model_name = selected_option
    else:
        model_name = st.text_input(
            "Model",
            value=st.session_state.get("ollama_model", "qwen2.5:1.5b"),
            help="Open-weight model identifier. Default: qwen2.5:1.5b",
        )

    st.session_state.ollama_model = model_name

    # Connection check with the chosen model
    st.markdown("### 🔌 Model Status")
    client = get_ollama_client()
    status = client.check_status()

    if status.server_reachable and status.model_available:
        st.markdown(
            '<span class="status-badge badge-connected">● Connected</span>',
            unsafe_allow_html=True,
        )
        st.caption(f"Server: {status.server_version}")
        st.caption(f"Model: {client.model}")
    elif status.server_reachable and not status.model_available:
        st.markdown(
            '<span class="status-badge badge-disconnected">● Model Missing</span>',
            unsafe_allow_html=True,
        )
        st.warning(status.error)
        st.code(f"ollama pull {client.model}", language="bash")
    else:
        st.markdown(
            '<span class="status-badge badge-disconnected">● Disconnected</span>',
            unsafe_allow_html=True,
        )
        st.error("Cannot reach Ollama.")
        with st.expander("🛠️ Setup Instructions"):
            st.markdown("""
1. **Install Ollama** — [ollama.com/download](https://ollama.com/download)
2. **Start the server:**
   ```bash
   ollama serve
   ```
3. **Pull the model:**
   ```bash
   ollama pull qwen2.5:1.5b
   ```
4. Refresh this page.
""")

    st.markdown("---")
    st.markdown("### 🔒 Privacy")
    st.markdown("""
<div class="privacy-notice">
<strong>Local-only processing.</strong> Your logs stay on this machine.
Nothing is sent to external servers. The AI model runs locally via Ollama.<br><br>
<em>You are still responsible for securing your device and any exported reports.</em>
</div>
""", unsafe_allow_html=True)

    st.markdown("---")
    st.caption(f"LogSloth v{__version__}")
    st.caption("Open-source · MIT License")
    st.caption(f"Active Model: {client.model}")
    st.caption("Model License: Apache 2.0 (Alibaba Cloud)")


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

st.markdown("""
<div class="logsloth-header">
    <h1>🦥 LogSloth</h1>
    <p class="logsloth-tagline">Stop reading authentication logs line by line.<br>Get a useful security briefing locally.</p>
</div>
""", unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Input section
# ---------------------------------------------------------------------------

st.markdown("## 📥 Load Authentication Logs")

tab_paste, tab_upload, tab_sample = st.tabs([
    "📋 Paste Logs", "📁 Upload File", "🧪 Sample Dataset"
])

with tab_paste:
    pasted = st.text_area(
        "Paste syslog-formatted auth.log lines",
        height=200,
        placeholder="Oct 21 06:12:01 server sshd[10234]: Failed password for ...",
    )
    if st.button("Parse pasted logs", key="btn_paste", type="primary"):
        if pasted.strip():
            st.session_state.raw_logs = pasted
            st.session_state.parse_summary = parse_logs(pasted)
            st.session_state.analysis_report = None
            st.session_state.analysis_error = None
        else:
            st.warning("Please paste some log lines first.")

with tab_upload:
    uploaded = st.file_uploader(
        "Upload a .log or .txt file",
        type=["log", "txt"],
        help="Standard syslog-formatted authentication log.",
    )
    if uploaded is not None:
        content = uploaded.read().decode("utf-8", errors="replace")
        if st.button("Parse uploaded file", key="btn_upload", type="primary"):
            st.session_state.raw_logs = content
            st.session_state.parse_summary = parse_logs(content)
            st.session_state.analysis_report = None
            st.session_state.analysis_error = None

with tab_sample:
    st.info(
        "⚠️ **Synthetic data only.** This sample was created for demonstration. "
        "It uses documentation-only IP ranges (RFC 5737) and fictional hostnames. "
        "It does not represent any real server."
    )
    if st.button("Load synthetic sample", key="btn_sample", type="primary"):
        sample_text = load_sample()
        st.session_state.raw_logs = sample_text
        st.session_state.parse_summary = parse_logs(sample_text)
        st.session_state.analysis_report = None
        st.session_state.analysis_error = None


# ---------------------------------------------------------------------------
# Parse results
# ---------------------------------------------------------------------------

summary: ParseSummary | None = st.session_state.parse_summary

if summary is not None:
    st.markdown("---")
    st.markdown("## 📊 Parse Results")

    # Metric cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Lines", summary.total_lines)
    with col2:
        st.metric("Events Parsed", summary.parsed_events)
    with col3:
        st.metric("Unrecognized", summary.unrecognized_lines)
    with col4:
        st.metric("Blank Lines", summary.blank_lines)

    # Event breakdown
    from collections import Counter

    type_counts = Counter(ev.event_type.value for ev in summary.events)
    ip_counts = Counter(ev.source_ip for ev in summary.events if ev.source_ip)
    user_counts = Counter(ev.username for ev in summary.events if ev.username)

    col_types, col_ips, col_users = st.columns(3)

    with col_types:
        st.markdown("#### Event Types")
        for etype, cnt in type_counts.most_common():
            st.text(f"{etype}: {cnt}")

    with col_ips:
        st.markdown("#### Top Source IPs")
        for ip, cnt in ip_counts.most_common(10):
            st.text(f"{ip}: {cnt}")

    with col_users:
        st.markdown("#### Top Usernames")
        for user, cnt in user_counts.most_common(10):
            st.text(f"{user}: {cnt}")

    # Event table
    with st.expander("📋 View All Parsed Events", expanded=False):
        event_data = []
        for ev in summary.events:
            event_data.append({
                "ID": ev.event_id,
                "Line": ev.line_number,
                "Time": ev.timestamp,
                "Type": ev.event_type.value,
                "User": ev.username or "",
                "Source IP": ev.source_ip or "",
                "Details": ev.details,
            })
        st.dataframe(event_data, use_container_width=True)

    if summary.unrecognized:
        with st.expander(f"⚠️ Unrecognized Lines ({len(summary.unrecognized)})"):
            for entry in summary.unrecognized[:50]:
                st.text(f"Line {entry['line_number']}: {entry['raw_line'][:120]}")

    # ---------------------------------------------------------------------------
    # AI Analysis
    # ---------------------------------------------------------------------------

    st.markdown("---")
    st.markdown("## 🤖 AI Security Briefing")

    if not status.server_reachable or not status.model_available:
        st.warning(
            "⚠️ Ollama is not connected or the model is not available. "
            "Configure the connection in the sidebar to enable AI analysis."
        )
    else:
        if st.button("🦥 Analyze with Local AI", type="primary", key="btn_analyze"):
            st.session_state.analysis_error = None
            with st.spinner("🦥 LogSloth is analyzing your logs locally… slow and steady…"):
                try:
                    report = analyze(summary, client)
                    st.session_state.analysis_report = report
                except RuntimeError as exc:
                    st.session_state.analysis_error = str(exc)
                    st.session_state.analysis_report = None
                except Exception as exc:
                    st.session_state.analysis_error = f"Unexpected error: {exc}"
                    st.session_state.analysis_report = None

    # Show analysis error
    if st.session_state.analysis_error:
        st.error(f"Analysis failed: {st.session_state.analysis_error}")
        st.info("You can adjust model settings in the sidebar and try again.")

    # Show analysis results
    report: AnalysisReport | None = st.session_state.analysis_report

    if report is not None:
        # Executive summary
        st.markdown("### Executive Summary")
        st.markdown(report.executive_summary if report.executive_summary else "_No summary generated._")

        # Priority badge
        st.markdown(render_priority_badge(report.review_priority), unsafe_allow_html=True)

        # Generation metadata
        st.caption(
            f"Model: {report.model_used} · "
            f"Generation time: {report.generation_time_seconds}s"
        )

        # Validation warnings
        if report.validation_warnings:
            with st.expander("⚠️ Validation Warnings"):
                for w in report.validation_warnings:
                    st.warning(w)

        # Findings
        if report.findings:
            st.markdown("### 🔍 Findings")
            for f in report.findings:
                with st.container():
                    st.markdown(
                        f"**{severity_emoji(f.severity)} {f.title}** "
                        f"({f.severity})"
                    )
                    st.markdown(f.description)
                    if f.evidence_ids:
                        st.caption(f"Evidence: {', '.join(f.evidence_ids)}")
                    st.markdown("---")

        # Recommendations
        if report.recommendations:
            st.markdown("### ✅ Recommendations")
            recs = [report.recommendations] if isinstance(report.recommendations, str) else list(report.recommendations)
            cleaned_recs = [
                re.sub(r"^[\s\-*•\d\.\)]+", "", str(r)).strip()
                for r in recs
                if str(r).strip()
            ]
            if cleaned_recs:
                recs_md = "\n".join(f"- {r}" for r in cleaned_recs)
                st.markdown(f'<div class="recommendations-box">\n\n{recs_md}\n\n</div>', unsafe_allow_html=True)

        # Limitations
        if report.limitations:
            st.markdown("### ⚠️ Limitations & Uncertainty")
            st.info(report.limitations)

        # ---------------------------------------------------------------
        # Export
        # ---------------------------------------------------------------

        st.markdown("---")
        st.markdown("## 📤 Export Report")

        full_report = build_full_report(summary, report, __version__)

        col_md, col_json = st.columns(2)
        with col_md:
            md_text = full_report.to_markdown()
            st.download_button(
                label="📄 Download Markdown",
                data=md_text,
                file_name="logsloth_report.md",
                mime="text/markdown",
            )
        with col_json:
            json_text = full_report.to_json()
            st.download_button(
                label="📋 Download JSON",
                data=json_text,
                file_name="logsloth_report.json",
                mime="application/json",
            )

        # Raw model output
        with st.expander("🔧 Raw Model Output"):
            st.code(report.raw_model_output, language="json")


# ---------------------------------------------------------------------------
# Analysis limitations & footer
# ---------------------------------------------------------------------------

st.markdown("---")

st.markdown("""
<div class="privacy-notice">
<strong>🛡️ Important Limitations</strong><br>
• LogSloth provides <em>informational analysis only</em>, not definitive security assessments.<br>
• The AI model may misinterpret patterns or miss important events.<br>
• Repeated failed logins are not automatically proof of a successful breach.<br>
• LogSloth never executes commands, blocks IPs, or modifies your system.<br>
• Always verify findings with your own expertise and additional tools.<br>
• This tool is not a substitute for professional security monitoring.
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div class="logsloth-footer">
    🦥 LogSloth v""" + __version__ + """ · Built for Hacktoberfest 2026 · MIT License<br>
    Active Model: """ + client.model + """ (Apache 2.0) · Powered by Ollama<br>
    <em>"Slow and steady wins the race — especially when reading auth logs."</em>
</div>
""", unsafe_allow_html=True)
