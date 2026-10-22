# LogSloth Demo Script

**Duration:** 60–90 seconds

## Prerequisites

- Ollama running locally with `qwen2.5:7b` pulled
- LogSloth installed and launched (`streamlit run app.py`)

## Script

### 1. Open the Application (5s)

Open your browser to `http://localhost:8501`.

Show the LogSloth header: "Stop reading authentication logs line by line.
Get a useful security briefing locally."

Point out the sidebar showing the model connection status (green "Connected" badge).

### 2. Load Synthetic Sample (10s)

Click the **"🧪 Sample Dataset"** tab.

Note the info banner: "Synthetic data only" — uses RFC 5737 documentation IPs.

Click **"Load synthetic sample"**.

### 3. Review Parse Results (15s)

Show the parse summary metrics:
- Total lines examined
- Events parsed
- Unrecognized lines

Point out the event-type breakdown (failed passwords, accepted logins, etc.)
and the top source IPs.

Expand the event table to show individual events with IDs, line numbers,
and details.

### 4. Run AI Analysis (20s)

Click **"🦥 Analyze with Local AI"**.

Show the spinner: "LogSloth is analyzing your logs locally… slow and steady…"

When complete, walk through:
- **Executive summary** — a concise 2–3 sentence overview
- **Review priority** badge (Low / Medium / High)
- **Findings** — each with a title, description, evidence IDs, and severity
- **Recommendations** — safe, practical next steps
- **Limitations** — what the model acknowledges it cannot confirm

### 5. Export the Report (10s)

Scroll to the export section.

Click **"📄 Download Markdown"** — show the downloaded file.

Click **"📋 Download JSON"** — show the structured output.

### 6. Explain Privacy (10s)

Point to the sidebar privacy notice:
> "Local-only processing. Your logs stay on this machine."

Emphasize: no accounts, no API keys, no cloud calls. The Qwen2.5 model
runs entirely through Ollama on localhost.

### 7. Wrap Up (10s)

Return to the header. Summarize:

> "LogSloth saves you from reading hundreds of repetitive auth log lines.
> Paste your logs, get an AI-generated security briefing in seconds,
> and everything stays on your machine. Slow and steady — because your
> logs deserve a thoughtful read, not a panicked scroll."

## Recording Instructions (Windows)

1. **Open Xbox Game Bar:** Press `Win + G`
2. **Start recording:** Click the Record button (or `Win + Alt + R`)
3. **Run through the demo script above**
4. **Stop recording:** `Win + Alt + R` again
5. **Find recording:** `C:\Users\<you>\Videos\Captures\`
6. **Upload:** Upload to YouTube (unlisted), Loom, or any public host
7. **Add the link** to your DEV submission

Alternative: Use **OBS Studio** (free, open-source) for more control.
