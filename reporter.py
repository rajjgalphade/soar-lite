import json
import csv
import io
from datetime import datetime


# Colours used in the HTML report for each tag
TAG_COLORS = {
    "MALICIOUS":  "#e74c3c",   # red
    "SUSPICIOUS": "#e67e22",   # orange
    "CLEAN":      "#27ae60",   # green
    "UNKNOWN":    "#95a5a6",   # grey
}


def to_json(events: list) -> str:
    """
    Converts the results list to a formatted JSON string.
    indent=2 makes it human-readable (not one long line).
    """
    return json.dumps(events, indent=2)


def to_csv(events: list) -> str:
    """
    Converts results to CSV format.
    One row per IOC (an event with 3 IPs = 3 rows).
    Opens cleanly in Excel.
    """
    buf = io.StringIO()   # write to memory, not a file directly
    writer = csv.writer(buf)

    # Header row
    writer.writerow([
        "line_no",
        "event_tag",
        "ioc",
        "ioc_tag",
        "reasons",
        "log_snippet"
    ])

    for ev in events:
        if not ev.get("tagged_iocs"):
            continue
        for ioc, info in ev["tagged_iocs"].items():
            writer.writerow([
                ev["line_no"],
                ev["event_tag"],
                ioc,
                info["tag"],
                " | ".join(info["reasons"]),
                ev["raw"][:120],   # first 120 chars of the log line
            ])

    return buf.getvalue()


def to_html(events: list, title: str = "SOAR-lite Report") -> str:
    """
    Generates a complete HTML report with colour-coded tags.
    Open the output file in any browser to see a professional report.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count totals for the summary section at the top
    counts = {"MALICIOUS": 0, "SUSPICIOUS": 0, "CLEAN": 0, "UNKNOWN": 0}
    for ev in events:
        tag = ev.get("event_tag", "UNKNOWN")
        if tag in counts:
            counts[tag] += 1

    # Build the summary cards HTML
    summary_html = ""
    for tag, count in counts.items():
        color = TAG_COLORS[tag]
        summary_html += f"""
        <div style="background:#1a1a2e;border:1px solid {color};
                    border-radius:8px;padding:1rem;text-align:center;min-width:120px">
            <div style="color:{color};font-size:28px;font-weight:bold">{count}</div>
            <div style="color:{color};font-size:13px;margin-top:4px">{tag}</div>
        </div>"""

    # Build the table rows HTML
    rows_html = ""
    for ev in events:
        if not ev.get("tagged_iocs"):
            continue
        ev_color = TAG_COLORS.get(ev.get("event_tag", "UNKNOWN"), "#999")

        for ioc, info in ev["tagged_iocs"].items():
            ioc_color = TAG_COLORS.get(info["tag"], "#999")
            reasons   = "<br>".join(info["reasons"])
            snippet   = ev["raw"][:100].replace("<", "&lt;").replace(">", "&gt;")

            rows_html += f"""
            <tr>
                <td style="color:#888">{ev['line_no']}</td>
                <td>
                    <span style="color:{ev_color};font-weight:bold">
                        {ev['event_tag']}
                    </span>
                </td>
                <td>
                    <code style="background:#0d0d1a;padding:2px 6px;
                                 border-radius:4px;color:#7eb8f7">
                        {ioc}
                    </code>
                </td>
                <td>
                    <span style="color:{ioc_color};font-weight:bold">
                        {info['tag']}
                    </span>
                </td>
                <td style="color:#aaa;font-size:12px">{reasons}</td>
                <td style="color:#666;font-size:11px;font-family:monospace">
                    {snippet}
                </td>
            </tr>"""

    # Full HTML document
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            background: #0d0d1a;
            color: #e0e0e0;
            margin: 0;
            padding: 2rem;
        }}
        h1 {{
            color: #7eb8f7;
            margin-bottom: 0.25rem;
        }}
        .subtitle {{
            color: #555;
            font-size: 13px;
            margin-bottom: 2rem;
        }}
        .summary {{
            display: flex;
            gap: 1rem;
            margin-bottom: 2rem;
            flex-wrap: wrap;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            background: #1a1a2e;
            color: #7eb8f7;
            padding: 10px 14px;
            text-align: left;
            border-bottom: 1px solid #2a2a4a;
        }}
        td {{
            padding: 10px 14px;
            border-bottom: 1px solid #1a1a2e;
            vertical-align: top;
        }}
        tr:hover td {{
            background: #12122a;
        }}
    </style>
</head>
<body>
    <h1>🛡 {title}</h1>
    <div class="subtitle">Generated: {timestamp}</div>

    <div class="summary">
        {summary_html}
    </div>

    <table>
        <thead>
            <tr>
                <th>Line</th>
                <th>Event tag</th>
                <th>IOC</th>
                <th>IOC tag</th>
                <th>Reasons</th>
                <th>Log snippet</th>
            </tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>"""