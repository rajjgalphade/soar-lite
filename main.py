import argparse
from rich.console import Console
from rich.table   import Table
from extractor    import parse_log_lines
from enricher     import enrich_event
from tagger       import tag_event
from reporter     import to_html, to_csv, to_json

console = Console()

# Colours for the rich terminal output
STYLES = {
    "MALICIOUS":  "bold red",
    "SUSPICIOUS": "bold yellow",
    "CLEAN":      "green",
    "UNKNOWN":    "dim",
}


def run(log_file, output, fmt, quiet):
    """
    The main pipeline — runs all 4 steps in order:
    1. Parse  — read log file, extract IOCs
    2. Enrich — call APIs for each IOC
    3. Tag    — score each IOC and event
    4. Report — write output file
    """

    console.print(f"\n[bold cyan]SOAR-lite[/] | scanning: [white]{log_file}[/]\n")

    # ----------------------------------------------------------
    # STEP 1 — PARSE
    # ----------------------------------------------------------
    all_events  = parse_log_lines(log_file)
    ioc_events  = [e for e in all_events if e["has_iocs"]]

    console.print(f"[white]Lines parsed:[/]     {len(all_events)}")
    console.print(f"[white]Lines with IOCs:[/]  {len(ioc_events)}")
    console.print(f"[white]Lines skipped:[/]    {len(all_events) - len(ioc_events)}\n")

    if not ioc_events:
        console.print("[yellow]No IOCs found in this log file. Try a different file.[/]")
        return

    # ----------------------------------------------------------
    # STEP 2 — ENRICH + STEP 3 — TAG
    # ----------------------------------------------------------
    console.print("[bold white]Enriching IOCs...[/]\n")

    results = []
    for ev in ioc_events:
        enriched = enrich_event(ev)    # calls VirusTotal + AbuseIPDB
        tagged   = tag_event(enriched) # scores and labels
        results.append(tagged)

        # Print MALICIOUS and SUSPICIOUS events live as they are found
        if not quiet and tagged["event_tag"] in ("MALICIOUS", "SUSPICIOUS"):
            style = STYLES[tagged["event_tag"]]
            iocs  = ", ".join(tagged["tagged_iocs"].keys())
            console.print(
                f"  [{style}]{tagged['event_tag']}[/] "
                f"[dim]line {tagged['line_no']}[/] → {iocs}"
            )

    # ----------------------------------------------------------
    # STEP 4 — SUMMARY TABLE
    # ----------------------------------------------------------
    console.print("\n")
    table = Table(title="Scan Summary", show_lines=True, style="cyan")
    table.add_column("Tag",   style="bold", min_width=12)
    table.add_column("Count", justify="right", min_width=6)

    for tag in ("MALICIOUS", "SUSPICIOUS", "CLEAN", "UNKNOWN"):
        count = sum(1 for r in results if r["event_tag"] == tag)
        if count > 0:
            table.add_row(tag, str(count), style=STYLES[tag])

    console.print(table)

    # ----------------------------------------------------------
    # STEP 5 — WRITE REPORT FILE
    # ----------------------------------------------------------
    if output:
        if fmt == "html":
            content = to_html(results)
        elif fmt == "csv":
            content = to_csv(results)
        else:
            content = to_json(results)

        with open(output, "w", encoding="utf-8") as f:
            f.write(content)

        console.print(f"\n[green]Report saved:[/] {output}\n")
    else:
        # No output file specified — print JSON to terminal
        console.print("\n[dim]No output file specified. Printing JSON...[/]\n")
        console.print(to_json(results))


def main():
    parser = argparse.ArgumentParser(
        description="SOAR-lite — automated IOC enrichment tool",
        epilog="Example: python main.py sample_logs/apache.log -o report.html -f html"
    )

    parser.add_argument(
        "logfile",
        help="Path to the log file to scan"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (e.g. report.html or results.csv)",
        default=None
    )
    parser.add_argument(
        "-f", "--format",
        help="Output format: json, csv, or html (default: json)",
        choices=["json", "csv", "html"],
        default="json"
    )
    parser.add_argument(
        "-q", "--quiet",
        help="Only show the summary table, no live event printing",
        action="store_true"
    )

    args = parser.parse_args()
    run(args.logfile, args.output, args.format, args.quiet)


if __name__ == "__main__":
    main()