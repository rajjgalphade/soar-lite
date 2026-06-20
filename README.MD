# SOAR-lite 🛡

A Python-based security automation tool that enriches Indicators of Compromise (IOCs)
found in log files using the VirusTotal and AbuseIPDB APIs — inspired by enterprise
SOAR platforms like Splunk SOAR and Palo Alto XSOAR.

## What it does

- Parses Apache, auth, and syslog files for IPs, file hashes, and URLs
- Enriches each IOC via VirusTotal (70+ AV engines) and AbuseIPDB
- Auto-tags events as MALICIOUS / SUSPICIOUS / CLEAN / UNKNOWN
- Outputs professional HTML reports, CSV files, or JSON

## Project structure
soar_lite/

├── main.py          # Entry point — CLI interface

├── config.py        # API keys and thresholds (not uploaded — see config.example.py for ref)

├── extractor.py     # Regex-based IOC extraction from log files

├── enricher.py      # VirusTotal and AbuseIPDB API calls

├── tagger.py        # Scoring logic — assigns risk labels

├── reporter.py      # HTML, CSV, and JSON report generation

├── requirements.txt # Python dependencies

└── sample_logs/     # Sample Apache and auth log files for testing

## Setup

1. Clone the repository
```bash
git clone https://github.com/YOURUSERNAME/soar-lite.git
cd soar-lite
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Add your API keys
```bash
# Copy the example config and fill in your real keys
copy config.example.py config.py
```

Get your free API keys:
- VirusTotal → https://www.virustotal.com/gui/my-apikey (500 lookups/day free)
- AbuseIPDB  → https://www.abuseipdb.com/account/api   (1000 checks/day free)

## Usage

```bash
# Scan a log file and print results
python main.py sample_logs/apache.log

# Save an HTML report
python main.py sample_logs/apache.log -o report.html -f html

# Save a CSV report
python main.py sample_logs/apache.log -o results.csv -f csv

# Quiet mode — only show summary table
python main.py sample_logs/apache.log -q
```

## Example output
SOAR-lite | scanning: sample_logs/apache.log
Lines parsed: 4
Lines with IOCs: 3
Lines skipped: 1
Enriching IOCs...
MALICIOUS line 1 → 185.220.101.47

MALICIOUS line 2 → 45.33.32.156


| TAG       	| COUNT 	|
|-----------	|-------	|
| Malicious 	| 2     	|
| Clean     	| 1     	|

## Tech stack

- Python 3.10+
- requests : HTTP API calls
- rich : terminal formatting
- VirusTotal API v3
- AbuseIPDB API v2

## Skills demonstrated

- REST API integration with authentication and error handling
- Regex-based text parsing for security IOC extraction
- Modular Python project structure
- Automated risk scoring and event triage logic
- CLI tool design with argparse
- Professional report generation (HTML, CSV, JSON)
