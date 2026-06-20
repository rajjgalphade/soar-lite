import os

# Copy this file to config.py and fill in your real API keys
# Get VirusTotal key at: https://www.virustotal.com/gui/my-apikey
# Get AbuseIPDB key at:  https://www.abuseipdb.com/account/api

VIRUSTOTAL_API_KEY  = os.getenv("VT_API_KEY",  "YOUR_VIRUSTOTAL_KEY_HERE")
ABUSEIPDB_API_KEY   = os.getenv("ABUSEIPDB_API_KEY", "YOUR_ABUSEIPDB_KEY_HERE")

VT_MALICIOUS_THRESHOLD     = 3
ABUSE_CONFIDENCE_THRESHOLD = 50
API_TIMEOUT                = 10