import re

# ---------------------------------------------------------------
# PATTERNS — each one describes what an IOC looks like in text
# ---------------------------------------------------------------

# IP address pattern
# \d{1,3}  = 1 to 3 digits
# \.       = a literal dot (backslash stops it meaning "any character")
# {3}      = repeat the previous group 3 times
# \b       = word boundary (so 999.999.999.9999 doesn't match)
_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# MD5 hash = exactly 32 characters, only hex digits (0-9 and a-f)
_MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')

# SHA-256 hash = exactly 64 hex characters
_SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')

# URL = starts with http:// or https://, followed by anything
# that isn't a space, quote, or angle bracket
_URL_RE = re.compile(r'https?://[^\s\'"<>]+')

# Private/internal IP ranges — these belong to YOUR network
# so there's no point checking them on VirusTotal
# 10.x.x.x        = private network
# 192.168.x.x     = home/office router range
# 172.16-31.x.x   = another private range
# 127.x.x.x       = loopback (your own machine)
_PRIVATE_IP = re.compile(
    r'^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[01])\.)'
)

# ---------------------------------------------------------------
# FUNCTION 1 — extract IOCs from any string of text
# ---------------------------------------------------------------

def extract_iocs(text: str) -> dict:
    """
    Takes one line of text.
    Returns a dictionary of lists — one list per IOC type.
    Uses sets {} first to automatically remove duplicates,
    then converts to list for easy use later.
    """

    # findall() returns every match as a list
    # We use a set comprehension to remove duplicates automatically
    ips = {
        ip for ip in _IP_RE.findall(text)
        if not _PRIVATE_IP.match(ip)   # skip private IPs
    }

    # | means "union" — combines both sets into one
    hashes = set(_MD5_RE.findall(text)) | set(_SHA256_RE.findall(text))

    urls = set(_URL_RE.findall(text))

    return {
        "ips":    list(ips),
        "hashes": list(hashes),
        "urls":   list(urls),
    }

# ---------------------------------------------------------------
# FUNCTION 2 — read an entire log file and parse every line
# ---------------------------------------------------------------

def parse_log_lines(filepath: str) -> list:
    """
    Opens a log file. Reads it line by line.
    For each line, runs extract_iocs() and stores the result.
    Returns a list of event dictionaries.
    """
    events = []

    # encoding="utf-8"  = handle normal text files
    # errors="ignore"   = skip any weird characters that would crash the script
    with open(filepath, encoding="utf-8", errors="ignore") as f:

        # enumerate starts counting from 1 (so line_no matches real line numbers)
        for i, line in enumerate(f, 1):
            line = line.strip()   # remove spaces and newlines from both ends

            if not line:          # skip completely empty lines
                continue

            iocs = extract_iocs(line)

            # any() returns True if at least one list in iocs is non-empty
            has_iocs = any(iocs.values())

            events.append({
                "line_no":  i,
                "raw":      line,
                "iocs":     iocs,
                "has_iocs": has_iocs,
            })

    return events