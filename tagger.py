from config import VT_MALICIOUS_THRESHOLD, ABUSE_CONFIDENCE_THRESHOLD


def score_ioc(enrichment: dict) -> tuple:
    """
    Reads the API results for ONE IOC and returns a verdict.
    
    Logic:
    - Start with severity = 0 (unknown)
    - Each API can push severity UP but never down
    - Final severity maps to a tag label
    
    Severity scale:
      0 = UNKNOWN  (APIs didn't return usable data)
      1 = CLEAN    (APIs checked it and found nothing)
      2 = SUSPICIOUS (some flags but below threshold)
      3 = MALICIOUS  (clearly bad)
    """
    reasons  = []
    severity = 0

    # ---- VirusTotal results ----
    vt = enrichment.get("virustotal", {})

    if "error" in vt:
        reasons.append(f"VT error: {vt['error']}")

    elif vt.get("not_found"):
        reasons.append("VT: hash not in database (unknown file)")

    else:
        mal = vt.get("malicious", 0)
        sus = vt.get("suspicious", 0)

        if mal >= VT_MALICIOUS_THRESHOLD:
            # Enough engines flagged it — definitely malicious
            reasons.append(f"VT: {mal} engines flagged as malicious")
            severity = max(severity, 3)

        elif mal > 0 or sus > 0:
            # Some flags but not enough to be certain
            reasons.append(f"VT: {mal} malicious, {sus} suspicious detections")
            severity = max(severity, 2)

        else:
            reasons.append(f"VT: clean (0 detections)")
            severity = max(severity, 1)

    # ---- AbuseIPDB results (only IPs have this) ----
    ab = enrichment.get("abuseipdb", {})

    if "error" in ab:
        reasons.append(f"AbuseIPDB error: {ab['error']}")

    elif ab:
        conf    = ab.get("abuse_confidence", 0)
        reports = ab.get("total_reports", 0)
        country = ab.get("country_code", "")
        isp     = ab.get("isp", "")

        if conf >= ABUSE_CONFIDENCE_THRESHOLD:
            reasons.append(
                f"AbuseIPDB: {conf}% confidence, {reports} reports, "
                f"{country}, ISP: {isp}"
            )
            severity = max(severity, 3)

        elif conf > 0:
            reasons.append(
                f"AbuseIPDB: low confidence {conf}%, {reports} reports"
            )
            severity = max(severity, 2)

        else:
            reasons.append("AbuseIPDB: no abuse reports")
            severity = max(severity, 1)

    # Map severity number to a label
    tag_map = {
        0: "UNKNOWN",
        1: "CLEAN",
        2: "SUSPICIOUS",
        3: "MALICIOUS"
    }
    return tag_map[severity], reasons


def tag_event(event: dict) -> dict:
    """
    Loops through every IOC in one log event.
    Tags each IOC individually.
    Sets the event-level tag to the WORST tag found.
    
    Example: if an event has 3 IPs and one is MALICIOUS,
    the whole event gets tagged MALICIOUS.
    """
    tagged_iocs   = {}
    event_severity = 0

    severity_map = {
        "UNKNOWN":    0,
        "CLEAN":      1,
        "SUSPICIOUS": 2,
        "MALICIOUS":  3,
    }

    for ioc, enrichment in event.get("enrichments", {}).items():
        tag, reasons = score_ioc(enrichment)
        tagged_iocs[ioc] = {
            "tag":     tag,
            "reasons": reasons,
        }
        # Track the worst tag seen across all IOCs in this event
        event_severity = max(event_severity, severity_map[tag])

    tag_map = {0: "UNKNOWN", 1: "CLEAN", 2: "SUSPICIOUS", 3: "MALICIOUS"}

    event["tagged_iocs"] = tagged_iocs
    event["event_tag"]   = tag_map[event_severity]
    return event