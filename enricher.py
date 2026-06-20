import requests
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, API_TIMEOUT

VT_BASE    = "https://www.virustotal.com/api/v3"
ABUSE_BASE = "https://api.abuseipdb.com/api/v2"


def enrich_ip_virustotal(ip: str) -> dict:
    try:
        r = requests.get(
            f"{VT_BASE}/ip_addresses/{ip}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=API_TIMEOUT
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "source":     "virustotal",
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection"}
    except Exception as e:
        return {"error": str(e)}


def enrich_ip_abuseipdb(ip: str) -> dict:
    try:
        r = requests.get(
            f"{ABUSE_BASE}/check",
            headers={
                "Key":    ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            },
            params={
                "ipAddress":    ip,
                "maxAgeInDays": 90
            },
            timeout=API_TIMEOUT
        )
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        data = r.json()["data"]
        return {
            "source":           "abuseipdb",
            "abuse_confidence": data.get("abuseConfidenceScore", 0),
            "total_reports":    data.get("totalReports", 0),
            "country_code":     data.get("countryCode", ""),
            "isp":              data.get("isp", ""),
            "domain":           data.get("domain", ""),
        }
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection"}
    except Exception as e:
        return {"error": str(e)}


def enrich_hash_virustotal(file_hash: str) -> dict:
    try:
        r = requests.get(
            f"{VT_BASE}/files/{file_hash}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=API_TIMEOUT
        )
        if r.status_code == 404:
            return {"source": "virustotal", "not_found": True}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "source":     "virustotal",
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
        }
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection"}
    except Exception as e:
        return {"error": str(e)}


def enrich_url_virustotal(url: str) -> dict:
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        r = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers={"x-apikey": VIRUSTOTAL_API_KEY},
            timeout=API_TIMEOUT
        )
        if r.status_code == 404:
            return {"source": "virustotal", "not_found": True}
        if r.status_code != 200:
            return {"error": f"HTTP {r.status_code}"}
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "source":     "virustotal",
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
        }
    except requests.exceptions.Timeout:
        return {"error": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "No internet connection"}
    except Exception as e:
        return {"error": str(e)}


def enrich_event(event: dict) -> dict:
    enrichments = {}

    for ip in event["iocs"].get("ips", []):
        print(f"  Checking IP: {ip}")
        enrichments[ip] = {
            "virustotal": enrich_ip_virustotal(ip),
            "abuseipdb":  enrich_ip_abuseipdb(ip),
        }

    for h in event["iocs"].get("hashes", []):
        print(f"  Checking hash: {h}")
        enrichments[h] = {
            "virustotal": enrich_hash_virustotal(h)
        }

    for url in event["iocs"].get("urls", []):
        print(f"  Checking URL: {url}")
        enrichments[url] = {
            "virustotal": enrich_url_virustotal(url)
        }

    event["enrichments"] = enrichments
    return event