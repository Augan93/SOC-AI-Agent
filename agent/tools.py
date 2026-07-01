import os
import requests
from langchain_community.tools import DuckDuckGoSearchRun


# AbuseIPDB — IP reputation lookup
#
# Free tier: 1,000 checks/day. No credit card needed.
# Sign up at https://www.abuseipdb.com/register
# Set ABUSEIPDB_API_KEY in your .env


def lookup_ip_reputation(ip: str) -> dict:
    """
    Query AbuseIPDB for an IP address.
    Returns a dict with reputation score, country, ISP, tor status.

    If no API key is set, returns mock data so development works offline.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")

    if not api_key:
        # Mock response for development — no API key needed
        print(f"[tools] No ABUSEIPDB_API_KEY set — returning mock data for {ip}")
        return {
            "abuseConfidenceScore": 85,
            "countryCode": "RU",
            "isp": "Mock ISP LLC",
            "isTor": False,
            "totalReports": 142,
            "mock": True,
        }

    if not ip or ip in ("unknown", "0.0.0.0", "127.0.0.1"):
        return {"error": "No valid IP to look up", "abuseConfidenceScore": 0}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json().get("data", {})
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "countryCode": data.get("countryCode", "unknown"),
            "isp": data.get("isp", "unknown"),
            "isTor": data.get("isTor", False),
            "totalReports": data.get("totalReports", 0),
        }
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB timeout", "abuseConfidenceScore": 0}
    except Exception as e:
        return {"error": str(e), "abuseConfidenceScore": 0}


# CVE lookup via DuckDuckGo web search
#
# No API key needed. Searches for CVE ID and returns a summary.
# In production, swap for NVD API (free, rate-limited):
# https://nvd.nist.gov/developers/vulnerabilities


_ddg = DuckDuckGoSearchRun()


def lookup_cve(cve_id: str) -> str:
    """
    Search for CVE details using DuckDuckGo.
    Returns a text summary of the vulnerability.
    """
    if not cve_id or cve_id.lower() == "unknown":
        return "No CVE ID provided in this alert."

    try:
        query = f"{cve_id} vulnerability CVSS score description site:nvd.nist.gov OR site:cve.mitre.org"
        result = _ddg.run(query)
        return result[:1500] if result else f"No results found for {cve_id}"
    except Exception as e:
        return f"CVE lookup failed for {cve_id}: {str(e)}"


def parse_cvss_from_text(text: str) -> tuple[float | None, str | None]:
    """
    Extract CVSS score and label from free-form CVE search text.
    Returns (score_float, label_string) or (None, None) if not found.
    """
    import re

    # Look for patterns like "CVSS 9.8" or "Base Score: 7.5"
    patterns = [
        r"cvss[:\s]+(\d+\.?\d*)",
        r"base score[:\s]+(\d+\.?\d*)",
        r"score[:\s]+(\d+\.?\d*)\s*/\s*10",
    ]
    for pattern in patterns:
        match = re.search(pattern, text.lower())
        if match:
            score = float(match.group(1))
            if score >= 9.0:
                label = "CRITICAL"
            elif score >= 7.0:
                label = "HIGH"
            elif score >= 4.0:
                label = "MEDIUM"
            else:
                label = "LOW"
            return score, label

    return None, None
