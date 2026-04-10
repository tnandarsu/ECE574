import requests

OSV_URL = "https://api.osv.dev/v1/query"

def query_osv(package_name: str, version: str) -> list[dict]:
    payload = {
        "version": version,
        "package": {"name": package_name, "ecosystem": "PyPI"}
    }

    try:
        resp = requests.post(OSV_URL, json=payload, timeout=10)
        if resp.status_code != 200:
            return []
    except requests.RequestException:
        return []

    vulns = []

    for v in resp.json().get("vulns", []):
        severity = "UNKNOWN"
        cvss_score = 0.0

        for s in v.get("severity", []):
            if s.get("type") == "CVSS_V3":
                try:
                    cvss_score = float(s.get("score", 0))
                except (ValueError, TypeError):
                    cvss_score = 0.0

                severity = classify_cvss(cvss_score)

        vulns.append({
            "id": v.get("id", "N/A"),
            "summary": v.get("summary", "No summary"),
            "severity": severity,
            "cvss_score": cvss_score
        })

    return vulns

def classify_cvss(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    return "LOW"