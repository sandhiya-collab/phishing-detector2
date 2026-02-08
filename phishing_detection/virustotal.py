import requests
import base64

# 🔑 PUT YOUR KEY HERE
VT_API_KEY = "722b0716c84f835a649f3d647c7f5aec2a3879bb6e1dad6b28d034b6265a3d76"
VT_URL = "https://www.virustotal.com/api/v3/urls"

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"{VT_URL}/{url_id}",
            headers=headers,
            timeout=8
        )

        data = response.json()

        if "data" not in data:
            return 0.0, "VirusTotal has no report for this URL"

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total_flags = malicious + suspicious

        if total_flags > 0:
            score = min(1.0, total_flags / 10)
            return score, (
                f"VirusTotal flagged {malicious} malicious "
                f"and {suspicious} suspicious engines"
            )

        return 0.0, "VirusTotal reports no malicious activity"

    except Exception as e:
        return 0.0, f"VirusTotal error: {str(e)}"


