import requests
import os

# 🔑 PUT YOUR KEY HERE
GOOGLE_API_KEY = "AQ.Ab8RN6Jifxi_CsW7vwOx5vVrFCr_dl2UYa7IV3sWXhii57hMPw"

SAFE_BROWSING_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

def check_google_safe(url):
    payload = {
        "client": {
            "clientId": "phishing-detection-system",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE",
                "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": url}
            ]
        }
    }

    try:
        response = requests.post(
            SAFE_BROWSING_URL,
            params={"key": GOOGLE_API_KEY},
            json=payload,
            timeout=8
        )

        data = response.json()

        if "matches" in data:
            return 0.9, "Google Safe Browsing flagged this URL as malicious"

        return 0.0, "Google Safe Browsing reports no threat"

    except Exception as e:
        return 0.0, f"Google Safe Browsing error: {str(e)}"



