from flask import Flask, request, jsonify, render_template
import joblib
import os
import re
from urllib.parse import urlparse
import pandas as pd

from google_safe import check_google_safe
from virustotal import check_virustotal
from domain_ai import domain_age_check
from feature_extraction import extract_features

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------- LOAD MODELS ----------
URL_MODEL = joblib.load(os.path.join(BASE_DIR, "models/phishing_url_model.pkl"))
URL_SCALER = joblib.load(os.path.join(BASE_DIR, "models/url_scaler.pkl"))

TEXT_MODEL = joblib.load(os.path.join(BASE_DIR, "models/phishing_text_model.pkl"))
VECTORIZER = joblib.load(os.path.join(BASE_DIR, "models/text_vectorizer.pkl"))

# ---------- TRUST LIST ----------
TRUSTED_DOMAINS = {
    "google.com",
    "facebook.com",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "linkedin.com",
    "openai.com",
    "chatgpt.com"
}

# ---------- HELPERS ----------
def normalize_url(url):
    return url if url.startswith("http") else "http://" + url

def extract_urls(text):
    return list(set(re.findall(r"(https?://[^\s]+|www\.[^\s]+)", text.lower())))

def is_trusted_domain(url):
    domain = urlparse(normalize_url(url)).netloc
    return any(domain == d or domain.endswith("." + d) for d in TRUSTED_DOMAINS)

def get_verdict(score):
    if score >= 0.70:
        return "Phishing Website", "High Risk", "phishing"
    elif score >= 0.45:
        return "Suspicious Website", "Medium Risk", "suspicious"
    elif score >= 0.30:
        return "Uncertain", "Low Confidence", "uncertain"
    return "Safe Website", "Low Risk", "safe"

# ---------- ROUTES ----------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.get_json()
        text = data.get("input", "").strip()

        if not text:
            return jsonify({"error": "Input cannot be empty"}), 400

        urls = extract_urls(text)
        risk_factors = []
        threat_intel = {}
        url_scores = []
        trusted_found = False

        # -------- TEXT ANALYSIS --------
        X_text = VECTORIZER.transform([text])
        text_score = TEXT_MODEL.predict_proba(X_text)[0][1]

        # -------- URL ANALYSIS --------
        for raw_url in urls:
            url = normalize_url(raw_url)
            domain = urlparse(url).netloc

            # Trusted domain flag
            trusted_flag = 1 if is_trusted_domain(url) else 0
            if trusted_flag:
                trusted_found = True

            # SSL check
            ssl_flag = 1 if url.startswith("https://") else 0

            # Threat intelligence defaults
            gs_score, gs_msg = 0.0, "Not checked"
            vt_score, vt_msg = 0.0, "Not checked"
            da_score, da_msg = 0.0, "Not checked"

            # Google Safe Browsing
            try:
                gs_score, gs_msg = check_google_safe(url)
            except Exception:
                gs_score, gs_msg = 0.0, "Google Safe Browsing check failed"

            # VirusTotal
            try:
                vt_score, vt_msg = check_virustotal(url)
            except Exception:
                vt_score, vt_msg = 0.0, "VirusTotal check failed"

            # Domain Age
            try:
                da_score, da_msg = domain_age_check(url)
            except Exception:
                da_score, da_msg = 0.0, "Domain age check failed"

            threat_intel["Google Safe Browsing"] = gs_msg
            threat_intel["VirusTotal"] = vt_msg

            if da_score > 0.5:
                risk_factors.append(da_msg)

            # -------- ML URL analysis with safe fallback --------
            try:
                features = extract_features(url)
                if not isinstance(features, list):
                    features = list(features)

                # Add context features
                features.extend([trusted_flag, ssl_flag, da_score])

                # Transform using scaler
                feature_names = URL_SCALER.get_feature_names_out()
                df_features = pd.DataFrame([features], columns=feature_names)
                scaled = URL_SCALER.transform(df_features)

                # Predict
                ml_score = URL_MODEL.predict_proba(scaled)[0][1]

                if ml_score > 0.6:
                    risk_factors.append("URL pattern resembles known phishing structures")

            except Exception:
                ml_score = 0.0  # Safe fallback

            url_scores.append(max(gs_score or 0.0, vt_score or 0.0, da_score or 0.0, ml_score))

        url_score = max(url_scores) if url_scores else 0.0

        # Reduce risk score for trusted domains, ensure minimum confidence
        if trusted_found and url_score > 0:
            url_score = max(url_score * 0.4, 0.1)

        # Combine URL and text scores
        final_score = min((0.6 * url_score) + (0.4 * text_score), 1.0)
        verdict, risk_level, status = get_verdict(final_score)
        confidence = round(final_score * 100, 2)

        if not risk_factors and status != "safe":
            risk_factors = ["No significant risk factors detected"]

        # -------- USER MESSAGE --------
        messages = {
            "phishing": (
                "This website shows strong indicators of phishing activity.",
                "Do NOT enter passwords, OTPs, or personal information."
            ),
            "suspicious": (
                "This website exhibits some suspicious characteristics.",
                "Proceed with caution."
            ),
            "uncertain": (
                "The system could not determine risk with high confidence.",
                "Manually verify the source before proceeding."
            ),
            "safe": (
                "No significant phishing indicators were detected.",
                "You can safely continue browsing."
            )
        }

        summary, recommendation = messages.get(status, ("Unknown status", "Exercise caution"))

        return jsonify({
            "verdict": verdict,
            "status": status,
            "risk_level": risk_level,
            "confidence": confidence,
            "summary": summary,
            "risk_factors": risk_factors,
            "threat_intelligence": threat_intel,
            "recommendation": recommendation
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
