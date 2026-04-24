import re

# -----------------------------
# CONFIG
# -----------------------------
SUSPICIOUS_WORDS = [
    "urgent", "immediately", "click", "verify", "blocked",
    "suspend", "reward", "cashback", "lottery", "win",
    "account", "bank", "offer", "free", "limited", "kyc"
]

SUSPICIOUS_TLDS = [".xyz", ".top", ".loan", ".click"]

TRUSTED_BANKS = ["sbi", "hdfc", "icici", "axis", "rbi", "paytm"]

# -----------------------------
# LANGUAGE DETECTION (Simple)
# -----------------------------
def detect_language(text):
    if any(word in text.lower() for word in ["hai", "kar", "karo", "aapka"]):
        return "Hinglish/Hindi"
    return "English"

# -----------------------------
# ENTITY EXTRACTION
# -----------------------------
def extract_entities(text):
    urls = re.findall(r'https?://\S+', text)
    upi_ids = re.findall(r'[\w.-]+@[\w]+', text)
    amounts = re.findall(r'₹\s?\d+|\d+\s?rs|\d{3,}', text.lower())

    return {
        "urls": urls,
        "upi_ids": upi_ids,
        "amounts": amounts
    }

# -----------------------------
# URL ANALYSIS
# -----------------------------
def analyze_urls(urls):
    score = 0
    reasons = []

    for url in urls:
        if any(tld in url for tld in SUSPICIOUS_TLDS):
            score += 2
            reasons.append(f"Suspicious domain: {url}")

        if "-" in url or len(url) > 30:
            score += 1
            reasons.append(f"Unusual URL pattern: {url}")

    return score, reasons

# -----------------------------
# IMPERSONATION DETECTION
# -----------------------------
def detect_impersonation(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    for bank in TRUSTED_BANKS:
        if bank in text_lower:
            score += 1
            reasons.append(f"Mentions bank: {bank.upper()}")

    return score, reasons

# -----------------------------
# PATTERN DETECTION
# -----------------------------
def detect_patterns(text):
    text_lower = text.lower()
    score = 0
    reasons = []

    for word in SUSPICIOUS_WORDS:
        if word in text_lower:
            score += 1
            reasons.append(f"Suspicious word: {word}")

    if "urgent" in text_lower or "immediately" in text_lower:
        score += 2
        reasons.append("Creates urgency")

    if "click" in text_lower:
        score += 1
        reasons.append("Requests clicking link")

    return score, reasons

# -----------------------------
# SCAM TYPE DETECTION
# -----------------------------
def detect_type(text):
    text_lower = text.lower()

    if "upi" in text_lower or "@upi" in text_lower:
        return "UPI Scam"
    elif "kyc" in text_lower or "account" in text_lower:
        return "Bank/KYC Scam"
    elif "job" in text_lower or "earn" in text_lower:
        return "Job Scam"
    elif "offer" in text_lower or "win" in text_lower:
        return "Lottery/Offer Scam"
    elif "otp" in text_lower:
        return "OTP Scam"
    else:
        return "Unknown"

# -----------------------------
# MAIN FUNCTION
# -----------------------------
def analyze_message(text):
    entities = extract_entities(text)

    pattern_score, pattern_reasons = detect_patterns(text)
    url_score, url_reasons = analyze_urls(entities["urls"])
    imp_score, imp_reasons = detect_impersonation(text)

    total_score = pattern_score + url_score + imp_score

    # Smart confidence (no heavy ML)
    confidence = min(1.0, 0.3 + total_score * 0.1)

    # Risk level
    if total_score >= 6:
        risk_level = "HIGH"
    elif total_score >= 3:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Combine reasons
    all_reasons = pattern_reasons + url_reasons + imp_reasons

    # Human-like explanation
    if all_reasons:
        explanation = "This message may be a scam because it: " + ", ".join(all_reasons)
    else:
        explanation = "No strong scam indicators detected."

    # Advice
    if risk_level == "HIGH":
        advice = "Avoid clicking links or sending money. This is likely a scam."
    elif risk_level == "MEDIUM":
        advice = "Be cautious. Verify the sender before taking action."
    else:
        advice = "Seems safe, but always stay alert."

    return {
        "risk_level": risk_level,
        "confidence": round(confidence, 2),
        "language": detect_language(text),
        "message_type": detect_type(text),
        "risk_score": total_score,
        "entities": entities,
        "explanation": explanation,
        "advice": advice,
        "risk_factors": all_reasons
    }


# -----------------------------
# TEST
# -----------------------------
if __name__ == "__main__":
    msg = "Aapka SBI account block hone wala hai. Click http://secure-pay.xyz aur ₹5000 bheje turant"
    print(analyze_message(msg))