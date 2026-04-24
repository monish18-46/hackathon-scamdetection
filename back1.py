import re
from transformers import pipeline

# OPTIONAL: Small model (fast download ~250MB)
try:
    classifier = pipeline(
        "text-classification",
        model="distilbert-base-uncased-finetuned-sst-2-english"
    )
    USE_ML = True
except:
    USE_ML = False

# Suspicious keywords
SUSPICIOUS_WORDS = [
    "urgent", "immediately", "click", "verify", "blocked",
    "suspend", "reward", "cashback", "lottery", "win",
    "account", "bank", "offer", "free", "limited"
]

# Suspicious domains
SUSPICIOUS_TLDS = [".xyz", ".top", ".loan", ".click"]

# -----------------------------
# ENTITY EXTRACTION
# -----------------------------
def extract_entities(text):
    urls = re.findall(r'https?://\S+', text)
    upi_ids = re.findall(r'[\w.-]+@[\w]+', text)
    amounts = re.findall(r'₹\s?\d+|\d+\s?rs', text.lower())

    return {
        "urls": urls,
        "upi_ids": upi_ids,
        "amounts": amounts
    }

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
            reasons.append(f"Contains suspicious word: {word}")

    for tld in SUSPICIOUS_TLDS:
        if tld in text_lower:
            score += 2
            reasons.append("Suspicious domain detected")

    if "urgent" in text_lower or "immediately" in text_lower:
        score += 2
        reasons.append("Creates urgency")

    return score, reasons

# -----------------------------
# MESSAGE TYPE DETECTION
# -----------------------------
def detect_type(text):
    text_lower = text.lower()

    if "upi" in text_lower or "@upi" in text_lower:
        return "UPI Scam"
    elif "bank" in text_lower or "account" in text_lower:
        return "Bank Scam"
    elif "job" in text_lower or "earn" in text_lower:
        return "Job Scam"
    elif "offer" in text_lower or "win" in text_lower:
        return "Promotional Scam"
    else:
        return "Unknown"

# -----------------------------
# MAIN FUNCTION
# -----------------------------
def analyze_message(text):
    entities = extract_entities(text)
    pattern_score, pattern_reasons = detect_patterns(text)

    # ML (optional)
    if USE_ML:
        prediction = classifier(text)[0]
        confidence = prediction['score']
    else:
        # fallback smart confidence
        confidence = min(1.0, 0.4 + pattern_score * 0.15)

    # Risk score
    risk_score = confidence + (pattern_score * 0.2)

    # Risk level
    if risk_score > 0.8:
        risk_level = "HIGH"
    elif risk_score > 0.5:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Explanation
    if pattern_reasons:
        explanation = "This message looks risky because: " + ", ".join(pattern_reasons)
    else:
        explanation = "No strong scam indicators detected."

    # Advice
    if risk_level == "HIGH":
        advice = "Do NOT click links or send money."
    elif risk_level == "MEDIUM":
        advice = "Be cautious. Verify before acting."
    else:
        advice = "Looks safe, but stay alert."

    return {
        "risk_level": risk_level,
        "confidence": round(confidence, 2),
        "message_type": detect_type(text),
        "entities": entities,
        "explanation": explanation,
        "advice": advice
    }


# Test
if __name__ == "__main__":
    msg = "Dear user, your SBI account will be blocked. Click http://fake.xyz and pay ₹5000 immediately."
    print(analyze_message(msg))