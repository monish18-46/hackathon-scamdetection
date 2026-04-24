import re
import os
import json
import pandas as pd
import uuid
from datetime import datetime
from langdetect import detect
from deep_translator import GoogleTranslator
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

# ---------------- LOG FILE ----------------
LOG_FILE = "scam_logs.csv"

# ---------------- AI MODEL ----------------
data = {
    "text": [
        "Your account is blocked click here",
        "Verify your bank account now",
        "Send OTP to update KYC",
        "Win cash prize click link",
        "Urgent action required login now",
        "Account suspended verify immediately",
        "Meeting at 5pm today",
        "Let's go for lunch",
        "Project deadline tomorrow",
        "Happy birthday bro",
        "See you in class",
        "Call me later"
    ],
    "label": [
        "scam","scam","scam","scam","scam","scam",
        "safe","safe","safe","safe","safe","safe"
    ]
}

df = pd.DataFrame(data)

model = Pipeline([
    ("vectorizer", CountVectorizer()),
    ("classifier", MultinomialNB())
])

model.fit(df["text"], df["label"])

def ai_predict(msg):
    prediction = model.predict([msg])[0]
    probability = model.predict_proba([msg]).max()
    return prediction.upper(), round(probability, 2)

# ---------------- LANGUAGE DETECTION ----------------
def detect_language(msg):
    try:
        code = detect(msg)
        return {
            "en": "English",
            "hi": "Hindi",
            "ta": "Tamil",
            "te": "Telugu",
            "kn": "Kannada",
            "ml": "Malayalam"
        }.get(code, code)
    except:
        return "Unknown"

# ---------------- TRANSLATION ----------------
def translate_to_english(msg):
    try:
        return GoogleTranslator(source='auto', target='en').translate(msg)
    except:
        return msg

# ---------------- KEYWORDS ----------------
KEYWORDS = {
    "click": 20, "urgent": 25, "verify": 20, "kyc": 20,
    "account": 10, "blocked": 20, "login": 15,
    "otp": 25, "bank": 15, "update": 10, "suspended": 20
}

# ---------------- HIGHLIGHT ----------------
def highlight_words(msg):
    words = msg.split()
    return " ".join([
        f"[{w.upper()}]" if w.lower().strip(".,!?") in KEYWORDS else w
        for w in words
    ])

# ---------------- ENTITY EXTRACTION ----------------
def extract_entities(msg):
    return {
        "upi_ids": re.findall(r'\b[\w.-]+@[\w]+\b', msg),
        "links": re.findall(r'http[s]?://\S+', msg),
        "amounts": re.findall(r'₹\d+|\d+\s?rs', msg.lower())
    }

# ---------------- RISK ENGINE ----------------
def calculate_risk(msg):
    msg_lower = msg.lower()
    risk = 0
    reasons = []

    for word, score in KEYWORDS.items():
        if word in msg_lower:
            risk += score
            reasons.append(f"Keyword detected: {word}")

    if "http" in msg_lower:
        risk += 30
        reasons.append("Contains link")

    return risk, reasons

# ---------------- LOGGING FEATURE ----------------
def log_result(result):
    row = {
        "timestamp": result["meta"]["timestamp"],
        "text": result["input"]["original_text"],
        "language": result["input"]["language"],
        "risk_level": result["analysis"]["risk"]["level"],
        "risk_score": result["analysis"]["risk"]["score"],
        "ai_label": result["analysis"]["ai_prediction"]["label"],
        "confidence": result["analysis"]["ai_prediction"]["confidence"]
    }

    df_row = pd.DataFrame([row])

    if not os.path.exists(LOG_FILE):
        df_row.to_csv(LOG_FILE, index=False)
    else:
        df_row.to_csv(LOG_FILE, mode='a', header=False, index=False)

# ---------------- MAIN FUNCTION ----------------
def analyze_text(msg):
    request_id = str(uuid.uuid4())
    timestamp = datetime.now().isoformat()

    language = detect_language(msg)
    translated = translate_to_english(msg)

    risk, reasons = calculate_risk(translated)
    ai_label, ai_conf = ai_predict(translated)
    entities = extract_entities(msg)

    # Risk level
    if risk >= 60 or ai_label == "SCAM":
        level = "HIGH"
    elif risk >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    # Advice
    if level == "HIGH":
        advice = "Do NOT click links or send money."
    elif level == "MEDIUM":
        advice = "Be cautious. Verify before acting."
    else:
        advice = "Looks safe, but stay alert."

    explanation = ", ".join(reasons) if reasons else "No strong indicators"

    result = {
        "status": "success",
        "meta": {
            "request_id": request_id,
            "timestamp": timestamp
        },
        "input": {
            "original_text": msg,
            "translated_text": translated,
            "language": language
        },
        "analysis": {
            "risk": {
                "level": level,
                "score": risk,
                "confidence": round(min(risk / 100, 1.0), 2)
            },
            "ai_prediction": {
                "label": ai_label,
                "confidence": ai_conf
            }
        },
        "entities": entities,
        "insights": {
            "highlighted_text": highlight_words(msg),
            "reasons": reasons,
            "explanation": explanation,
            "advice": advice
        }
    }

    # 🔥 LOG EVERY REQUEST
    log_result(result)

    return result

# ---------------- TEST ----------------
if __name__ == "__main__":
    msg = input("Enter message: ")
    result = analyze_text(msg)
    print(json.dumps(result, indent=4))