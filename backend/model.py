import os
import pandas as pd
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from joblib import dump, load

# Dataset contoh (ganti dengan dataset nyata)
def generate_sample_data():
    data = {
        "log": [
            # SQL Injection
            "GET /?id=1' OR '1'='1 HTTP/1.1",
            "POST /login?user=admin'--",
            # Brute-Force
            "POST /login HTTP/1.1 401",
            "Failed password for user=admin",
            # XSS
            "<script>alert('xss')</script>",
            "onerror='javascript:alert(1)'",
            # Normal
            "GET /index.html HTTP/1.1 200",
            "GET /css/style.css HTTP/1.1 200"
        ],
        "label": [
            "SQL Injection", "SQL Injection",
            "Brute-Force", "Brute-Force",
            "XSS", "XSS",
            "Normal", "Normal"
        ]
    }
    return pd.DataFrame(data)

# Preprocessing dan pelatihan model
def train_model():
    df = generate_sample_data()
    
    # TF-IDF Vectorizer
    vectorizer = TfidfVectorizer(
        max_features=1000,
        ngram_range=(1, 2),
        lowercase=True,
        stop_words=None
    )
    
    X = vectorizer.fit_transform(df['log'])
    y = df['label']
    
    # Split dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Model ML
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluasi
    y_pred = model.predict(X_test)
    print("Classification Report:")
    print(classification_report(y_test, y_pred))
    
    # Simpan model dan vectorizer
    os.makedirs("models", exist_ok=True)
    dump(model, "models/log_classifier.pkl")
    dump(vectorizer, "models/vectorizer.pkl")
    print("Model dan vectorizer disimpan di folder models/")

# Muat model dan vectorizer
def load_model():
    model = load("models/log_classifier.pkl")
    vectorizer = load("models/vectorizer.pkl")
    return model, vectorizer

# Prediksi teks log
def predict_log(log_text):
    model, vectorizer = load_model()
    X = vectorizer.transform([log_text])
    prediction = model.predict(X)[0]
    confidence = np.max(model.predict_proba(X)[0]) * 100
    return prediction, confidence