from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
import re
from werkzeug.utils import secure_filename
import json
from datetime import datetime
import random  # For mock predictions
from flask import send_file
from fpdf import FPDF
from rules import ATTACK_RULES 
import io
from urllib.parse import unquote

app = Flask(__name__)
CORS(app)

# Simpan hasil analisis terakhir untuk PDF
last_upload_threats = []

# Konfigurasi database SQLite
app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///logs.db?mode=rwc"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Create upload folder
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# Model Database untuk Riwayat Analisis
class LogAnalysis(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_line = db.Column(db.Text, nullable=False)
    threat_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    confidence = db.Column(db.String(10))  # Hanya untuk prediksi ML
    source = db.Column(db.String(20))  # "Rule-Based" atau "ML Model"

    def to_dict(self):
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "log_line": self.log_line,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "confidence": self.confidence,
            "source": self.source,
        }


# Create database tables
with app.app_context():
    db.create_all()

"""
# Muat aturan dari file JSON (rule-based)
def load_rules():
    return {
        "SQL Injection": {
            "patterns": [
                r".*('.+--|UNION|SELECT|DROP).*$",
                r".*(%27|%22|').*(%3D|=|%3B).*",  # URL-encoded SQLi
            ],
            "severity": "High",
        },
        "Brute-Force": {
            "patterns": [r".*POST.*\/login.*401.*$", r".*Failed password for.*$"],
            "severity": "Medium",
        },
        "XSS": {
            "patterns": [r".*<script>.*<\/script>.*$", r".*(onerror=|onload=).*\(\).*"],
            "severity": "Medium",
        },
    }


ATTACK_RULES = load_rules()
"""


# Fungsi deteksi berbasis aturan
def detect_threats(line):
    decoded_line = unquote(line)  # Decode URL encoding

    for attack_type, config in ATTACK_RULES.items():
        for pattern in config["patterns"]:
            if re.search(pattern, decoded_line, re.IGNORECASE):
                return [{
                    "type": attack_type,
                    "severity": config["severity"],
                    "match": pattern,
                }]
    return [{
        "type": "Normal",
        "severity": "None",
        "match": None
    }]


# Mock ML prediction function
def predict_log(line):
    # Simulate ML prediction - in a real app, this would use a trained model
    threat_types = ["SQL Injection", "XSS", "Brute-Force", "Normal"]
    # 70% chance of being normal, 30% chance of threat
    if random.random() < 0.3:
        threat = random.choice(threat_types[:-1])  # Exclude "Normal"
        confidence = random.randint(70, 99)
    else:
        threat = "Normal"
        confidence = random.randint(85, 99)
    return threat, confidence


# Mock training function
def train_model():
    print("Simulating model training...")
    # In a real app, this would train and save a model
    print("Model 'trained' successfully!")


# Endpoint untuk upload file log
@app.route("/api/upload", methods=["POST"])
def upload_file():
    if "logfile" not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files["logfile"]

    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    try:
        # Simpan file
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # Baca isi file
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        # Analisis dengan rule-based dan ML
        threats = []
        ml_predictions = []

        for line in lines:
            # Deteksi berbasis aturan
            detected = detect_threats(line)
            if detected:
                threats.extend(
                    [
                        {
                            "line": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                            **threat,
                        }
                        for threat in detected
                    ]
                )
            else:
                # Jika tidak terdeteksi oleh rule-based, gunakan ML
                prediction, confidence = predict_log(line)
                if prediction != "Normal" and confidence > 70:
                    ml_predictions.append(
                        {
                            "line": line.strip(),
                            "timestamp": datetime.now().isoformat(),
                            "type": prediction,
                            "severity": "Medium" if prediction == "XSS" else "High",
                            "confidence": f"{confidence:.2f}%",
                            "source": "rule based",
                        }
                    )

        # Gabungkan hasil
        combined_threats = threats + ml_predictions

        global last_upload_threats
        last_upload_threats = combined_threats


        # Simpan ke database
        for threat in combined_threats:
            log_entry = LogAnalysis(
                log_line=threat["line"],
                threat_type=threat["type"],
                severity=threat["severity"],
                confidence=threat.get("confidence"),
                source=threat.get("source", "Rule-Based"),
            )
            db.session.add(log_entry)
        db.session.commit()

        # Hapus file setelah diproses
        os.remove(file_path)

        # Kembalikan hasil
        return jsonify(
            {
                "totalLogs": len(lines),
                "threats": combined_threats,
                "cleanLogs": len(lines) - len(combined_threats),
                "summary": {
                    "high_risk": sum(
                        1 for t in combined_threats if t["severity"] == "High"
                    ),
                    "medium_risk": sum(
                        1 for t in combined_threats if t["severity"] == "Medium"
                    ),
                },
            }
        )

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


# Endpoint untuk melihat riwayat analisis
@app.route("/api/history", methods=["GET"])
def get_history():
    try:
        entries = LogAnalysis.query.order_by(LogAnalysis.timestamp.desc()).all()
        return jsonify([entry.to_dict() for entry in entries])
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Root endpoint
@app.route("/")
def home():
    return """
    <h1>Log Analysis API</h1>
    <p>Endpoints:</p>
    <ul>
        <li>POST /api/upload - Upload log file for analysis</li>
        <li>GET /api/history - Get analysis history</li>
    </ul>
    """

@app.route('/download_summary', methods=['GET'])
def download_summary():
    logs = LogAnalysis.query.all()

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Log Summary (5W1H)", ln=True, align="C")
    pdf.ln(10)

    for i, log in enumerate(logs, start=1):
        # Who: Ambil IP dari log
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log.log_line)
        who_info = ip_matches[0] if ip_matches else "Tidak diketahui"

        # Deteksi rule
        matched = get_matching_rule(log.log_line)
        why_info = matched["reason"] if matched else "Tidak diketahui"
        how_info = matched["method"] if matched else "Tidak diketahui"

        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(200, 10, txt=f"Log #{i}", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 10, txt=f"""What : {log.threat_type}
When : {log.timestamp}
Where: {log.log_line[:100]}...
Why  : {why_info}
Who  : {who_info}
How  : {how_info}
""")
        pdf.ln(5)

    pdf_output = io.BytesIO()
    # pdf.output(pdf_output)
    # pdf_output.seek(0)

    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    pdf_output = io.BytesIO(pdf_bytes)

    pdf_output.seek(0)

    return send_file(pdf_output, as_attachment=True, download_name="log_summary_5W1H.pdf")

@app.route("/download_pdf", methods=["GET"])
def download_pdf():
    if not last_upload_threats:
        return jsonify({"error": "Belum ada hasil analisis"}), 400

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Log Summary (5W1H)", ln=True, align="C")
    pdf.ln(10)

    for i, threat in enumerate(last_upload_threats, start=1):
        # Who: Ambil IP dari baris log
        ip_matches = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', threat["line"])
        who_info = ip_matches[0] if ip_matches else "Tidak diketahui"

        # Ambil info pola yang cocok dan cara serang (how)
        matched = get_matching_rule(threat["line"])
        why_info = matched["reason"] if matched else "Log tidak cocok dengan pola serangan apa pun."
        how_info = matched["method"] if matched else "Tidak ada indikasi aktivitas mencurigakan atau teknik serangan."

        pdf.set_font("Arial", style="B", size=12)
        pdf.cell(200, 10, txt=f"Log #{i}", ln=True)
        pdf.set_font("Arial", size=11)
        pdf.multi_cell(0, 10, txt=f"""What : {threat["type"]}
When : {threat["timestamp"]}
Where: {threat["line"][:100]}...
Why  : {why_info}
Who  : {who_info}
How  : {how_info}
""")
        pdf.ln(5)

    # Output PDF ke memori
    pdf_bytes = pdf.output(dest='S').encode('latin-1')
    pdf_output = io.BytesIO(pdf_bytes)
    pdf_output.seek(0)

    return send_file(pdf_output, as_attachment=True, download_name="log_summary_5W1H.pdf")


def get_matching_rule(log_line):
    for rule_name, rule_data in ATTACK_RULES.items():
        for pattern in rule_data.get("patterns", []):
            if re.search(pattern, log_line, re.IGNORECASE):
                return {
                    "name": rule_name,
                    "severity": rule_data.get("severity", "Unknown"),
                    "weight": rule_data.get("weight", 0.5),
                    "reason": f"Kecocokan pola: {pattern}",
                    "method": rule_data.get("how", rule_name)
                }
    return None



if __name__ == "__main__":
    # Simulate model training
    print("Melatih model ML...")
    train_model()

    app.run(debug=True, port=5000)
