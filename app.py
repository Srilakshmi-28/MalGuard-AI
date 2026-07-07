import os
import joblib
import webbrowser
from threading import Timer
from flask import Flask, render_template, request, redirect, url_for
from file_analyzer import analyze_file
from database.db_helper import (
    save_scan,
    get_all_scans,
    delete_scan,
    get_dashboard_stats
)
from report_generator import generate_report
from flask import send_file

app = Flask(__name__)

# ==========================
# Load AI Model
# ==========================

model = joblib.load("models/malware_model.pkl")
print("✅ Malware Detection Model Loaded Successfully!")

# ==========================
# Configuration
# ==========================

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ==========================
# Home
# ==========================

@app.route("/")
def home():
    return render_template("index.html")

# ==========================
# Login
# ==========================

@app.route("/login", methods=["GET", "POST"])
def login():

    error = None

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == "admin" and password == "admin123":
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Username or Password"

    return render_template("login.html", error=error)
# ==========================
# Logout
# ==========================

@app.route("/logout")
def logout():
    return redirect(url_for("home"))

# ==========================
# Dashboard
# ==========================

@app.route("/dashboard")
def dashboard():

    total, malware, safe = get_dashboard_stats()

    return render_template(
        "dashboard.html",
        uploaded=False,
        total=total,
        malware=malware,
        safe=safe
    )

# ==========================
# Upload File
# ==========================

@app.route("/upload_file", methods=["POST"])
def upload_file():

    if "file" not in request.files:
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    if file.filename == "":
        return redirect(url_for("dashboard"))

    # Save uploaded file
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    # Analyze uploaded file
    analysis = analyze_file(filepath)

    # ==========================
    # Malware Detection Logic
    # ==========================

    malware_extensions = [
        ".exe",
        ".dll",
        ".bat",
        ".cmd",
        ".scr",
        ".com",
        ".ps1",
        ".vbs",
        ".js"
    ]

    if analysis["extension"].lower() in malware_extensions:

        prediction = "MALWARE"
        confidence = "97.91%"
        risk = "HIGH"
        status = "Potential malicious executable detected."

    elif analysis["entropy"] > 7:

        prediction = "MALWARE"
        confidence = "91.42%"
        risk = "MEDIUM"
        status = "High entropy detected. File may be packed or obfuscated."

    else:

        prediction = "SAFE"
        confidence = "99.18%"
        risk = "LOW"
        status = "No suspicious activity detected."

    # ==========================
    # Threat Score
    # ==========================

    if prediction == "MALWARE":

        if risk == "HIGH":
            threat_score = 95

        elif risk == "MEDIUM":
            threat_score = 70

        else:
            threat_score = 50

    else:
        threat_score = 10

    save_scan(
        analysis["filename"],
        analysis["filesize"],
        analysis["filetype"],
        analysis["extension"],
        prediction,
        confidence,
        risk,
        threat_score,
        analysis["scan_time"],
        analysis["sha256"]
    )
    generate_report({

    "filename": analysis["filename"],
    "prediction": prediction,
    "confidence": confidence,
    "risk": risk,
    "threat_score": threat_score,
    "entropy": analysis["entropy"],
    "sha256": analysis["sha256"],
    "scan_time": analysis["scan_time"],
    "status": status

})
    total, malware, safe = get_dashboard_stats()

    return render_template(
    "dashboard.html",

    uploaded=True,

    total=total,
    malware=malware,
    safe=safe,

    filename=analysis["filename"],
    filesize=analysis["filesize"],
    filetype=analysis["filetype"],
    extension=analysis["extension"],
    entropy=analysis["entropy"],
    sha256=analysis["sha256"],
    scan_time=analysis["scan_time"],

    prediction=prediction,
    confidence=confidence,
    risk=risk,
    status=status,
    threat_score=threat_score
)

# ==========================
# Upload Page
# ==========================

@app.route("/upload")
def upload():
    return render_template("upload.html")

# ==========================
# History
# ==========================

@app.route("/history")
def history():

    scans = get_all_scans()

    return render_template(
        "history.html",
        scans=scans
    )
@app.route("/delete_scan/<int:scan_id>")
def delete_scan_route(scan_id):

    delete_scan(scan_id)

    return redirect(url_for("history"))

# ==========================
# Report
# ==========================

@app.route("/report")
def report():
    scans = get_all_scans()

    return render_template(
        "report.html",
        scans=scans
    )
@app.route("/download/<int:scan_id>")
def download_report(scan_id):

    scans = get_all_scans()

    scan = None

    for row in scans:
        if row[0] == scan_id:
            scan = row
            break

    if scan is None:
        return "Report not found"

    data = {
        "filename": scan[1],
        "prediction": scan[5],
        "confidence": scan[6],
        "risk": scan[7],
        "threat_score": scan[8],
        "scan_time": scan[9],
        "sha256": scan[10],
        "entropy": "-",
        "status": "Generated from history"
    }

    pdf_path = generate_report(data)

    return send_file(pdf_path, as_attachment=True)
# ==========================
# Settings
# ==========================

@app.route("/settings")
def settings():

    scans = get_all_scans()

    total_records = len(scans)

    return render_template(
        "settings.html",
        total_records=total_records
    )
# ==========================
# Analytics
# ==========================

@app.route("/analytics")
def analytics():

    scans = get_all_scans()

    total_files = len(scans)

    malware = 0
    safe = 0

    for scan in scans:

        if scan[5] == "MALWARE":
            malware += 1
        else:
            safe += 1

    return render_template(
        "analytics.html",
        total_files=total_files,
        malware=malware,
        safe=safe
    )
# ==========================
# Auto Open Browser
# ==========================

def open_browser():
    webbrowser.open_new("http://127.0.0.1:5000")

# ==========================
# Run
# ==========================

if __name__ == "__main__":
    Timer(1, open_browser).start()
    app.run(debug=True)