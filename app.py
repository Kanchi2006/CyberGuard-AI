import smtplib
from email.mime.text import MIMEText
from flask import send_file
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
import re
import hashlib
from flask import session, redirect, url_for
from flask import Flask, render_template, request
import sqlite3

# Simple feature dataset
# Features: [length, has_https, has_at_symbol]
X = np.array([
    [20, 1, 0],
    [100, 0, 1],
    [80, 0, 1],
    [25, 1, 0],
    [70, 0, 0],
    [15, 1, 0]
])

# Labels: 0 = Safe, 1 = Phishing
y = np.array([0, 1, 1, 0, 1, 0])


app = Flask(__name__)
app.secret_key = "cyberguard_secret_key"

url_pattern = re.compile(
    r'^(https?:\/\/)?'        # http or https
    r'([\w\-]+\.)+[a-zA-Z]{2,}'  # domain name
)

def check_url(url):
    score = 0
    reasons = []

    if not url.startswith("https://"):
        score += 10
        reasons.append("Does not use HTTPS")

    if len(url) > 60:
        score += 15
        reasons.append("URL is too long")

    if "@" in url:
        score += 20
        reasons.append("Contains '@' symbol")

    suspicious_words = ["login", "verify", "bank", "update", "secure", "account"]
    if any(word in url.lower() for word in suspicious_words):
        score += 15
        reasons.append("Contains suspicious keywords")

    suspicious_domains = [".xyz", ".ru", ".tk", ".ml"]
    if any(domain in url for domain in suspicious_domains):
        score += 15
        reasons.append("Uses suspicious domain")

    if url.count('.') > 3:
        score += 10
        reasons.append("Too many subdomains")

    # Rule-based result
    if score <= 25:
        result = "SAFE"
    elif score <= 60:
        result = "SUSPICIOUS"
    else:
        result = "PHISHING"

    # ✅ ML Prediction (INSIDE function)
    length_feature = len(url)
    https_feature = 1 if url.startswith("https") else 0
    at_feature = 1 if "@" in url else 0

    
    
    if result.startswith("PHISHING"):
    	send_alert_email(url)
    return result, score, reasons
def send_alert_email(url):
    sender = "your_email@gmail.com"
    password = "your_app_password"
    receiver = "your_email@gmail.com"

    message = MIMEText(f"Phishing detected for URL: {url}")
    message["Subject"] = "CyberGuard Alert"
    message["From"] = sender
    message["To"] = receiver

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(sender, password)
        server.sendmail(sender, receiver, message.as_string())
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            result TEXT,
            score INTEGER
        )
    """)

    conn.commit()
    conn.close()

@app.route("/", methods=["GET", "POST"])
def home():
    if request.method == "POST":
        url = request.form["url"]

        # ✅ URL VALIDATION HERE (INSIDE FUNCTION)
        if not url_pattern.match(url):
            return render_template("result.html",
                                   result="INVALID URL",
                                   score=0,
                                   reasons=["Entered text is not a valid URL format."])

        result, score, reasons = check_url(url)

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (url, result, score) VALUES (?, ?, ?)",
            (url, result, score)
        )
        conn.commit()
        conn.close()

        return render_template("result.html",
                               result=result,
                               score=score,
                               reasons=reasons)

    return render_template("index.html")
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD_HASH = hashlib.sha256("admin123".encode()).hexdigest()
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        hashed_input = hashlib.sha256(password.encode()).hexdigest()

        if username == ADMIN_USERNAME and hashed_input == ADMIN_PASSWORD_HASH:
            session["admin"] = True
            return redirect(url_for("history"))
        else:
            return "Invalid Credentials!"

    return render_template("login.html")
@app.route("/history")
def history():
    if "admin" not in session:
        return redirect(url_for("login"))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans")
    data = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result='PHISHING'")
    total_phishing = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result='SUSPICIOUS'")
    total_suspicious = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM scans WHERE result='SAFE'")
    total_safe = cursor.fetchone()[0]

    conn.close()

    return render_template("history.html",
                           data=data,
                           total_scans=total_scans,
                           total_phishing=total_phishing,
                           total_suspicious=total_suspicious,
                           total_safe=total_safe)
@app.route("/download_report")
def download_report():
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    filename = "cyber_report.pdf"
    doc = SimpleDocTemplate(filename)
    elements = []

    styles = getSampleStyleSheet()
    elements.append(Paragraph("CyberGuard Scan Report", styles['Title']))
    elements.append(Spacer(1, 20))

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans")
    rows = cursor.fetchall()
    conn.close()

    for row in rows:
        elements.append(Paragraph(f"ID: {row[0]}", styles['Normal']))
        elements.append(Paragraph(f"URL: {row[1]}", styles['Normal']))
        elements.append(Paragraph(f"Result: {row[2]}", styles['Normal']))
        elements.append(Paragraph(f"Score: {row[3]}", styles['Normal']))
        elements.append(Spacer(1, 15))

    doc.build(elements)

    return send_file(filename, as_attachment=True)
@app.route("/logout")
def logout():
    session.pop("admin", None)
    return redirect(url_for("login"))	
if __name__ == "__main__":
    init_db()
    app.run(debug=True)