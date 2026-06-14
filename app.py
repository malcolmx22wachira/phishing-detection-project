from flask import Flask, render_template, request
from datetime import datetime
import os
import csv

from detection.url_parser import URLParser
from detection.rule_engine import RuleEngine

app = Flask(__name__)


# =====================================
# HOME PAGE
# =====================================
@app.route('/')
def home():
    return render_template('index.html')


# =====================================
# URL ANALYSIS
# =====================================
@app.route('/analyse', methods=['POST'])
def analyse():

    url = request.form['url']

    parser = URLParser()
    engine = RuleEngine()

    features = parser.parse(url)
    result = engine.analyse(features)

    # Create logs folder if missing
    os.makedirs("logs", exist_ok=True)

    log_file = os.path.join("logs", "analysis_log.csv")

    # Create CSV if missing
    if not os.path.exists(log_file):
        with open(log_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp",
                "url",
                "verdict",
                "score",
                "triggered_rules"
            ])

    # Append analysis result
    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(),
            url,
            result["verdict"],
            result["score"],
            ", ".join(result["triggered"])
        ])

    return render_template(
        "result.html",
        verdict=result["verdict"],
        score=result["score"],
        triggered=result["triggered"]
    )


# =====================================
# PHISHING SIMULATION PAGE
# =====================================
@app.route('/simulation')
def simulation():
    return render_template('simulation.html')


# =====================================
# CAPTURE CREDENTIALS
# =====================================
@app.route('/simulation/capture', methods=['POST'])
def capture():

    username = request.form['username']
    password = request.form['password']

    os.makedirs("logs", exist_ok=True)

    credential_file = os.path.join(
        "logs",
        "credentials.txt"
    )

    with open(
        credential_file,
        "a",
        encoding="utf-8"
    ) as f:

        f.write(
            f"{datetime.now()} | "
            f"{username} | "
            f"{password}\n"
        )

    return render_template(
        "education.html",
        username=username
    )


# =====================================
# RUN APPLICATION
# =====================================
if __name__ == "__main__":
    app.run(debug=True)