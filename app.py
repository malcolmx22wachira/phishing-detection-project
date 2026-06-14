from flask import Flask, render_template, request
from datetime import datetime
import os
import csv

from detection.url_parser import URLParser
from detection.rule_engine import RuleEngine

app = Flask(__name__)

# -------------------------
# HOME PAGE
# -------------------------
@app.route('/')
def home():
    return render_template('index.html')


# -------------------------
# ANALYSE ROUTE
# -------------------------
@app.route('/analyse', methods=['POST'])
def analyse():
    url = request.form['url']

    parser = URLParser()
    engine = RuleEngine()

    features = parser.parse(url)
    result = engine.analyse(features)

    os.makedirs("logs", exist_ok=True)
    log_file = os.path.join("logs", "analysis_log.csv")

    if not os.path.exists(log_file):
        with open(log_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["timestamp", "url", "verdict", "score", "triggered"])

    with open(log_file, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            datetime.now(),
            url,
            result["verdict"],
            result["score"],
            str(result["triggered"])
        ])

    return render_template(
        "result.html",
        verdict=result["verdict"],
        score=result["score"],
        triggered=result["triggered"]
    )


# -------------------------
# SIMULATION PAGE
# -------------------------
@app.route('/simulation')
def simulation():
    return render_template('simulation.html')


# -------------------------
# CAPTURE CREDENTIALS
# -------------------------
@app.route('/simulation/capture', methods=['POST'])
def capture():
    username = request.form['username']
    password = request.form['password']

    os.makedirs("logs", exist_ok=True)

    with open("logs/credentials.txt", "a", encoding="utf-8") as f:
        f.write(f"{datetime.now()} | {username} | {password}\n")

    return render_template("capture_result.html", username=username)


# -------------------------
# RUN APP
# -------------------------
if __name__ == "__main__":
    app.run(debug=True)