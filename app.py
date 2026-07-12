from flask import Flask, render_template, request
from datetime import datetime
import os
import csv
from urllib.parse import urlparse
from detection.url_parser import URLParser
from detection.rule_engine import RuleEngine


app = Flask(__name__)
def is_valid_url(url):
    """
    Returns True if the URL has:
    - http or https
    - a valid domain
    """

    try:
        parsed = urlparse(url)

        return (
            parsed.scheme in ("http", "https")
            and "." in parsed.netloc
            and len(parsed.netloc) > 3
        )

    except Exception:
        return False


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

    if not is_valid_url(url):
        return render_template(
            "index.html",
            error="Please enter a valid URL"
    )

    parser = URLParser()
    engine = RuleEngine()

    # Extract URL features
    features = parser.parse(url)

    # Run detection engine
    result = engine.analyse(features)
    print("========== DEBUG ==========")
    print(result)
    print("===========================")

    # Create logs folder if it doesn't exist
    os.makedirs("logs", exist_ok=True)

    log_file = os.path.join(
        "logs",
        "analysis_log.csv"
    )

    # Create CSV file if missing
    if not os.path.exists(log_file):
        with open(
            log_file,
            "w",
            newline="",
            encoding="utf-8"
        ) as f:

            writer = csv.writer(f)

            writer.writerow([
                "timestamp",
                "url",
                "verdict",
                "score",
                "triggered_rules"
            ])

    # Save analysis result
    with open(
        log_file,
        "a",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            datetime.now(),
            url,
            result["verdict"],
            result["score"],
            ", ".join(result["triggered"])
        ])

    # Generate recommendation based on verdict

    if result["verdict"].lower() == "phishing":

        recommendation = [
            "Do not visit this website.",
            "Do not enter usernames or passwords.",
            "Close the page immediately.",
            "Verify the website using its official domain.",
            "Report the suspicious website to your IT administrator or browser."
    ]

    else:

        recommendation = [
        "The website appears legitimate based on the   implemented rules.",
        "Always double-check the URL before entering personal information.",
        "Confirm that HTTPS is present.",
        "Keep your browser and antivirus software updated."
    ]

    return render_template(
       "result.html",
        verdict=result["verdict"],
        score=result["score"],
        triggered=result["triggered"],
        features=features,
        recommendation=recommendation
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
# =====================================
# VIEW ANALYSIS LOGS
# =====================================
@app.route("/logs")
def view_logs():

    log_file = os.path.join("logs", "analysis_log.csv")

    logs = []

    if os.path.exists(log_file):

        with open(log_file, newline="", encoding="utf-8") as csvfile:

            reader = csv.DictReader(csvfile)

            for row in reader:
                logs.append(row)

    return render_template(
        "logs.html",
        logs=logs
    )
if __name__ == "__main__":
    app.run(debug=True)