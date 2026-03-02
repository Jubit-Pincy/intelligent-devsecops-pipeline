from datetime import datetime
import os
import requests
import sys
import json

SONAR_URL = "http://127.0.0.1:9000"
PROJECT_KEY = "SecureApp"
SONAR_TOKEN = os.getenv("SONAR_TOKEN")

url = f"{SONAR_URL}/api/measures/component"
params = {
    "component": PROJECT_KEY,
    "metricKeys": "bugs,vulnerabilities,security_hotspots"
}

response = requests.get(url, params=params, auth=(SONAR_TOKEN, ""))
data = response.json()

measures = data["component"]["measures"]

bugs = int(measures[0]["value"])
vulns = int(measures[1]["value"])
hotspots = int(measures[2]["value"])
risk_score = bugs*3 + vulns*5 + hotspots*2

history_file = "reports/history.json"
previous_score = None
trend = "N/A"

# Ensure reports folder exists
os.makedirs("reports", exist_ok=True)

# Load previous score if exists
if os.path.exists(history_file):
    with open(history_file, "r") as f:
        history = json.load(f)
        previous_score = history.get("last_risk_score")

# Determine trend
if previous_score is not None:
    if risk_score > previous_score:
        trend = "↑ Risk Increased"
    elif risk_score < previous_score:
        trend = "↓ Risk Reduced"
    else:
        trend = "→ Risk Stable"
else:
    trend = "First Analysis Run"

# Save current score for next build
with open(history_file, "w") as f:
    json.dump({"last_risk_score": risk_score}, f)

if risk_score == 0:
    level = "LOW"
elif risk_score <= 5:
    level = "MEDIUM"
else:
    level = "HIGH"

# --- Adaptive Decision Logic ---

if level == "HIGH":
    decision = "BUILD BLOCKED DUE TO HIGH RISK"
    exit_code = 1

elif level == "MEDIUM":
    if "Increased" in trend:
        decision = "MANUAL SECURITY REVIEW REQUIRED (Risk Increasing)"
        exit_code = 0
    else:
        decision = "BUILD APPROVED WITH WARNINGS"
        exit_code = 0

elif level == "LOW":
    if "Increased" in trend:
        decision = "BUILD APPROVED - MONITOR RISK (Increasing Trend)"
        exit_code = 0
    else:
        decision = "BUILD APPROVED"
        exit_code = 0

print("Risk Score:", risk_score)
print("Risk Level:", level)
print("Governance Action:", decision)
if level == "HIGH":
    decision = "BUILD BLOCKED DUE TO HIGH RISK"
    exit_code = 1
elif level == "MEDIUM":
    decision = "BUILD APPROVED WITH WARNINGS"
    exit_code = 0
else:
    decision = "BUILD APPROVED"
    exit_code = 0

os.makedirs("reports", exist_ok=True)

if level == "HIGH":
    summary = f"""
    This build was BLOCKED because the system detected
    {vulns} vulnerabilities, {bugs} bugs, and {hotspots} security hotspots.
    Immediate remediation is required before deployment.
    """
elif level == "MEDIUM":
    summary = f"""
    This build was approved with warnings due to
    {vulns} vulnerabilities, {bugs} bugs, and {hotspots} security hotspots.
    Manual review is recommended.
    """
else:
    summary = f"""
    This build was approved as the detected issues
    ({vulns} vulnerabilities, {bugs} bugs, {hotspots} hotspots)
    are within acceptable risk thresholds.
    """

print("Decision:", decision)
print("Risk Trend:", trend)

html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<title>Bug  Report</title>
<style>
body {{ font-family: Arial; padding: 20px; }}
h1 {{ color: #2c3e50; }}
.low {{ color: green; }}
.medium {{ color: orange; }}
.high {{ color: red; }}
</style>
</head>
<body>
<h1>Executive Security Report</h1>
<p><b>Project:</b> SecureApp</p>
<p><b>Generated at:</b> {datetime.now()}</p>

<h2>Findings</h2>
<ul>
  <li>Bugs: {bugs}</li>
  <li>Vulnerabilities: {vulns}</li>
  <li>Security Hotspots: {hotspots}</li>
</ul>

<h2>Risk Evaluation</h2>
<p><b>Risk Score:</b> {risk_score}</p>
<p><b>Risk Level:</b>
<span class="{level.lower()}">{level}</span>
</p>

<h2>Decision</h2>
<p>
{decision}
</p>

<h2>Incident Summary</h2>
<p>{summary}</p>

<h3>Risk Trend</h3>
<p>{trend}</p>

<h2>Governance Decision</h2>
<p><b>{decision}</b></p>

</body>
</html>
"""
print("SUMMARY:", summary)
with open("reports/security-report.html", "w") as f:
    f.write(html)
sys.exit(exit_code)
