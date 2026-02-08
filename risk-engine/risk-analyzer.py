from datetime import datetime
import os
import requests
import sys

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

if risk_score == 0:
    level = "LOW"
elif risk_score <= 5:
    level = "MEDIUM"
else:
    level = "HIGH"

print("Risk Score:", risk_score)
print("Risk Level:", level)

if level == "HIGH":
    sys.exit(1)  # fail pipeline

os.makedirs("reports", exist_ok=True)

html = f"""
<html>
<head>
<title>Security Risk Report</title>
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
{"BUILD APPROVED" if level != "HIGH" else "BUILD BLOCKED DUE TO HIGH RISK"}
</p>

</body>
</html>
"""

with open("reports/security-report.html", "w") as f:
    f.write(html)
