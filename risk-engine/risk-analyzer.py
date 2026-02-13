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

print("Risk Score:", risk_score)
print("Risk Level:", level)

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

print("Decision:", decision)
sys.exit(exit_code)

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
{decision}
</p>

<h2>Incident Summary</h2>
<p>{summary}</p>

</body>
</html>
"""

with open("reports/security-report.html", "w") as f:
    f.write(html)
