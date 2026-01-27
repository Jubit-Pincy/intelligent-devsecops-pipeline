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
