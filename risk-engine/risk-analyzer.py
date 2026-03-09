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
    "metricKeys": "bugs,vulnerabilities,security_hotspots",
    "branch": "main"
}

response = requests.get(url, params=params, auth=(SONAR_TOKEN, ""))
data = response.json()

measures = data["component"]["measures"]

bugs = int(measures[0]["value"])
vulns = int(measures[1]["value"])
hotspots = int(measures[2]["value"])
risk_score = bugs*3 + vulns*5 + hotspots*2

history_file = "reports/history.json"
history = []

# Ensure reports folder exists
os.makedirs("reports", exist_ok=True)

# Load history if exists
if os.path.exists(history_file):
    with open(history_file, "r") as f:
        try:
            history = json.load(f)
        except:
            history = []

# Determine previous score
previous_score = history[-1]["risk_score"] if history else None

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

# Append new record
history.append({
    "timestamp": datetime.now().strftime("%H:%M:%S"),
    "risk_score": risk_score
})

# Save updated history
with open(history_file, "w") as f:
    json.dump(history, f, indent=4)

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
# print("RAW SONAR RESPONSE:", data)


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

history_labels = [entry["timestamp"] for entry in history]
history_scores = [entry["risk_score"] for entry in history]

html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureApp Security Dashboard</title>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
body {{
    font-family: 'Segoe UI', Arial, sans-serif;
    background:#f4f6f9;
    margin:0;
    padding:30px;
}}

.container {{
    max-width:1100px;
    margin:auto;
}}

.header {{
    background:#1f2d3d;
    color:white;
    padding:20px;
    border-radius:8px;
}}

.cards {{
    display:flex;
    gap:20px;
    margin-top:20px;
}}

.card {{
    background:white;
    padding:20px;
    border-radius:8px;
    flex:1;
    box-shadow:0 2px 8px rgba(0,0,0,0.1);
    text-align:center;
}}

.metric {{
    font-size:28px;
    font-weight:bold;
}}

.low {{ color:#2ecc71; }}
.medium {{ color:#f39c12; }}
.high {{ color:#e74c3c; }}

.section {{
    background:white;
    margin-top:20px;
    padding:20px;
    border-radius:8px;
    box-shadow:0 2px 8px rgba(0,0,0,0.1);
}}

.decision {{
    font-size:20px;
    font-weight:bold;
}}
</style>
</head>

<body>

<div class="container">

<div class="header">
<h1>Executive Security Dashboard</h1>
<p><b>Project:</b> SecureApp</p>
<p><b>Generated:</b> {datetime.now()}</p>
</div>

<div class="cards">

<div class="card">
<h3>Bugs</h3>
<div class="metric">{bugs}</div>
</div>

<div class="card">
<h3>Vulnerabilities</h3>
<div class="metric">{vulns}</div>
</div>

<div class="card">
<h3>Security Hotspots</h3>
<div class="metric">{hotspots}</div>
</div>

<div class="card">
<h3>Risk Score</h3>
<div class="metric {level.lower()}">{risk_score}</div>
</div>

</div>

<div class="section">
<h2>Risk Evaluation</h2>

<p><b>Risk Level:</b>
<span class="{level.lower()}">{level}</span>
</p>

<p class="decision">{decision}</p>

<h3>Incident Summary</h3>
<p>{summary}</p>
</div>

<div class="section">
<h2>Risk Trend</h2>

<canvas id="riskChart"></canvas>

</div>

</div>

<script>
const ctx = document.getElementById('riskChart');

new Chart(ctx, {{
    type: 'line',
    data: {{
        labels: {history_labels},
        datasets: [{{
            label: 'Risk Score',
            data: {history_scores},
            borderColor: '#3498db',
            backgroundColor: 'rgba(52,152,219,0.2)',
            tension: 0.3,
            fill: true
        }}]
    }},
    options: {{
        responsive: true,
        scales: {{
            y: {{
                beginAtZero: true
            }}
        }}
    }}
}});
</script>

</body>
</html>
"""

print("SUMMARY:", summary)
with open("reports/security-report.html", "w") as f:
    f.write(html)
sys.exit(exit_code)
