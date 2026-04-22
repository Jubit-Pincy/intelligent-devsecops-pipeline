from datetime import datetime, timezone, timedelta
import os, sys, json, requests

# ── CONFIG ──────────────────────────────────────────────────────────
def get_project_key():
    for path in [".sonarqube/out/.sonar/report-task.txt",
                 ".scannerwork/report-task.txt",
                 "target/sonar/report-task.txt"]:
        if os.path.exists(path):
            for line in open(path):
                if line.startswith("projectKey="):
                    return line.split("=", 1)[1].strip()
    return os.getenv("PROJECT_KEY", "DefaultProject")

PROJECT_KEY   = get_project_key()
SONAR_URL     = os.getenv("SONAR_URL", "https://sonarcloud.io")
SONAR_TOKEN   = os.getenv("SONAR_TOKEN")
PROJECT_REPO  = "https://github.com/Jubit-Pincy/intelligent-devsecops-pipeline"
RUNNING_APP   = "http://localhost:8081/"
IST           = timezone(timedelta(hours=5, minutes=30))

if not SONAR_TOKEN:
    print("ERROR: SONAR_TOKEN is not set"); sys.exit(1)

def sonar_get(path, params=None):
    r = requests.get(f"{SONAR_URL}{path}", params=params,
                     auth=(SONAR_TOKEN, ""), timeout=30)
    r.raise_for_status()
    return r.json()

# ── FETCH SUMMARY METRICS ────────────────────────────────────────────
metrics_resp = sonar_get("/api/measures/component", {
    "component": PROJECT_KEY,
    "metricKeys": "bugs,vulnerabilities,security_hotspots,code_smells,"
                  "coverage,duplicated_lines_density,ncloc",
    "branch": "main"
})
metrics_dict = {
    m["metric"]: m["value"]
    for m in metrics_resp.get("component", {}).get("measures", [])
}

def mi(key, default=0):
    try: return int(metrics_dict.get(key, default))
    except: return default

def mf(key, default=0.0):
    try: return float(metrics_dict.get(key, default))
    except: return default

bugs         = mi("bugs")
vulns        = mi("vulnerabilities")
hotspots     = mi("security_hotspots")
code_smells  = mi("code_smells")
coverage     = mf("coverage")
duplication  = mf("duplicated_lines_density")
ncloc        = mi("ncloc")

# ── FETCH ISSUE DETAILS ──────────────────────────────────────────────
def fetch_issues(types, severities=None, page_size=10):
    params = {
        "componentKeys": PROJECT_KEY,
        "types": types,
        "ps": page_size,
        "p": 1
    }
    if severities:
        params["severities"] = severities
    data = sonar_get("/api/issues/search", params)
    return data.get("issues", [])

bug_issues  = fetch_issues("BUG")
vuln_issues = fetch_issues("VULNERABILITY")

# Hotspots use a separate API
def fetch_hotspots(page_size=10):
    data = sonar_get("/api/hotspots/search", {
        "projectKey": PROJECT_KEY,
        "ps": page_size
    })
    return data.get("hotspots", [])

hotspot_issues = fetch_hotspots()

# ── WEIGHTS & RISK SCORE ─────────────────────────────────────────────
def safe_int(env_var, default):
    v = os.getenv(env_var, "")
    try: return int(v)
    except: return default

bugs_weight     = safe_int("WEIGHT_BUGS", 3)
vulns_weight    = safe_int("WEIGHT_VULNS", 5)
hotspots_weight = safe_int("WEIGHT_HOTSPOTS", 2)
risk_score = (bugs * bugs_weight) + (vulns * vulns_weight) + (hotspots * hotspots_weight)

# ── HISTORY & TREND ──────────────────────────────────────────────────
os.makedirs("reports", exist_ok=True)
history_file = "reports/history.json"
history = []
if os.path.exists(history_file):
    try:
        history = json.load(open(history_file))
    except: pass

previous_score = history[-1]["risk_score"] if history else None
if previous_score is None:
    trend = "First Analysis Run"
elif risk_score > previous_score:
    trend = "↑ Risk Increased"
elif risk_score < previous_score:
    trend = "↓ Risk Reduced"
else:
    trend = "→ Risk Stable"

history.append({
    "timestamp": datetime.now(IST).strftime("%d-%m-%Y %H:%M:%S"),
    "risk_score": risk_score
})
json.dump(history, open(history_file, "w"), indent=2)

# ── RISK CLASSIFICATION ──────────────────────────────────────────────
if risk_score <= 2:    level = "LOW"
elif risk_score <= 5:  level = "MEDIUM"
else:                  level = "HIGH"

if level == "HIGH":
    decision, exit_code = "BUILD BLOCKED DUE TO HIGH RISK", 1
elif level == "MEDIUM":
    if "Increased" in trend:
        decision, exit_code = "MANUAL SECURITY REVIEW REQUIRED (Risk Increasing)", 0
    else:
        decision, exit_code = "BUILD APPROVED WITH WARNINGS", 0
else:
    decision, exit_code = ("BUILD APPROVED - MONITOR RISK" if "Increased" in trend
                           else "BUILD APPROVED"), 0

print(f"Risk Score: {risk_score}  Level: {level}  Decision: {decision}")

# ── HTML HELPERS ──────────────────────────────────────────────────────
SEVERITY_COLOR = {
    "BLOCKER": "#e74c3c", "CRITICAL": "#e67e22",
    "MAJOR": "#f39c12",   "MINOR": "#3498db", "INFO": "#95a5a6"
}

def severity_badge(sev):
    color = SEVERITY_COLOR.get(sev.upper(), "#95a5a6")
    return (f'<span style="background:{color};color:white;padding:2px 8px;'
            f'border-radius:10px;font-size:11px;font-weight:600">{sev}</span>')

def issue_rows(issues, issue_type):
    if not issues:
        return ('<tr><td colspan="4" style="text-align:center;color:#888;'
                'padding:20px">No issues found ✓</td></tr>')
    rows = []
    for i in issues:
        sev   = i.get("severity", i.get("vulnerabilityProbability", "INFO"))
        msg   = i.get("message", "—")[:120]
        comp  = i.get("component", "—").split(":")[-1]
        line  = i.get("line", "—")
        rows.append(
            f"<tr>"
            f"<td>{severity_badge(sev)}</td>"
            f"<td style='font-family:monospace;font-size:13px'>{comp}</td>"
            f"<td style='text-align:center'>{line}</td>"
            f"<td>{msg}</td>"
            f"</tr>"
        )
    return "\n".join(rows)

def hotspot_rows(issues):
    if not issues:
        return ('<tr><td colspan="4" style="text-align:center;color:#888;'
                'padding:20px">No hotspots found ✓</td></tr>')
    rows = []
    for i in issues:
        prob  = i.get("vulnerabilityProbability", "LOW")
        msg   = i.get("message", "—")[:120]
        comp  = i.get("component", "—").split(":")[-1]
        line  = i.get("line", "—")
        rows.append(
            f"<tr>"
            f"<td>{severity_badge(prob)}</td>"
            f"<td style='font-family:monospace;font-size:13px'>{comp}</td>"
            f"<td style='text-align:center'>{line}</td>"
            f"<td>{msg}</td>"
            f"</tr>"
        )
    return "\n".join(rows)

def gauge_color(score):
    if score > 5: return "#e74c3c"
    if score > 2: return "#f39c12"
    return "#2ecc71"

history_labels = [e["timestamp"] for e in history]
history_scores = [e["risk_score"]  for e in history]
SONAR_DASH     = f"{SONAR_URL}/dashboard?id={PROJECT_KEY}"

# ── HTML REPORT ───────────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DevSecOps Security Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root {{
  --bg:#0f1117; --surface:#1a1d27; --surface2:#22263a;
  --accent:#4f8ef7; --green:#2ecc71; --yellow:#f39c12;
  --red:#e74c3c; --text:#e8eaf0; --muted:#8b90a0;
  --radius:12px; --shadow:0 4px 24px rgba(0,0,0,.4);
}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;padding:24px}}
a{{color:var(--accent);text-decoration:none}}

/* Layout */
.wrap{{max-width:1200px;margin:auto;display:flex;flex-direction:column;gap:20px}}

/* Header */
.header{{background:linear-gradient(135deg,#1f2d50,#2c3e6e);border-radius:var(--radius);padding:28px 32px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:16px;box-shadow:var(--shadow)}}
.header h1{{font-size:1.6rem;font-weight:700;letter-spacing:.5px}}
.header .meta{{font-size:.85rem;color:var(--muted);margin-top:6px}}

/* Risk badge in header */
.risk-pill{{padding:8px 20px;border-radius:30px;font-weight:700;font-size:1.1rem;letter-spacing:.5px}}
.risk-LOW{{background:rgba(46,204,113,.15);color:#2ecc71;border:2px solid #2ecc71}}
.risk-MEDIUM{{background:rgba(243,156,18,.15);color:#f39c12;border:2px solid #f39c12}}
.risk-HIGH{{background:rgba(231,76,60,.15);color:#e74c3c;border:2px solid #e74c3c}}

/* Cards row */
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:16px}}
.card{{background:var(--surface);border-radius:var(--radius);padding:20px;text-align:center;box-shadow:var(--shadow);border:1px solid rgba(255,255,255,.05)}}
.card .label{{font-size:.8rem;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:8px}}
.card .value{{font-size:2.2rem;font-weight:700}}
.card .sub{{font-size:.75rem;color:var(--muted);margin-top:4px}}

/* Two-column section */
.two-col{{display:grid;grid-template-columns:1fr 1fr;gap:20px}}
@media(max-width:768px){{.two-col{{grid-template-columns:1fr}}}}

/* Panel */
.panel{{background:var(--surface);border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);border:1px solid rgba(255,255,255,.05)}}
.panel h2{{font-size:1rem;font-weight:600;margin-bottom:16px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px}}

/* Decision banner */
.decision{{border-radius:var(--radius);padding:16px 24px;font-size:1rem;font-weight:600;margin-top:4px}}
.decision-LOW{{background:rgba(46,204,113,.1);border-left:4px solid #2ecc71;color:#2ecc71}}
.decision-MEDIUM{{background:rgba(243,156,18,.1);border-left:4px solid #f39c12;color:#f39c12}}
.decision-HIGH{{background:rgba(231,76,60,.1);border-left:4px solid #e74c3c;color:#e74c3c}}

/* Issue tables */
.issue-table{{width:100%;border-collapse:collapse;font-size:.85rem}}
.issue-table th{{background:var(--surface2);color:var(--muted);font-size:.75rem;text-transform:uppercase;letter-spacing:.7px;padding:10px 12px;text-align:left}}
.issue-table td{{padding:9px 12px;border-bottom:1px solid rgba(255,255,255,.04);vertical-align:top}}
.issue-table tr:last-child td{{border-bottom:none}}
.issue-table tr:hover td{{background:rgba(255,255,255,.03)}}

/* Tabs */
.tab-bar{{display:flex;gap:4px;margin-bottom:16px;background:var(--surface2);border-radius:8px;padding:4px}}
.tab{{flex:1;padding:8px;border:none;background:transparent;color:var(--muted);cursor:pointer;border-radius:6px;font-size:.85rem;font-weight:500;transition:.2s}}
.tab.active{{background:var(--accent);color:white}}

/* Links bar */
.links{{display:flex;gap:12px;flex-wrap:wrap}}
.btn{{padding:10px 18px;border-radius:8px;font-weight:600;font-size:.85rem;transition:.15s;display:inline-flex;align-items:center;gap:6px}}
.btn:hover{{opacity:.85;transform:translateY(-1px)}}
.btn-green{{background:#27ae60;color:white}}
.btn-blue{{background:#2980b9;color:white}}
.btn-dark{{background:#2c3e50;color:white}}

/* Gauge */
#gaugeWrap{{position:relative;width:220px;margin:auto}}
#gaugeScore{{position:absolute;bottom:10px;left:50%;transform:translateX(-50%);font-size:2.4rem;font-weight:700}}
</style>
</head>
<body>
<div class="wrap">

<!-- HEADER -->
<div class="header">
  <div>
    <h1>🛡️ DevSecOps Security Dashboard</h1>
    <div class="meta">Project: <b>{PROJECT_KEY}</b> &nbsp;|&nbsp; Generated: {datetime.now(IST).strftime("%d %b %Y, %H:%M:%S IST")}</div>
    <div class="meta" style="margin-top:4px">Trend: <b>{trend}</b></div>
  </div>
  <div>
    <div class="risk-pill risk-{level}">{level} RISK</div>
  </div>
</div>

<!-- DECISION BANNER -->
<div class="decision decision-{level}">⚡ {decision}</div>

<!-- METRIC CARDS -->
<div class="cards">
  <div class="card">
    <div class="label">Bugs</div>
    <div class="value" style="color:{'#e74c3c' if bugs>0 else '#2ecc71'}">{bugs}</div>
    <div class="sub">weight ×{bugs_weight}</div>
  </div>
  <div class="card">
    <div class="label">Vulnerabilities</div>
    <div class="value" style="color:{'#e74c3c' if vulns>0 else '#2ecc71'}">{vulns}</div>
    <div class="sub">weight ×{vulns_weight}</div>
  </div>
  <div class="card">
    <div class="label">Hotspots</div>
    <div class="value" style="color:{'#f39c12' if hotspots>0 else '#2ecc71'}">{hotspots}</div>
    <div class="sub">weight ×{hotspots_weight}</div>
  </div>
  <div class="card">
    <div class="label">Risk Score</div>
    <div class="value" style="color:{gauge_color(risk_score)}">{risk_score}</div>
    <div class="sub">computed</div>
  </div>
  <div class="card">
    <div class="label">Code Smells</div>
    <div class="value" style="color:var(--muted)">{code_smells}</div>
    <div class="sub">maintainability</div>
  </div>
  <div class="card">
    <div class="label">Coverage</div>
    <div class="value" style="color:{'#2ecc71' if coverage>=70 else '#f39c12'}">{coverage:.1f}%</div>
    <div class="sub">test coverage</div>
  </div>
  <div class="card">
    <div class="label">Duplication</div>
    <div class="value" style="color:{'#e74c3c' if duplication>10 else '#2ecc71'}">{duplication:.1f}%</div>
    <div class="sub">duplicated lines</div>
  </div>
  <div class="card">
    <div class="label">Lines of Code</div>
    <div class="value" style="font-size:1.5rem">{ncloc:,}</div>
    <div class="sub">ncloc</div>
  </div>
</div>

<!-- GAUGE + TREND CHART -->
<div class="two-col">
  <div class="panel">
    <h2>Risk Gauge</h2>
    <div id="gaugeWrap">
      <canvas id="riskGauge" height="130"></canvas>
      <div id="gaugeScore" style="color:{gauge_color(risk_score)}">{risk_score}</div>
    </div>
  </div>
  <div class="panel">
    <h2>Risk Trend</h2>
    <canvas id="riskChart" height="160"></canvas>
  </div>
</div>

<!-- ISSUE DETAILS TABS -->
<div class="panel">
  <h2>Issue Details</h2>
  <div class="tab-bar">
    <button class="tab active" onclick="showTab('bugs')">🐛 Bugs ({bugs})</button>
    <button class="tab" onclick="showTab('vulns')">🔓 Vulnerabilities ({vulns})</button>
    <button class="tab" onclick="showTab('hotspots')">🔥 Hotspots ({hotspots})</button>
  </div>

  <div id="tab-bugs">
    <table class="issue-table">
      <thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>{issue_rows(bug_issues, 'BUG')}</tbody>
    </table>
  </div>
  <div id="tab-vulns" style="display:none">
    <table class="issue-table">
      <thead><tr><th>Severity</th><th>File</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>{issue_rows(vuln_issues, 'VULNERABILITY')}</tbody>
    </table>
  </div>
  <div id="tab-hotspots" style="display:none">
    <table class="issue-table">
      <thead><tr><th>Priority</th><th>File</th><th>Line</th><th>Message</th></tr></thead>
      <tbody>{hotspot_rows(hotspot_issues)}</tbody>
    </table>
  </div>
</div>

<!-- LINKS -->
<div class="links">
  <a class="btn btn-green" href="{SONAR_DASH}" target="_blank">📊 SonarCloud Report</a>
  <a class="btn btn-blue" href="{RUNNING_APP}" target="_blank">🚀 Running App</a>
  <a class="btn btn-dark" href="{PROJECT_REPO}" target="_blank">📁 GitHub Repo</a>
</div>

</div>

<script>
/* ── Tab switching ── */
function showTab(name) {{
  ['bugs','vulns','hotspots'].forEach(t => {{
    document.getElementById('tab-'+t).style.display = t===name ? '' : 'none';
  }});
  document.querySelectorAll('.tab').forEach((btn,i) => {{
    btn.classList.toggle('active', ['bugs','vulns','hotspots'][i] === name);
  }});
}}

/* ── Gauge ── */
new Chart(document.getElementById('riskGauge'), {{
  type:'doughnut',
  data:{{
    datasets:[{{
      data:[{risk_score}, {max(0, 10-risk_score)}],
      backgroundColor:['{gauge_color(risk_score)}','#22263a'],
      borderWidth:0
    }}]
  }},
  options:{{circumference:180,rotation:270,cutout:'75%',plugins:{{legend:{{display:false}},tooltip:{{enabled:false}}}}}}
}});

/* ── Trend line ── */
new Chart(document.getElementById('riskChart'), {{
  type:'line',
  data:{{
    labels:{json.dumps(history_labels)},
    datasets:[{{
      label:'Risk Score',
      data:{json.dumps(history_scores)},
      borderColor:'#4f8ef7',
      backgroundColor:'rgba(79,142,247,.15)',
      tension:.35,fill:true,
      pointBackgroundColor:'#4f8ef7',
      pointRadius:4
    }}]
  }},
  options:{{
    responsive:true,
    plugins:{{legend:{{labels:{{color:'#8b90a0'}}}}}},
    scales:{{
      x:{{ticks:{{color:'#8b90a0'}},grid:{{color:'rgba(255,255,255,.05)'}}}},
      y:{{beginAtZero:true,ticks:{{color:'#8b90a0'}},grid:{{color:'rgba(255,255,255,.05)'}},suggestedMax:10}}
    }}
  }}
}});
</script>
</body>
</html>"""

with open("reports/security-report.html", "w") as f:
    f.write(html)

print(f"Report written → reports/security-report.html")
sys.exit(exit_code)