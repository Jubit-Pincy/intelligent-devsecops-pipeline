"""
risk-analyzer.py
Intelligent Risk-Adaptive DevSecOps – Risk Engine
Features:
  • Polyglot-aware (reads DETECTED_TYPES from env)
  • Fetches individual issue details (bugs, vulns, hotspots) from SonarCloud
  • Writes a rich, redesigned HTML security dashboard
"""

from datetime import datetime, timezone, timedelta
import os, sys, json, requests

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
IST = timezone(timedelta(hours=5, minutes=30))

SONAR_URL   = os.getenv("SONAR_URL", "https://sonarcloud.io")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
PROJECT_KEY = os.getenv("PROJECT_KEY", "")
SONAR_DASHBOARD = f"{SONAR_URL}/dashboard?id={PROJECT_KEY}"
PROJECT_REPO    = os.getenv("GITHUB_REPO_URL",
                            "https://github.com/Jubit-Pincy/intelligent-devsecops-pipeline")
RUNNING_APP     = os.getenv("RUNNING_APP_URL", "http://localhost:8081/")
GITHUB_RUN_URL  = os.getenv("GITHUB_RUN_URL", "#")

# Detected types comes as JSON array from GH Actions; fall back to env string
_raw_types = os.getenv("DETECTED_TYPES", '["unknown"]')
try:
    DETECTED_TYPES = json.loads(_raw_types)
except Exception:
    DETECTED_TYPES = [_raw_types]

# Try reading project key from report-task.txt (local Jenkins / CLI runs)
def _key_from_report():
    for path in (
        ".sonarqube/out/.sonar/report-task.txt",
        ".scannerwork/report-task.txt",
        "target/sonar/report-task.txt",
    ):
        if os.path.exists(path):
            with open(path) as f:
                for line in f:
                    if line.startswith("projectKey="):
                        return line.split("=", 1)[1].strip()
    return None

if not PROJECT_KEY:
    PROJECT_KEY = _key_from_report() or "DefaultProject"

if not SONAR_TOKEN:
    print("ERROR: SONAR_TOKEN not set.")
    sys.exit(1)


def get_safe_int(env_var, default):
    v = os.getenv(env_var, "")
    try:
        return int(v)
    except (ValueError, TypeError):
        return default


WEIGHT_BUGS     = get_safe_int("WEIGHT_BUGS",     3)
WEIGHT_VULNS    = get_safe_int("WEIGHT_VULNS",     5)
WEIGHT_HOTSPOTS = get_safe_int("WEIGHT_HOTSPOTS",  2)


# ─────────────────────────────────────────
# Sonar API helpers
# ─────────────────────────────────────────
AUTH = (SONAR_TOKEN, "")


def sonar_get(endpoint, params=None):
    r = requests.get(f"{SONAR_URL}/api/{endpoint}",
                     params=params, auth=AUTH, timeout=30)
    r.raise_for_status()
    return r.json()


def fetch_summary_metrics():
    """Return {bugs, vulnerabilities, security_hotspots, code_smells, coverage, duplicated_lines_density}."""
    keys = ("bugs,vulnerabilities,security_hotspots,"
            "code_smells,coverage,duplicated_lines_density,"
            "reliability_rating,security_rating,sqale_rating")
    data = sonar_get("measures/component", {
        "component": PROJECT_KEY,
        "metricKeys": keys,
        "branch": "main",
    })
    measures = data.get("component", {}).get("measures", [])
    result = {}
    for m in measures:
        try:
            result[m["metric"]] = float(m["value"])
        except (KeyError, ValueError):
            result[m["metric"]] = 0
    return result


def fetch_issues(issue_types, severity=None, ps=20):
    """
    Fetch individual issues from SonarCloud.
    issue_types: comma-separated string e.g. "BUG,VULNERABILITY"
    Returns list of issue dicts.
    """
    params = {
        "componentKeys": PROJECT_KEY,
        "types": issue_types,
        "ps": ps,
        "p": 1,
    }
    if severity:
        params["severities"] = severity

    try:
        data = sonar_get("issues/search", params)
        return data.get("issues", [])
    except Exception as e:
        print(f"  Warning: could not fetch issues ({issue_types}): {e}")
        return []


def fetch_hotspots(ps=20):
    """Fetch security hotspots (separate API from issues)."""
    params = {
        "projectKey": PROJECT_KEY,
        "ps": ps,
        "p": 1,
        "status": "TO_REVIEW",
        "branch": "main",
    }
    try:
        data = sonar_get("hotspots/search", params)
        return data.get("hotspots", [])
    except Exception as e:
        print(f"  Warning: could not fetch hotspots: {e}")
        return []


# ─────────────────────────────────────────
# Fetch data
# ─────────────────────────────────────────
print("Fetching SonarCloud metrics …")
metrics = fetch_summary_metrics()

bugs_count     = int(metrics.get("bugs", 0))
vulns_count    = int(metrics.get("vulnerabilities", 0))
hotspots_count = int(metrics.get("security_hotspots", 0))
smells_count   = int(metrics.get("code_smells", 0))
coverage_pct   = round(metrics.get("coverage", 0), 1)
duplication_pct = round(metrics.get("duplicated_lines_density", 0), 1)

# Rating helpers (1=A … 5=E)
def rating_label(val):
    return {1: "A", 2: "B", 3: "C", 4: "D", 5: "E"}.get(int(val), "?")

reliability_rating = rating_label(metrics.get("reliability_rating", 1))
security_rating    = rating_label(metrics.get("security_rating", 1))
maintainability_rating = rating_label(metrics.get("sqale_rating", 1))

print(f"  Bugs: {bugs_count}, Vulns: {vulns_count}, Hotspots: {hotspots_count}")

print("Fetching individual issue details …")
bug_issues   = fetch_issues("BUG",          ps=10)
vuln_issues  = fetch_issues("VULNERABILITY", ps=10)
hotspot_list = fetch_hotspots(ps=10)

# ─────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────
risk_score = (
    bugs_count     * WEIGHT_BUGS     +
    vulns_count    * WEIGHT_VULNS    +
    hotspots_count * WEIGHT_HOTSPOTS
)

if risk_score <= 2:
    level = "LOW"
elif risk_score <= 5:
    level = "MEDIUM"
else:
    level = "HIGH"

print(f"Weights → Bugs: {WEIGHT_BUGS}, Vulns: {WEIGHT_VULNS}, Hotspots: {WEIGHT_HOTSPOTS}")
print(f"Risk Score: {risk_score}")
print(f"Risk Level: {level}")

# ─────────────────────────────────────────
# History & Trend
# ─────────────────────────────────────────
os.makedirs("reports", exist_ok=True)
history_file = "reports/history.json"
history = []

if os.path.exists(history_file):
    try:
        with open(history_file) as f:
            history = json.load(f)
    except Exception:
        history = []

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
    "risk_score": risk_score,
    "level": level,
})

with open(history_file, "w") as f:
    json.dump(history, f, indent=2)

# ─────────────────────────────────────────
# Adaptive decision
# ─────────────────────────────────────────
exit_code = 0
if level == "HIGH":
    decision = "BUILD BLOCKED DUE TO HIGH RISK"
    exit_code = 1
elif level == "MEDIUM":
    decision = ("MANUAL SECURITY REVIEW REQUIRED (Risk Increasing)"
                if "Increased" in trend else "BUILD APPROVED WITH WARNINGS")
else:
    decision = ("BUILD APPROVED – MONITOR RISK (Increasing Trend)"
                if "Increased" in trend else "BUILD APPROVED")

print(f"Governance Action: {decision}")
print(f"Risk Trend: {trend}")


# ─────────────────────────────────────────
# HTML helpers
# ─────────────────────────────────────────
SEVERITY_COLOUR = {
    "BLOCKER":  "#e74c3c",
    "CRITICAL": "#e67e22",
    "MAJOR":    "#f1c40f",
    "MINOR":    "#3498db",
    "INFO":     "#95a5a6",
}

def severity_badge(sev):
    sev = (sev or "INFO").upper()
    col = SEVERITY_COLOUR.get(sev, "#95a5a6")
    return (f'<span style="background:{col};color:#fff;padding:2px 8px;'
            f'border-radius:3px;font-size:11px;font-weight:700;">{sev}</span>')

def issue_row(issue, link_type="issue"):
    """Render one table row for a bug or vulnerability."""
    key      = issue.get("key", "")
    msg      = issue.get("message", "—")[:120]
    sev      = issue.get("severity", "")
    comp     = issue.get("component", "").split(":")[-1]          # strip project prefix
    line     = issue.get("line", "")
    rule     = issue.get("rule", "")
    status   = issue.get("status", "OPEN")
    link     = f"{SONAR_DASHBOARD}&issues={key}"
    return f"""
<tr>
  <td><a href="{link}" target="_blank" title="View in SonarCloud"
         style="color:#3a86ff;text-decoration:none;">{comp}{f':{line}' if line else ''}</a></td>
  <td>{msg}</td>
  <td>{severity_badge(sev)}</td>
  <td><code style="font-size:11px;color:#888;">{rule}</code></td>
  <td><span style="font-size:11px;color:#aaa;">{status}</span></td>
</tr>"""

def hotspot_row(hs):
    """Render one table row for a security hotspot."""
    key      = hs.get("key", "")
    msg      = hs.get("message", "—")[:120]
    vuln_prob = hs.get("vulnerabilityProbability", "")
    comp     = hs.get("component", "").split(":")[-1]
    line     = hs.get("line", "")
    rule     = hs.get("ruleKey", "")
    link     = f"{SONAR_URL}/security_hotspots?id={PROJECT_KEY}&hotspots={key}"
    return f"""
<tr>
  <td><a href="{link}" target="_blank" style="color:#3a86ff;text-decoration:none;"
         >{comp}{f':{line}' if line else ''}</a></td>
  <td>{msg}</td>
  <td>{severity_badge(vuln_prob)}</td>
  <td><code style="font-size:11px;color:#888;">{rule}</code></td>
  <td><span style="font-size:11px;color:#aaa;">TO_REVIEW</span></td>
</tr>"""

def issues_table(rows_html, label, count, colour):
    if not rows_html:
        return f'<p style="color:#888;font-style:italic;">No {label} found.</p>'
    return f"""
<div style="margin-bottom:24px;">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:10px;">
    <span style="background:{colour};color:#fff;border-radius:50%;
                 width:26px;height:26px;display:flex;align-items:center;
                 justify-content:center;font-weight:700;font-size:13px;">{count}</span>
    <span style="font-weight:600;font-size:14px;">{label}</span>
    <span style="color:#888;font-size:12px;">(showing up to 10)</span>
  </div>
  <div style="overflow-x:auto;">
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="background:#f0f4ff;text-align:left;">
          <th style="padding:8px 12px;border-bottom:1px solid #dde3f0;">Location</th>
          <th style="padding:8px 12px;border-bottom:1px solid #dde3f0;">Message</th>
          <th style="padding:8px 12px;border-bottom:1px solid #dde3f0;">Severity</th>
          <th style="padding:8px 12px;border-bottom:1px solid #dde3f0;">Rule</th>
          <th style="padding:8px 12px;border-bottom:1px solid #dde3f0;">Status</th>
        </tr>
      </thead>
      <tbody>{"".join(rows_html)}</tbody>
    </table>
  </div>
</div>"""

# ─────────────────────────────────────────
# Build issue table HTML blocks
# ─────────────────────────────────────────
bug_rows      = [issue_row(i) for i in bug_issues]
vuln_rows     = [issue_row(i) for i in vuln_issues]
hotspot_rows  = [hotspot_row(h) for h in hotspot_list]

bugs_table_html     = issues_table(bug_rows,     "Bugs",                  bugs_count,     "#e74c3c")
vulns_table_html    = issues_table(vuln_rows,    "Vulnerabilities",       vulns_count,    "#e67e22")
hotspots_table_html = issues_table(hotspot_rows, "Security Hotspots",     hotspots_count, "#9b59b6")

# ─────────────────────────────────────────
# History chart data
# ─────────────────────────────────────────
history_labels = json.dumps([e["timestamp"] for e in history])
history_scores = json.dumps([e["risk_score"] for e in history])
history_levels = json.dumps([e.get("level", "") for e in history])

# ─────────────────────────────────────────
# Risk colours
# ─────────────────────────────────────────
RISK_BG   = {"LOW": "#0f4c2a", "MEDIUM": "#4a3000", "HIGH": "#4a0a0a"}
RISK_FG   = {"LOW": "#2ecc71", "MEDIUM": "#f39c12", "HIGH": "#e74c3c"}
RISK_GLOW = {"LOW": "rgba(46,204,113,0.3)", "MEDIUM": "rgba(243,156,18,0.3)", "HIGH": "rgba(231,76,60,0.3)"}

level_bg   = RISK_BG.get(level,   "#1a1f2e")
level_fg   = RISK_FG.get(level,   "#fff")
level_glow = RISK_GLOW.get(level, "transparent")

# Detected types pill string
type_pills_html = " ".join(
    f'<span style="background:#1e3a5f;color:#7ec8e3;border-radius:20px;'
    f'padding:3px 12px;font-size:12px;font-weight:600;">{t.upper()}</span>'
    for t in DETECTED_TYPES
)

# Decision colour
decision_fg = level_fg

# Summary sentence
if level == "HIGH":
    summary = (f"This build was <strong>BLOCKED</strong>: {vulns_count} vulnerabilities, "
               f"{bugs_count} bugs and {hotspots_count} security hotspots exceed acceptable thresholds. "
               f"Immediate remediation required.")
elif level == "MEDIUM":
    summary = (f"This build was <strong>approved with warnings</strong>: {vulns_count} vulnerabilities, "
               f"{bugs_count} bugs and {hotspots_count} hotspots were detected. Manual review recommended.")
else:
    summary = (f"This build was <strong>approved</strong>. The detected issues "
               f"({vulns_count} vulns, {bugs_count} bugs, {hotspots_count} hotspots) "
               f"are within acceptable risk thresholds.")

now_str = datetime.now(IST).strftime("%d %b %Y – %H:%M:%S IST")

# ─────────────────────────────────────────
# HTML template
# ─────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DevSecOps · Security Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"></script>
<style>
/* ── Reset & Base ─────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
  --bg:          #0d1117;
  --surface:     #161b22;
  --surface2:    #1c2433;
  --border:      rgba(255,255,255,0.08);
  --text:        #e6edf3;
  --muted:       #8b949e;
  --accent:      #3a86ff;
  --low:         #2ecc71;
  --medium:      #f39c12;
  --high:        #e74c3c;
  --risk-fg:     {level_fg};
  --risk-glow:   {level_glow};
  --mono:        'Space Mono', monospace;
  --sans:        'DM Sans', sans-serif;
  --radius:      12px;
}}
body {{
  background: var(--bg);
  color: var(--text);
  font-family: var(--sans);
  min-height: 100vh;
  padding: 0 0 60px;
}}

/* ── Top nav bar ──────────────────────────── */
.topbar {{
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 40px;
  height: 56px;
  position: sticky;
  top: 0;
  z-index: 100;
  backdrop-filter: blur(8px);
}}
.topbar-brand {{
  font-family: var(--mono);
  font-size: 14px;
  color: var(--accent);
  display: flex;
  align-items: center;
  gap: 8px;
}}
.topbar-brand .dot {{
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--risk-fg);
  box-shadow: 0 0 6px var(--risk-glow);
  animation: pulse 2s infinite;
}}
@keyframes pulse {{
  0%, 100% {{ opacity: 1; transform: scale(1); }}
  50%       {{ opacity: .6; transform: scale(1.3); }}
}}
.topbar-meta {{
  font-size: 12px;
  color: var(--muted);
  font-family: var(--mono);
}}

/* ── Hero ─────────────────────────────────── */
.hero {{
  background: linear-gradient(160deg, #0d1b35 0%, var(--bg) 60%);
  padding: 60px 40px 40px;
  text-align: center;
  border-bottom: 1px solid var(--border);
}}
.hero h1 {{
  font-family: var(--mono);
  font-size: clamp(22px, 4vw, 36px);
  color: var(--text);
  letter-spacing: -1px;
  margin-bottom: 8px;
}}
.hero .subtitle {{
  color: var(--muted);
  font-size: 14px;
  margin-bottom: 20px;
}}
.hero .type-pills {{ margin-bottom: 30px; display: flex; gap: 8px; justify-content: center; flex-wrap: wrap; }}

/* ── Risk Hero Card ───────────────────────── */
.risk-hero {{
  display: inline-flex;
  flex-direction: column;
  align-items: center;
  background: {level_bg};
  border: 2px solid {level_fg};
  border-radius: 20px;
  padding: 28px 60px;
  box-shadow: 0 0 40px {level_glow};
  margin-bottom: 16px;
}}
.risk-hero .score {{
  font-family: var(--mono);
  font-size: 72px;
  font-weight: 700;
  color: {level_fg};
  line-height: 1;
}}
.risk-hero .label {{
  font-size: 13px;
  letter-spacing: 3px;
  color: {level_fg};
  opacity: .7;
  margin-top: 4px;
  text-transform: uppercase;
}}
.risk-badge {{
  font-family: var(--mono);
  font-size: 18px;
  font-weight: 700;
  color: {level_fg};
  background: {level_bg};
  border: 1px solid {level_fg};
  border-radius: 30px;
  padding: 6px 24px;
  letter-spacing: 2px;
}}

/* ── Layout ───────────────────────────────── */
.page {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px 0; }}

/* ── Section ──────────────────────────────── */
.section {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 28px;
  margin-bottom: 24px;
}}
.section-title {{
  font-family: var(--mono);
  font-size: 13px;
  letter-spacing: 2px;
  text-transform: uppercase;
  color: var(--muted);
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  gap: 10px;
}}
.section-title::before {{
  content: '';
  display: block;
  width: 3px; height: 16px;
  border-radius: 2px;
  background: var(--accent);
}}

/* ── Metric Cards ─────────────────────────── */
.metric-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 16px;
}}
.metric-card {{
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px 16px;
  text-align: center;
  transition: border-color .2s, transform .2s;
}}
.metric-card:hover {{ border-color: var(--accent); transform: translateY(-2px); }}
.metric-card .val {{
  font-family: var(--mono);
  font-size: 36px;
  font-weight: 700;
  line-height: 1;
  margin-bottom: 6px;
}}
.metric-card .val.bug   {{ color: var(--high); }}
.metric-card .val.vuln  {{ color: #e67e22; }}
.metric-card .val.spot  {{ color: #9b59b6; }}
.metric-card .val.smell {{ color: var(--medium); }}
.metric-card .val.cov   {{ color: var(--accent); }}
.metric-card .val.dup   {{ color: var(--muted); }}
.metric-card .lbl {{
  font-size: 12px;
  color: var(--muted);
  text-transform: uppercase;
  letter-spacing: 1px;
}}

/* ── Rating badges ────────────────────────── */
.rating-row {{
  display: flex;
  gap: 16px;
  flex-wrap: wrap;
  margin-top: 16px;
}}
.rating-item {{
  flex: 1;
  min-width: 120px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
}}
.rating-item .rating-val {{
  font-family: var(--mono);
  font-size: 28px;
  font-weight: 700;
}}
.rating-A {{ color: #2ecc71; }}
.rating-B {{ color: #a8e063; }}
.rating-C {{ color: var(--medium); }}
.rating-D {{ color: #e67e22; }}
.rating-E {{ color: var(--high); }}
.rating-item .rating-lbl {{
  font-size: 11px;
  color: var(--muted);
  margin-top: 4px;
  text-transform: uppercase;
  letter-spacing: 1px;
}}

/* ── Decision banner ──────────────────────── */
.decision-banner {{
  background: {level_bg};
  border: 1px solid {level_fg};
  border-radius: 10px;
  padding: 18px 24px;
  display: flex;
  align-items: center;
  gap: 16px;
  margin-bottom: 16px;
}}
.decision-icon {{
  font-size: 28px;
  flex-shrink: 0;
}}
.decision-text {{ flex: 1; }}
.decision-text .action {{
  font-family: var(--mono);
  font-size: 13px;
  font-weight: 700;
  color: {level_fg};
  letter-spacing: 1px;
}}
.decision-text .summary {{
  font-size: 13px;
  color: var(--muted);
  margin-top: 4px;
  line-height: 1.6;
}}
.trend-chip {{
  font-family: var(--mono);
  font-size: 12px;
  padding: 4px 12px;
  border-radius: 20px;
  border: 1px solid var(--border);
  color: var(--muted);
  white-space: nowrap;
}}

/* ── Issues tables ────────────────────────── */
.issues-section table {{ width:100%; border-collapse:collapse; font-size:13px; }}
.issues-section th {{
  background: var(--surface2);
  padding: 10px 14px;
  text-align: left;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: 1px;
  color: var(--muted);
  border-bottom: 1px solid var(--border);
  font-family: var(--mono);
}}
.issues-section td {{
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
  color: var(--text);
}}
.issues-section tr:hover td {{ background: rgba(58,134,255,0.05); }}
.issues-section tr:last-child td {{ border-bottom: none; }}

/* Tab nav */
.tab-nav {{
  display: flex;
  gap: 2px;
  background: var(--surface2);
  border-radius: 8px;
  padding: 4px;
  margin-bottom: 20px;
  width: fit-content;
}}
.tab-btn {{
  background: none;
  border: none;
  color: var(--muted);
  padding: 6px 18px;
  border-radius: 6px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 1px;
  transition: all .2s;
  display: flex;
  align-items: center;
  gap: 6px;
}}
.tab-btn.active {{
  background: var(--surface);
  color: var(--text);
  box-shadow: 0 1px 4px rgba(0,0,0,.4);
}}
.tab-btn:hover:not(.active) {{ color: var(--text); }}
.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}
.count-dot {{
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 18px; height: 18px;
  border-radius: 50%;
  font-size: 10px;
  font-weight: 700;
}}

/* ── Chart ────────────────────────────────── */
.chart-wrap {{
  position: relative;
  height: 280px;
}}

/* ── Links ────────────────────────────────── */
.links-row {{
  display: flex;
  gap: 12px;
  flex-wrap: wrap;
}}
.btn-link {{
  display: inline-flex;
  align-items: center;
  gap: 8px;
  padding: 10px 20px;
  border-radius: 8px;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 1px;
  text-decoration: none;
  transition: opacity .2s, transform .15s;
  border: 1px solid var(--border);
}}
.btn-link:hover {{ opacity: .85; transform: translateY(-1px); }}
.btn-sonar {{ background: #1b4332; color: #2ecc71; border-color: #2ecc7144; }}
.btn-repo  {{ background: #1c2433; color: var(--accent); border-color: #3a86ff44; }}
.btn-app   {{ background: #2c1f4a; color: #a78bfa; border-color: #a78bfa44; }}
.btn-run   {{ background: #2c1a00; color: var(--medium); border-color: #f39c1244; }}

/* ── Footer ───────────────────────────────── */
.footer {{
  text-align: center;
  color: var(--muted);
  font-size: 12px;
  padding: 40px 24px 0;
  font-family: var(--mono);
}}
</style>
</head>
<body>

<!-- Top bar -->
<nav class="topbar">
  <div class="topbar-brand">
    <div class="dot"></div>
    DEVSECOPS · RISK DASHBOARD
  </div>
  <div class="topbar-meta">{now_str}</div>
</nav>

<!-- Hero -->
<div class="hero">
  <h1>Security Risk Report</h1>
  <p class="subtitle">Project: <strong style="color:var(--text);">{PROJECT_KEY}</strong></p>
  <div class="type-pills">{type_pills_html}</div>

  <div class="risk-hero">
    <div class="score">{risk_score}</div>
    <div class="label">Risk Score</div>
  </div>
  <br>
  <span class="risk-badge">{level} RISK</span>
</div>

<!-- Page content -->
<div class="page">

  <!-- Quick Links -->
  <div class="section">
    <div class="section-title">Quick Links</div>
    <div class="links-row">
      <a class="btn-link btn-sonar" href="{SONAR_DASHBOARD}" target="_blank">
        ⬡ SonarCloud Dashboard
      </a>
      <a class="btn-link btn-repo" href="{PROJECT_REPO}" target="_blank">
        ⌥ GitHub Repository
      </a>
      <a class="btn-link btn-app" href="{RUNNING_APP}" target="_blank">
        ▶ Running Application
      </a>
      <a class="btn-link btn-run" href="{GITHUB_RUN_URL}" target="_blank">
        ⚙ CI/CD Run
      </a>
    </div>
  </div>

  <!-- Metrics -->
  <div class="section">
    <div class="section-title">Metrics Overview</div>
    <div class="metric-grid">
      <div class="metric-card">
        <div class="val bug">{bugs_count}</div>
        <div class="lbl">Bugs</div>
      </div>
      <div class="metric-card">
        <div class="val vuln">{vulns_count}</div>
        <div class="lbl">Vulnerabilities</div>
      </div>
      <div class="metric-card">
        <div class="val spot">{hotspots_count}</div>
        <div class="lbl">Hotspots</div>
      </div>
      <div class="metric-card">
        <div class="val smell">{smells_count}</div>
        <div class="lbl">Code Smells</div>
      </div>
      <div class="metric-card">
        <div class="val cov">{coverage_pct}%</div>
        <div class="lbl">Coverage</div>
      </div>
      <div class="metric-card">
        <div class="val dup">{duplication_pct}%</div>
        <div class="lbl">Duplication</div>
      </div>
    </div>

    <div class="rating-row">
      <div class="rating-item">
        <div class="rating-val rating-{reliability_rating}">{reliability_rating}</div>
        <div class="rating-lbl">Reliability</div>
      </div>
      <div class="rating-item">
        <div class="rating-val rating-{security_rating}">{security_rating}</div>
        <div class="rating-lbl">Security</div>
      </div>
      <div class="rating-item">
        <div class="rating-val rating-{maintainability_rating}">{maintainability_rating}</div>
        <div class="rating-lbl">Maintainability</div>
      </div>
      <div class="rating-item">
        <div class="rating-val" style="font-size:18px;color:var(--accent);">{risk_score}</div>
        <div class="rating-lbl">Risk Score</div>
      </div>
    </div>
  </div>

  <!-- Decision -->
  <div class="section">
    <div class="section-title">Governance Decision</div>
    <div class="decision-banner">
      <div class="decision-icon">{'🚫' if level=='HIGH' else '⚠️' if level=='MEDIUM' else '✅'}</div>
      <div class="decision-text">
        <div class="action">{decision}</div>
        <div class="summary">{summary}</div>
      </div>
      <div class="trend-chip">{trend}</div>
    </div>
    <div style="font-size:12px;color:var(--muted);font-family:var(--mono);">
      Weights → Bugs×{WEIGHT_BUGS} + Vulns×{WEIGHT_VULNS} + Hotspots×{WEIGHT_HOTSPOTS} = <strong style="color:var(--text);">{risk_score}</strong>
    </div>
  </div>

  <!-- Issue Details -->
  <div class="section issues-section">
    <div class="section-title">Issue Details</div>

    <div class="tab-nav">
      <button class="tab-btn active" onclick="switchTab('bugs', this)">
        <span class="count-dot" style="background:#e74c3c22;color:#e74c3c;">{bugs_count}</span>
        BUGS
      </button>
      <button class="tab-btn" onclick="switchTab('vulns', this)">
        <span class="count-dot" style="background:#e67e2222;color:#e67e22;">{vulns_count}</span>
        VULNERABILITIES
      </button>
      <button class="tab-btn" onclick="switchTab('hotspots', this)">
        <span class="count-dot" style="background:#9b59b622;color:#9b59b6;">{hotspots_count}</span>
        HOTSPOTS
      </button>
    </div>

    <div id="tab-bugs" class="tab-pane active">
      {bugs_table_html}
    </div>
    <div id="tab-vulns" class="tab-pane">
      {vulns_table_html}
    </div>
    <div id="tab-hotspots" class="tab-pane">
      {hotspots_table_html}
    </div>
  </div>

  <!-- Trend chart -->
  <div class="section">
    <div class="section-title">Risk Score Trend</div>
    <div class="chart-wrap">
      <canvas id="riskChart"></canvas>
    </div>
  </div>

</div><!-- /page -->

<div class="footer">
  Generated by Intelligent Risk-Adaptive DevSecOps · {now_str}
</div>

<script>
/* ── Tab switching ──────────────────────────── */
function switchTab(name, btn) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}

/* ── Trend chart ────────────────────────────── */
const labels = {history_labels};
const scores = {history_scores};
const levels = {history_levels};

const pointColors = scores.map((_, i) => {{
  const l = levels[i];
  return l === 'HIGH' ? '#e74c3c' : l === 'MEDIUM' ? '#f39c12' : '#2ecc71';
}});

const ctx = document.getElementById('riskChart').getContext('2d');
new Chart(ctx, {{
  type: 'line',
  data: {{
    labels,
    datasets: [{{
      label: 'Risk Score',
      data: scores,
      borderColor: '#3a86ff',
      backgroundColor: 'rgba(58,134,255,0.08)',
      pointBackgroundColor: pointColors,
      pointBorderColor: pointColors,
      pointRadius: 6,
      pointHoverRadius: 9,
      tension: 0.35,
      fill: true,
    }}]
  }},
  options: {{
    responsive: true,
    maintainAspectRatio: false,
    plugins: {{
      legend: {{ display: false }},
      tooltip: {{
        backgroundColor: '#161b22',
        borderColor: 'rgba(255,255,255,0.1)',
        borderWidth: 1,
        titleColor: '#e6edf3',
        bodyColor: '#8b949e',
        callbacks: {{
          afterBody: (items) => {{
            const i = items[0].dataIndex;
            return ['Level: ' + (levels[i] || '?')];
          }}
        }}
      }}
    }},
    scales: {{
      x: {{
        ticks: {{ color: '#8b949e', font: {{ family: 'Space Mono', size: 10 }} }},
        grid:  {{ color: 'rgba(255,255,255,0.04)' }},
      }},
      y: {{
        beginAtZero: true,
        ticks: {{ color: '#8b949e', font: {{ family: 'Space Mono', size: 11 }} }},
        grid:  {{ color: 'rgba(255,255,255,0.06)' }},
      }}
    }}
  }}
}});
</script>
</body>
</html>
"""

with open("reports/security-report.html", "w") as f:
    f.write(html)

print(f"HTML report written → reports/security-report.html")
sys.exit(exit_code)