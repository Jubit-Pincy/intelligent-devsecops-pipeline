"""
risk-analyzer.py
Intelligent Risk-Adaptive DevSecOps – Risk Engine v4
UI Updated to match the new Security Dashboard Design.
"""

from datetime import datetime, timezone, timedelta
import os, sys, json, requests

# ─────────────────────────────────────────────────
# Config
# ─────────────────────────────────────────────────
IST = timezone(timedelta(hours=5, minutes=30))

SONAR_URL      = os.getenv("SONAR_URL", "https://sonarcloud.io")
SONAR_TOKEN    = os.getenv("SONAR_TOKEN", "")
PROJECT_KEY    = os.getenv("PROJECT_KEY", "")
PROJECT_REPO   = os.getenv("GITHUB_REPO_URL",
                           "https://github.com/Jubit-Pincy/intelligent-devsecops-pipeline")
RUNNING_APP    = os.getenv("RUNNING_APP_URL", "http://localhost:8081/")
GITHUB_RUN_URL = os.getenv("GITHUB_RUN_URL", "#")

_raw_types = os.getenv("DETECTED_TYPES", '["unknown"]')
try:
    DETECTED_TYPES = json.loads(_raw_types)
except Exception:
    DETECTED_TYPES = [_raw_types]

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

SONAR_DASHBOARD = f"{SONAR_URL}/project/overview?id={PROJECT_KEY}"

if not SONAR_TOKEN:
    print("ERROR: SONAR_TOKEN not set.")
    sys.exit(1)

def get_safe_int(env_var, default):
    try:
        return int(os.getenv(env_var, ""))
    except (ValueError, TypeError):
        return default

WEIGHT_BUGS     = get_safe_int("WEIGHT_BUGS",     3)
WEIGHT_VULNS    = get_safe_int("WEIGHT_VULNS",     5)
WEIGHT_HOTSPOTS = get_safe_int("WEIGHT_HOTSPOTS",  2)

AUTH = (SONAR_TOKEN, "")

# ─────────────────────────────────────────────────
# SonarCloud API helpers
# ─────────────────────────────────────────────────
def sonar_get(endpoint, params=None):
    r = requests.get(f"{SONAR_URL}/api/{endpoint}",
                     params=params, auth=AUTH, timeout=30)
    r.raise_for_status()
    return r.json()

def fetch_summary_metrics():
    keys = ("bugs,vulnerabilities,security_hotspots,"
            "code_smells,coverage,duplicated_lines_density,"
            "reliability_rating,security_rating,sqale_rating,ncloc_language_distribution")
    data = sonar_get("measures/component", {
        "component": PROJECT_KEY,
        "metricKeys": keys,
        "branch": "main",
    })
    result = {}
    for m in data.get("component", {}).get("measures", []):
        metric_key = m["metric"]
        if metric_key == "ncloc_language_distribution":
            result[metric_key] = m.get("value", "")
        else:
            try:
                result[metric_key] = float(m["value"])
            except (KeyError, ValueError):
                result[metric_key] = 0
    return result

def fetch_issues(issue_types, ps=10, statuses=None):
    params = {
        "componentKeys": PROJECT_KEY,
        "types": issue_types,
        "ps": ps,
        "p": 1,
    }
    if statuses:
        params["statuses"] = statuses
    try:
        data = sonar_get("issues/search", params)
        return data.get("issues", [])
    except Exception as e:
        print(f"  Warning: could not fetch {issue_types} ({statuses}): {e}")
        return []

def fetch_hotspots(ps=10):
    try:
        data = sonar_get("hotspots/search", {
            "projectKey": PROJECT_KEY,
            "ps": ps,
            "p": 1,
            "status": "TO_REVIEW",
            "branch": "main",
        })
        return data.get("hotspots", [])
    except Exception as e:
        print(f"  Warning: could not fetch hotspots: {e}")
        return []

def get_line(issue: dict) -> str:
    line = issue.get("line")
    if line is not None:
        return str(line)
    text_range = issue.get("textRange") or {}
    start = text_range.get("startLine")
    if start is not None:
        return str(start)
    return "N/A"

def get_file(issue: dict) -> str:
    comp = issue.get("component", "")
    parts = comp.split(":", 1)
    if len(parts) == 2:
        return parts[1]
    return comp

# ─────────────────────────────────────────────────
# Fetch data
# ─────────────────────────────────────────────────
print("Fetching SonarCloud summary metrics …")
metrics = fetch_summary_metrics()

bugs_count      = int(metrics.get("bugs", 0))
vulns_count     = int(metrics.get("vulnerabilities", 0))
hotspots_count  = int(metrics.get("security_hotspots", 0))
smells_count    = int(metrics.get("code_smells", 0))
coverage_pct    = round(metrics.get("coverage", 0), 1)
duplication_pct = round(metrics.get("duplicated_lines_density", 0), 1)

# Parse language distribution
lang_dist_raw = metrics.get("ncloc_language_distribution", "")
language_data = []
if lang_dist_raw:
    for pair in lang_dist_raw.split(";"):
        if "=" in pair:
            lang, lines = pair.split("=", 1)
            language_data.append({"lang": lang, "lines": int(lines)})
    if language_data:
        DETECTED_TYPES = [item["lang"] for item in language_data]

def rating_label(val):
    return {1: "A", 2: "B", 3: "C", 4: "D", 5: "E"}.get(int(val), "?")

reliability_rating     = rating_label(metrics.get("reliability_rating", 1))
security_rating        = rating_label(metrics.get("security_rating", 1))
maintainability_rating = rating_label(metrics.get("sqale_rating", 1))

print(f"  Bugs={bugs_count}, Vulns={vulns_count}, Hotspots={hotspots_count}")

print("Fetching individual issue details …")
OPEN_STATUSES   = "OPEN,CONFIRMED,REOPENED"
CLOSED_STATUSES = "RESOLVED,CLOSED"

bug_issues        = fetch_issues("BUG",           ps=10, statuses=OPEN_STATUSES)
bug_issues_closed = fetch_issues("BUG",           ps=10, statuses=CLOSED_STATUSES)
vuln_issues       = fetch_issues("VULNERABILITY", ps=10, statuses=OPEN_STATUSES)
vuln_issues_closed= fetch_issues("VULNERABILITY", ps=10, statuses=CLOSED_STATUSES)
hotspot_list      = fetch_hotspots(ps=10)

# ─────────────────────────────────────────────────
# Risk scoring
# ─────────────────────────────────────────────────
risk_score = (bugs_count * WEIGHT_BUGS +
              vulns_count * WEIGHT_VULNS +
              hotspots_count * WEIGHT_HOTSPOTS)

level = "LOW" if risk_score <= 2 else "MEDIUM" if risk_score <= 5 else "HIGH"

print(f"Weights → Bugs:{WEIGHT_BUGS} Vulns:{WEIGHT_VULNS} Hotspots:{WEIGHT_HOTSPOTS}")
print(f"Risk Score: {risk_score}  Level: {level}")

# ─────────────────────────────────────────────────
# History & trend
# ─────────────────────────────────────────────────
os.makedirs("reports", exist_ok=True)
history_file = "reports/history.json"
history = []
if os.path.exists(history_file):
    try:
        with open(history_file) as f:
            history = json.load(f)
    except Exception:
        pass

prev = history[-1]["risk_score"] if history else None
if prev is None:
    trend = "First Run"
elif risk_score > prev:
    trend = "↑ Increasing"
elif risk_score < prev:
    trend = "↓ Decreasing"
else:
    trend = "→ Stable"

def _infer_level(score):
    if score <= 2:   return "LOW"
    if score <= 5:   return "MEDIUM"
    return "HIGH"

for entry in history:
    if not entry.get("level"):
        entry["level"] = _infer_level(entry.get("risk_score", 0))

history.append({
    "timestamp":  datetime.now(IST).strftime("%d-%m-%Y %H:%M"),
    "risk_score": risk_score,
    "level":      level,
})
with open(history_file, "w") as f:
    json.dump(history, f, indent=2)

# ─────────────────────────────────────────────────
# Adaptive decision
# ─────────────────────────────────────────────────
exit_code = 0
if level == "HIGH":
    decision  = "BUILD BLOCKED"
    exit_code = 1
elif level == "MEDIUM":
    decision = ("Conditional Approval"
                if "Increasing" not in trend else "Manual Review Required")
else:
    decision = "Approved"

print(f"Decision: {decision}  Trend: {trend}")

# ─────────────────────────────────────────────────
# Remediation guidance
# ─────────────────────────────────────────────────
RULE_ADVICE = {
    "squid:S2068":  ("Hard-coded credentials",
                     "Move secrets to environment variables or a secrets manager (e.g. AWS Secrets Manager, HashiCorp Vault). Never commit credentials to source control."),
    "squid:S2076":  ("OS command injection",
                     "Validate and sanitise all user-supplied input before passing it to shell commands. Prefer safe APIs over shell execution."),
    "squid:S2083":  ("Path traversal",
                     "Canonicalise file paths and verify they remain within the intended directory before opening files."),
    "squid:S3649":  ("SQL injection",
                     "Use parameterised queries or an ORM. Never build SQL strings by concatenating user input."),
    "squid:S5122":  ("CORS misconfiguration",
                     "Restrict CORS to specific, trusted origins. Avoid wildcard '*' in production."),
    "squid:S4790":  ("Weak hashing algorithm",
                     "Replace MD5 / SHA-1 with SHA-256 or stronger. Use bcrypt/argon2 for password hashing."),
    "squid:S2245":  ("Insecure random",
                     "Use a cryptographically secure RNG (e.g. java.security.SecureRandom, secrets module in Python) for security-sensitive values."),
    "squid:S2259":  ("Null dereference",
                     "Add null / None checks before dereferencing. Consider Optional types or null-safe operators."),
    "squid:S1751":  ("Unconditional break",
                     "Review loop logic. An unconditional break on the first iteration almost always indicates a logic bug."),
    "squid:S2201":  ("Return value ignored",
                     "Check the return value of methods that signal errors or state changes. Store or explicitly discard with a comment."),
    "squid:S138":   ("Method too long",
                     "Extract cohesive blocks into well-named private methods. Aim for methods under 30–40 lines."),
    "squid:S1192":  ("Duplicated string literal",
                     "Extract repeated string literals into named constants to reduce typo risk and ease future updates."),
}

GENERIC_ADVICE = {
    "BUG": (
        "General bug remediation",
        "Review the flagged code path carefully. Add unit tests that reproduce the issue, fix "
        "the root cause (not just the symptom), and verify no related paths are affected. "
        "Check SonarCloud's 'Why is this an issue?' section for rule-specific guidance."
    ),
    "VULNERABILITY": (
        "General vulnerability remediation",
        "Treat the issue as a security defect: assess exploitability, apply least-privilege "
        "principles, validate all inputs, and follow the OWASP remediation guidance linked in "
        "SonarCloud. Prioritise BLOCKER and CRITICAL severities first."
    ),
    "HOTSPOT": (
        "Security hotspot review",
        "Hotspots require manual review to determine exploitability. Read the flagged code in "
        "context, assess whether the risk is real, then either fix it or mark it 'Safe' with a "
        "written justification recorded in SonarCloud."
    ),
}

def get_advice(rule: str, issue_type: str) -> tuple:
    for prefix, advice in RULE_ADVICE.items():
        if rule.startswith(prefix) or rule == prefix:
            return advice
    return GENERIC_ADVICE.get(issue_type.upper(), ("Review required",
            "Consult the SonarCloud rule description for specific remediation steps."))

# ─────────────────────────────────────────────────
# HTML rendering helpers
# ─────────────────────────────────────────────────
def sev_badge(sev: str) -> str:
    s = (sev or "INFO").upper()
    fg = {
        "BLOCKER":  "#FF3B30",
        "CRITICAL": "#FF3B30",
        "MAJOR":    "#FFD60A",
        "MINOR":    "#5E9CFF",
        "INFO":     "#888888",
        "HIGH":     "#FF3B30",
        "MEDIUM":   "#FFD60A",
        "LOW":      "#15803D",
    }.get(s, "#888888")
    return f'<span class="badge" style="--badge-fg: {fg};">{s}</span>'

def issue_row(issue: dict, itype: str = "BUG", kind: str = "bugs", is_closed: bool = False) -> str:
    key        = issue.get("key", "")
    msg        = issue.get("message", "—")[:150]
    sev        = issue.get("severity", "INFO")
    rule       = issue.get("rule", "")
    status     = issue.get("status", "OPEN")
    resolution = issue.get("resolution", "")
    line       = get_line(issue)
    file       = get_file(issue)

    if is_closed:
        link = (f"{SONAR_URL}/project/issues?id={PROJECT_KEY}"
                f"&open={key}&statuses={status}&resolved=true")
        res_color = {
            "FIXED":         "#15803D",
            "FALSE-POSITIVE":"#6B6883",
            "WONTFIX":       "#B45309",
            "REMOVED":       "#6B6883",
        }.get(resolution.upper(), "#6B6883")
        res_html = f'<span class="res-chip" style="--res-fg:{res_color};">{resolution}</span>' if resolution else ''
        
        return f"""
        <tr class="closed-row" onclick="window.open('{link}', '_blank')">
          <td>{sev_badge(sev)}</td>
          <td>{msg}</td>
          <td>{res_html}</td>
          <td><span class="rule-code">{rule}</span></td>
        </tr>"""

    link = f"{SONAR_URL}/project/issues?id={PROJECT_KEY}&open={key}"
    adv_title, adv_body = get_advice(rule, itype)
    display_file = file.split("/")[-1] if file else "—"
    uid = f"fix-{key}"

    return f"""
<tr class="issue-row" onclick="toggleRow('{uid}')" id="row-{key}">
  <td>{sev_badge(sev)}</td>
  <td class="td-msg">{msg}</td>
  <td class="td-file"><a class="loc-link" href="{link}" target="_blank" onclick="event.stopPropagation();">{display_file}</a><span class="line-chip"><i class="fas fa-hashtag"></i>{line}</span></td>
  <td><span class="rule-code">{rule}</span></td>
  <td><span class="status-chip">{status}</span></td>
  <td class="td-expand"><span class="chevron">›</span></td>
</tr>
<tr class="fix-row" id="{uid}"><td class="fix-cell" colspan="6">
  <div class="fix-inner">
    <div class="fix-title"><i class="fas fa-wrench"></i> {adv_title}</div>
    <div class="fix-body">{adv_body}</div>
    <a class="fix-rule-link" href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}" target="_blank" onclick="event.stopPropagation();"><i class="fas fa-book"></i> View rule documentation</a>
    <div class="resolve-actions" role="group" aria-label="Resolve issue">
      <button class="resolve-btn resolve-btn-primary" onclick="resolveIssue('{key}','FIXED','{kind}',event)"><i class="fas fa-check"></i> Mark as Fixed</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','FALSE-POSITIVE','{kind}',event)"><i class="fas fa-circle-xmark"></i> False Positive</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','WONTFIX','{kind}',event)"><i class="fas fa-ban"></i> Won't Fix</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','CONFIRM','{kind}',event)"><i class="fas fa-flag"></i> Confirm</button>
    </div>
  </div>
</td></tr>"""

def hotspot_row(hs: dict, kind: str = "hotspots") -> str:
    key      = hs.get("key", "")
    msg      = hs.get("message", "—")[:150]
    prob     = hs.get("vulnerabilityProbability", "LOW")
    rule     = hs.get("ruleKey", "")
    line     = get_line(hs)
    file     = get_file(hs)

    link = f"{SONAR_URL}/project/security_hotspots?id={PROJECT_KEY}&hotspots={key}"
    adv_title, adv_body = get_advice(rule, "HOTSPOT")
    display_file = file.split("/")[-1] if file else "—"
    uid = f"fix-{key}"

    return f"""
<tr class="issue-row" onclick="toggleRow('{uid}')" id="row-{key}">
  <td>{sev_badge(prob)}</td>
  <td class="td-msg">{msg}</td>
  <td class="td-file"><a class="loc-link" href="{link}" target="_blank" onclick="event.stopPropagation();">{display_file}</a><span class="line-chip"><i class="fas fa-hashtag"></i>{line}</span></td>
  <td><span class="rule-code">{rule}</span></td>
  <td><span class="status-chip">TO_REVIEW</span></td>
  <td class="td-expand"><span class="chevron">›</span></td>
</tr>
<tr class="fix-row" id="{uid}"><td class="fix-cell" colspan="6">
  <div class="fix-inner">
    <div class="fix-title"><i class="fas fa-wrench"></i> {adv_title}</div>
    <div class="fix-body">{adv_body}</div>
    <a class="fix-rule-link" href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}" target="_blank" onclick="event.stopPropagation();"><i class="fas fa-book"></i> View rule documentation</a>
    <div class="resolve-actions" role="group" aria-label="Resolve issue">
      <button class="resolve-btn resolve-btn-primary" onclick="resolveIssue('{key}','FIXED','{kind}',event)"><i class="fas fa-check"></i> Mark as Fixed</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','FALSE-POSITIVE','{kind}',event)"><i class="fas fa-circle-xmark"></i> False Positive</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','WONTFIX','{kind}',event)"><i class="fas fa-ban"></i> Won't Fix</button>
      <button class="resolve-btn" onclick="resolveIssue('{key}','CONFIRM','{kind}',event)"><i class="fas fa-flag"></i> Confirm</button>
    </div>
  </div>
</td></tr>"""

def issues_table(rows_html: list, closed_rows_html: list, kind: str) -> str:
    thead_open = "<thead><tr><th>Severity</th><th>Issue</th><th>Location</th><th>Rule</th><th>Status</th><th></th></tr></thead>"
    thead_closed = "<thead><tr><th>Severity</th><th>Issue</th><th>Resolution</th><th>Rule</th></tr></thead>"

    if not rows_html and not closed_rows_html:
        return f'<div class="empty-msg">No {kind} detected — great work!</div>'

    open_block = ""
    if rows_html:
        open_block = f"""
<div class="table-wrap">
  <table class="issue-table">
    {thead_open}
    <tbody>{"".join(rows_html)}</tbody>
  </table>
</div>
<div class="table-note"><i class="fas fa-circle-info"></i> Click any row to view the suggested fix and resolution actions.</div>"""
    else:
        open_block = f'<div class="empty-msg">No open {kind} — great work!</div>'

    closed_block = ""
    if closed_rows_html:
        n = len(closed_rows_html)
        closed_block = f"""
<details class="closed-section" id="closed-{kind}">
  <summary class="closed-summary"><i class="fas fa-check-circle"></i> Resolved / Closed <span class="closed-count" id="closed-count-{kind}">{n}</span></summary>
  <div class="closed-table-wrap">
    <table class="issue-table">
      {thead_closed}
      <tbody id="closed-body-{kind}">{"".join(closed_rows_html)}</tbody>
    </table>
  </div>
</details>"""

    return open_block + closed_block

# Build HTML blocks
bug_rows          = [issue_row(i, "BUG", "bugs", is_closed=False) for i in bug_issues]
bug_rows_closed   = [issue_row(i, "BUG", "bugs", is_closed=True)  for i in bug_issues_closed]
vuln_rows         = [issue_row(i, "VULNERABILITY", "vulns", is_closed=False) for i in vuln_issues]
vuln_rows_closed  = [issue_row(i, "VULNERABILITY", "vulns", is_closed=True)  for i in vuln_issues_closed]
hs_rows           = [hotspot_row(h, "hotspots") for h in hotspot_list]

bugs_html     = issues_table(bug_rows,  bug_rows_closed,  "bugs")
vulns_html    = issues_table(vuln_rows, vuln_rows_closed, "vulns")
hotspots_html = issues_table(hs_rows,  [],               "hotspots")

# Chart data
h_labels = json.dumps([e["timestamp"]  for e in history])
h_scores = json.dumps([e["risk_score"] for e in history])
h_levels = json.dumps([e.get("level","") for e in history])
lang_chart_data = json.dumps(language_data)

# Misc
type_pills = "".join(f'<span class="type-pill">{t.upper()}</span>' for t in DETECTED_TYPES)

RISK_CSS_CLASS = {"LOW": "risk-low", "MEDIUM": "risk-med", "HIGH": "risk-high"}
risk_cls = RISK_CSS_CLASS.get(level, "risk-low")

decision_icon_cls = {
    "HIGH":   "fa-solid fa-circle-xmark",
    "MEDIUM": "fa-solid fa-triangle-exclamation",
    "LOW":    "fa-solid fa-circle-check",
}.get(level, "fa-solid fa-circle-check")

if level == "HIGH":
    summary_txt = (f"Risk exceeds acceptable thresholds. "
                   f"Immediate remediation required for {vulns_count} vulnerabilities and {bugs_count} bugs before deployment.")
elif level == "MEDIUM":
    summary_txt = (f"Risk is within tolerance but security findings require remediation before the next release. "
                   f"Schedule fixes for the {vulns_count} vulnerabilities and review the {hotspots_count} hotspots.")
else:
    summary_txt = (f"Build approved. Detected issues ({vulns_count} vulns, "
                   f"{bugs_count} bugs) are minimal and well within safety thresholds.")

now_str = datetime.now(IST).strftime("%b %d, %Y · %H:%M")

# ─────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Dashboard — {PROJECT_KEY}</title>
<meta name="description" content="Risk score, vulnerabilities, hotspots and code-quality metrics for {PROJECT_KEY}.">

<script>
(function () {{
  var saved = '';
  try {{ saved = localStorage.getItem('dso-theme') || ''; }} catch (e) {{}}
  if (!saved) saved = 'light';
  var resolved = saved;
  if (saved === 'system') {{
    try {{ resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'; }}
    catch (e) {{ resolved = 'light'; }}
  }}
  document.documentElement.setAttribute('data-theme', resolved);
  window.__dsoInitialTheme = resolved;
  window.__dsoSavedPref = saved;
}})();
</script>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js" id="chartjsScript"></script>

<style>
/* ═══════════════════════════════════════════════
   Design tokens — Warm off-white + Indigo (default)
═══════════════════════════════════════════════ */
:root {{
  color-scheme: light;
  --bg:         #F7F6F2;
  --bg2:        #FFFFFF;
  --bg3:        #EFEDE6;
  --border:     #E2DFD5;
  --border2:    #C9C5B6;
  --text:       #1A1830;
  --text2:      #4A4766;
  --text3:      #6B6883;
  --accent:     #4F46E5;
  --accent-s:   rgba(79, 70, 229, 0.08);
  --low-fg:     #15803D;  --low-bg:  rgba(21, 128, 61, 0.10);
  --med-fg:     #B45309;  --med-bg:  rgba(180, 83, 9, 0.10);
  --high-fg:    #B91C1C;  --high-bg: rgba(185, 28, 28, 0.10);
  --info-fg:    #1D4ED8;  --info-bg: rgba(29, 78, 216, 0.10);
  --fix-bg:     #FBFAF6;
  --fix-border: #E2DFD5;
  --mono: 'IBM Plex Mono', ui-monospace, monospace;
  --sans: 'Inter', system-ui, sans-serif;
  --r: 8px;
  --shadow: 0 1px 2px rgba(26,24,48,0.04), 0 4px 16px rgba(26,24,48,0.04);
}}

html[data-theme="dark"] {{
  color-scheme: dark;
  --bg:         #131322;
  --bg2:        #1B1B2E;
  --bg3:        #232338;
  --border:     #2D2D45;
  --border2:    #3F3F5A;
  --text:       #F1F1F7;
  --text2:      #C8C8D6;
  --text3:      #8B8BA3;
  --accent:     #A5B4FC;
  --accent-s:   rgba(165, 180, 252, 0.10);
  --low-fg:     #4ADE80;  --low-bg:  rgba(74, 222, 128, 0.12);
  --med-fg:     #FBBF24;  --med-bg:  rgba(251, 191, 36, 0.12);
  --high-fg:    #F87171;  --high-bg: rgba(248, 113, 113, 0.12);
  --info-fg:    #93C5FD;  --info-bg: rgba(147, 197, 253, 0.12);
  --fix-bg:     #1F1F33;
  --fix-border: #2D2D45;
  --shadow: 0 4px 12px rgba(0,0,0,0.5);
}}

*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
  transition: background .2s, color .2s;
}}

a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

:focus-visible {{ outline: 2px solid var(--accent); outline-offset: 2px; border-radius: 4px; }}

.skip-link {{
  position: absolute; left: -9999px; top: 8px;
  background: var(--accent); color: #fff;
  padding: 8px 14px; border-radius: 4px;
  font-family: var(--mono); font-size: 12px; z-index: 999;
}}
.skip-link:focus {{ left: 8px; }}

/* ───── Nav ───── */
.nav {{
  position: sticky; top: 0; z-index: 200;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 24px; height: 56px;
}}
.nav-brand {{
  font-family: var(--mono);
  font-size: 11px; font-weight: 600;
  color: var(--text);
  display: flex; align-items: center; gap: 10px;
  letter-spacing: .12em; text-transform: uppercase;
}}
.nav-brand i {{ color: var(--accent); font-size: 14px; }}
.status-dot {{
  width: 8px; height: 8px; border-radius: 50%;
  animation: pulse 2.4s ease-in-out infinite;
  flex-shrink: 0; margin-left: 4px;
}}
.status-dot.risk-low  {{ background: var(--low-fg); }}
.status-dot.risk-med  {{ background: var(--med-fg); }}
.status-dot.risk-high {{ background: var(--high-fg); }}
@keyframes pulse {{ 0%,100% {{opacity:1;transform:scale(1);}} 50% {{opacity:.4;transform:scale(1.4);}} }}
.nav-right {{ display: flex; align-items: center; gap: 12px; }}
.nav-ts {{ font-family: var(--mono); font-size: 11px; color: var(--text3); letter-spacing: .04em; }}
@media (max-width: 640px) {{ .nav-ts {{ display: none; }} }}

.theme-toggle {{
  display: flex; background: var(--bg3);
  border: 1px solid var(--border); border-radius: 6px;
  padding: 2px; gap: 2px;
}}
.theme-btn {{
  background: none; border: none; cursor: pointer;
  border-radius: 4px; color: var(--text3);
  display: flex; align-items: center; justify-content: center;
  width: 30px; height: 26px; flex-shrink: 0;
  transition: background .12s, color .12s;
}}
.theme-btn:hover {{ color: var(--text2); background: var(--border); }}
.theme-btn.active {{ background: var(--accent); color: #fff; }}
.theme-btn i {{ font-size: 12px; }}

/* ───── Hero ───── */
.hero {{
  padding: 56px 24px 40px;
  text-align: center;
  border-bottom: 1px solid var(--border);
  background: var(--bg2);
}}
.hero-title {{
  font-family: var(--mono);
  font-size: clamp(15px, 2.5vw, 22px);
  font-weight: 600; color: var(--text);
  letter-spacing: .08em; text-transform: uppercase;
  margin-bottom: 6px;
}}
.hero-sub {{
  color: var(--text3); font-size: 12px;
  margin-bottom: 22px; font-family: var(--mono);
  letter-spacing: .04em;
}}
.type-pills {{ display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; margin-bottom: 32px; }}
.type-pill {{
  background: var(--bg3); color: var(--text2);
  border: 1px solid var(--border); border-radius: 4px;
  padding: 3px 10px;
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  letter-spacing: .1em; text-transform: uppercase;
}}
.score-ring {{
  display: inline-flex; flex-direction: column; align-items: center;
  padding: 28px 60px; border-radius: 12px;
  border: 1px solid; margin-bottom: 16px;
}}
.score-ring.risk-low  {{ background: var(--low-bg);  border-color: var(--low-fg);  }}
.score-ring.risk-med  {{ background: var(--med-bg);  border-color: var(--med-fg);  }}
.score-ring.risk-high {{ background: var(--high-bg); border-color: var(--high-fg); }}
.score-num {{ font-family: var(--mono); font-size: 64px; font-weight: 600; line-height: 1; }}
.score-ring.risk-low  .score-num {{ color: var(--low-fg);  }}
.score-ring.risk-med  .score-num {{ color: var(--med-fg);  }}
.score-ring.risk-high .score-num {{ color: var(--high-fg); }}
.score-lbl {{ font-size: 9px; letter-spacing: .18em; margin-top: 6px; text-transform: uppercase; font-family: var(--mono); color: var(--text3); }}
.level-badge {{
  display: inline-block; font-family: var(--mono);
  font-size: 10px; font-weight: 600;
  letter-spacing: .16em; padding: 5px 18px;
  border-radius: 4px; border: 1px solid;
  text-transform: uppercase;
}}
.level-badge.risk-low  {{ color: var(--low-fg);  background: var(--low-bg);  border-color: var(--low-fg);  }}
.level-badge.risk-med  {{ color: var(--med-fg);  background: var(--med-bg);  border-color: var(--med-fg);  }}
.level-badge.risk-high {{ color: var(--high-fg); background: var(--high-bg); border-color: var(--high-fg); }}

/* ───── Page ───── */
.page {{ max-width: 1280px; margin: 0 auto; padding: 24px 20px 60px; }}
.card {{
  background: var(--bg2); border: 1px solid var(--border);
  border-radius: var(--r); padding: 22px; margin-bottom: 14px;
  box-shadow: var(--shadow);
}}
.card-title {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  letter-spacing: .16em; text-transform: uppercase;
  color: var(--text2); margin-bottom: 18px;
  display: flex; align-items: center; gap: 10px;
}}
.card-title::before {{
  content: ''; display: block;
  width: 3px; height: 12px; border-radius: 2px;
  background: var(--accent); flex-shrink: 0;
}}

/* ───── Metrics ───── */
.metric-grid {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px; margin-bottom: 14px;
}}
.metric-tile {{
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: var(--r); padding: 18px 14px;
  text-align: center;
  transition: transform .2s, border-color .2s, box-shadow .2s;
}}
.metric-tile:hover {{
  border-color: var(--accent); transform: translateY(-2px);
  box-shadow: var(--shadow);
}}
.metric-tile .m-val {{
  font-family: var(--mono); font-size: 30px; font-weight: 600;
  line-height: 1; margin-bottom: 6px;
}}
.m-bug   {{ color: var(--high-fg); }}
.m-vuln  {{ color: var(--high-fg); }}
.m-spot  {{ color: var(--med-fg); }}
.m-smell {{ color: var(--info-fg); }}
.m-cov   {{ color: var(--low-fg); }}
.m-dup   {{ color: var(--text3); }}
.metric-tile .m-lbl {{
  font-size: 9px; color: var(--text3);
  text-transform: uppercase; letter-spacing: .1em;
  font-family: var(--mono);
}}
.rating-row {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 10px;
}}
.rating-tile {{
  background: var(--bg3); border: 1px solid var(--border);
  border-radius: var(--r); padding: 14px; text-align: center;
}}
.rating-tile .r-val {{ font-family: var(--mono); font-size: 26px; font-weight: 600; }}
.r-A, .r-B {{ color: var(--low-fg); }}
.r-C       {{ color: var(--med-fg); }}
.r-D, .r-E {{ color: var(--high-fg); }}
.rating-tile .r-lbl {{
  font-size: 11px; color: var(--text3);
  text-transform: uppercase; letter-spacing: .1em;
  margin-top: 4px; font-family: var(--mono);
}}

/* ───── Decision ───── */
.decision-banner {{
  display: flex; align-items: flex-start; gap: 16px;
  padding: 16px 18px; border-radius: var(--r);
  border: 1px solid; margin-bottom: 12px;
}}
.decision-banner.risk-low  {{ background: var(--low-bg);  border-color: var(--low-fg);  }}
.decision-banner.risk-med  {{ background: var(--med-bg);  border-color: var(--med-fg);  }}
.decision-banner.risk-high {{ background: var(--high-bg); border-color: var(--high-fg); }}
.d-icon {{ font-size: 22px; flex-shrink: 0; line-height: 1.4; }}
.decision-banner.risk-low  .d-icon {{ color: var(--low-fg);  }}
.decision-banner.risk-med  .d-icon {{ color: var(--med-fg);  }}
.decision-banner.risk-high .d-icon {{ color: var(--high-fg); }}
.d-body {{ flex: 1; }}
.d-action {{
  font-family: var(--mono); font-size: 11px; font-weight: 600;
  letter-spacing: .1em; margin-bottom: 4px; text-transform: uppercase;
}}
.decision-banner.risk-low  .d-action {{ color: var(--low-fg);  }}
.decision-banner.risk-med  .d-action {{ color: var(--med-fg);  }}
.decision-banner.risk-high .d-action {{ color: var(--high-fg); }}
.d-summary {{ font-size: 13px; color: var(--text); line-height: 1.6; }}
.d-right {{ display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }}
.trend-chip {{
  font-family: var(--mono); font-size: 10px;
  padding: 4px 10px; border-radius: 4px;
  border: 1px solid var(--border);
  background: var(--bg2); color: var(--low-fg);
  white-space: nowrap; letter-spacing: .04em;
}}
.formula-line {{
  font-family: var(--mono); font-size: 11px;
  color: var(--text3); margin-top: 12px;
  padding: 12px 14px; background: var(--bg3);
  border-radius: var(--r); border: 1px solid var(--border);
  letter-spacing: .02em; line-height: 1.7;
}}

/* ───── Tabs ───── */
.tab-bar {{
  display: flex; gap: 2px;
  background: var(--bg3); border-radius: var(--r); padding: 3px;
  width: fit-content; margin-bottom: 18px;
  border: 1px solid var(--border);
}}
.tab-btn {{
  background: none; border: none; color: var(--text3);
  padding: 6px 14px; border-radius: 5px; cursor: pointer;
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  letter-spacing: .08em; display: flex; align-items: center; gap: 7px;
  transition: all .12s; text-transform: uppercase;
}}
.tab-btn.active {{ background: var(--accent); color: #fff; }}
.tab-btn:not(.active):hover {{ color: var(--text); background: var(--border); }}
.tab-badge {{
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 18px; height: 16px; border-radius: 3px; padding: 0 5px;
  font-size: 10px; font-weight: 700;
  background: rgba(0,0,0,0.08); color: inherit;
}}
html[data-theme="dark"] .tab-badge {{ background: rgba(255,255,255,0.10); }}
.tab-btn.active .tab-badge {{ background: rgba(255,255,255,0.25); color: #fff; }}
.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}

/* ───── Issue tables ───── */
.table-wrap {{ overflow-x: auto; }}
.issue-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
.issue-table thead th {{
  font-family: var(--mono); font-size: 9px; font-weight: 600;
  text-transform: uppercase; letter-spacing: .1em; color: var(--text3);
  padding: 10px 14px; border-bottom: 1px solid var(--border);
  text-align: left; background: var(--bg3); white-space: nowrap;
}}
.issue-table tbody .issue-row {{ cursor: pointer; transition: background .1s; }}
.issue-table tbody .issue-row:hover {{ background: var(--accent-s); }}
.issue-table tbody td {{
  padding: 12px 14px; border-bottom: 1px solid var(--border);
  color: var(--text); vertical-align: middle;
}}
.td-file {{ min-width: 140px; white-space: nowrap; }}
.td-msg  {{ min-width: 180px; color: var(--text); }}
.td-expand {{ width: 32px; text-align: center; }}
.loc-link {{
  font-family: var(--mono); font-size: 12px; font-weight: 600;
  color: var(--text); display: block; white-space: nowrap;
}}
.loc-link:hover {{ color: var(--accent); text-decoration: underline; }}
.line-chip {{
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono); font-size: 9px; font-weight: 600;
  color: var(--text3); margin-top: 3px;
  border: 1px solid var(--border); border-radius: 3px;
  padding: 1px 6px;
}}
.rule-code {{
  font-family: var(--mono); font-size: 10px;
  color: var(--text3); background: var(--bg3);
  border: 1px solid var(--border); border-radius: 3px;
  padding: 2px 6px; white-space: nowrap;
}}
.status-chip {{ font-family: var(--mono); font-size: 11px; color: var(--text3); }}
.chevron {{
  font-size: 16px; color: var(--text3);
  display: inline-block; transition: transform .2s; line-height: 1;
}}
.issue-row.expanded .chevron {{ transform: rotate(90deg); color: var(--accent); }}
.badge {{
  display: inline-block; font-family: var(--mono);
  font-size: 9px; font-weight: 700; letter-spacing: .08em;
  padding: 3px 8px; border-radius: 4px;
  color: var(--badge-fg);
  background: color-mix(in srgb, var(--badge-fg) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--badge-fg) 30%, transparent);
  text-transform: uppercase;
}}

/* Resolved chip */
.res-chip {{
  display: inline-block; font-family: var(--mono);
  font-size: 9px; font-weight: 700; letter-spacing: .06em;
  padding: 2px 7px; border-radius: 3px;
  color: var(--res-fg);
  background: color-mix(in srgb, var(--res-fg) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--res-fg) 28%, transparent);
  text-transform: uppercase;
}}

/* Fix drawer */
.fix-row {{ display: none; }}
.fix-row.open {{ display: table-row !important; }}
.fix-cell {{ padding: 0 !important; }}
.fix-inner {{
  padding: 16px 18px; background: var(--fix-bg);
  border-left: 3px solid var(--accent); border-bottom: 1px solid var(--border);
}}
.fix-title {{
  font-size: 11px; font-weight: 600; color: var(--text);
  margin-bottom: 8px; font-family: var(--mono);
  display: flex; align-items: center; gap: 8px;
  letter-spacing: .04em; text-transform: uppercase;
}}
.fix-title i {{ color: var(--accent); }}
.fix-body {{ font-size: 13px; color: var(--text2); line-height: 1.7; margin-bottom: 10px; }}
.fix-rule-link {{
  font-family: var(--mono); font-size: 10px; color: var(--text3);
  letter-spacing: .04em; display: inline-flex; align-items: center; gap: 6px;
}}
.fix-rule-link:hover {{ color: var(--accent); text-decoration: underline; }}

.table-note {{
  font-size: 11px; color: var(--text3); margin-top: 10px;
  font-style: italic; display: flex; align-items: center; gap: 6px;
}}
.empty-msg {{
  font-size: 12px; color: var(--text3); padding: 20px 0;
  font-style: italic; font-family: var(--mono); letter-spacing: .04em;
  text-align: center;
}}

/* Resolved section */
.closed-section {{
  margin-top: 14px; border: 1px solid var(--border);
  border-radius: var(--r); overflow: hidden;
}}
.closed-summary {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 16px; cursor: pointer;
  font-family: var(--mono); font-size: 10px; font-weight: 600;
  letter-spacing: .08em; color: var(--text2);
  background: var(--bg3); user-select: none;
  list-style: none; text-transform: uppercase;
}}
.closed-summary::-webkit-details-marker {{ display: none; }}
.closed-summary i {{ color: var(--low-fg); }}
.closed-summary::after {{
  content: '›'; margin-left: auto; font-size: 16px;
  color: var(--text3); transition: transform .2s;
}}
details[open] > .closed-summary::after {{ transform: rotate(90deg); }}
.closed-count {{
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 20px; height: 18px; border-radius: 3px; padding: 0 6px;
  font-size: 10px; font-weight: 700;
  background: color-mix(in srgb, var(--low-fg) 14%, transparent);
  color: var(--low-fg);
  border: 1px solid color-mix(in srgb, var(--low-fg) 30%, transparent);
}}
.closed-row td {{ opacity: 0.7; }}

/* Links */
.links-row {{
  display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}}
.lnk {{
  display: flex; align-items: center; justify-content: center; gap: 9px;
  padding: 14px 16px; border-radius: var(--r);
  font-family: var(--mono); font-size: 12px; font-weight: 600;
  letter-spacing: .08em;
  border: 1px solid var(--border); color: var(--text2);
  background: var(--bg3); transition: all .12s;
  text-align: center; text-transform: uppercase;
}}
.lnk i {{ font-size: 13px; color: var(--accent); }}
.lnk:hover {{ background: var(--bg2); border-color: var(--accent); color: var(--text); text-decoration: none; }}

/* Charts */
.chart-wrap {{ position: relative; height: 280px; }}
.chart-error {{
  height: 280px; display: flex; align-items: center; justify-content: center;
  font-family: var(--mono); font-size: 11px; color: var(--text3);
  border: 1px dashed var(--border); border-radius: var(--r);
  letter-spacing: .04em; text-align: center; padding: 0 24px;
}}
.lang-chart-container {{
  display: grid; grid-template-columns: 280px 1fr;
  gap: 28px; align-items: center;
}}
@media (max-width: 768px) {{ .lang-chart-container {{ grid-template-columns: 1fr; }} }}
.lang-chart-wrap {{ position: relative; height: 280px; display: flex; align-items: center; justify-content: center; }}
.lang-legend {{ display: flex; flex-direction: column; gap: 10px; }}
.lang-legend-item {{
  display: flex; align-items: center; gap: 12px;
  padding: 10px 12px; border-radius: var(--r);
  background: var(--bg3); border: 1px solid var(--border);
}}
.lang-color {{ width: 14px; height: 14px; border-radius: 3px; flex-shrink: 0; }}
.lang-info {{ flex: 1; display: flex; align-items: center; justify-content: space-between; gap: 12px; }}
.lang-name {{ font-family: var(--mono); font-size: 12px; font-weight: 600; color: var(--text); text-transform: uppercase; letter-spacing: .06em; }}
.lang-stats {{ display: flex; align-items: center; gap: 12px; font-family: var(--mono); font-size: 11px; color: var(--text3); }}
.lang-pct {{ font-weight: 600; color: var(--text2); }}

/* Resolve buttons */
.resolve-actions {{
  display: flex; gap: 8px; margin-top: 14px;
  padding-top: 12px; border-top: 1px solid var(--border);
  flex-wrap: wrap;
}}
.resolve-btn {{
  display: inline-flex; align-items: center; gap: 6px;
  padding: 7px 14px; border-radius: 5px;
  border: 1px solid var(--border); background: var(--bg2);
  color: var(--text2); font-family: var(--mono);
  font-size: 10px; font-weight: 600;
  letter-spacing: .04em; cursor: pointer;
  transition: all .12s; text-transform: uppercase;
}}
.resolve-btn:hover {{ background: var(--accent-s); color: var(--text); border-color: var(--accent); }}
.resolve-btn:disabled {{ opacity: 0.6; cursor: not-allowed; }}
.resolve-btn-primary {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
.resolve-btn-primary:hover {{ background: var(--accent); color: #fff; opacity: 0.9; }}

/* Footer */
.footer {{
  text-align: center; font-family: var(--mono); font-size: 10px;
  color: var(--text3); padding: 28px 0;
  letter-spacing: .08em; text-transform: uppercase;
}}
</style>
</head>
<body>

<a class="skip-link" href="#main">Skip to main content</a>

<nav class="nav" aria-label="Primary">
  <div class="nav-brand">
    <i class="fas fa-shield-halved" aria-hidden="true"></i>
    DevSecOps · Security Dashboard
    <span class="status-dot {risk_cls}" aria-label="Risk level {level}"></span>
  </div>
  <div class="nav-right">
    <span class="nav-ts">{now_str}</span>
    <div class="theme-toggle" id="themeToggle" role="radiogroup" aria-label="Theme">
      <button class="theme-btn" data-t="light"  onclick="setTheme('light')"  title="Light mode" role="radio" aria-checked="false" aria-label="Light mode"><i class="fa-solid fa-sun"></i></button>
      <button class="theme-btn" data-t="dark"   onclick="setTheme('dark')"   title="Dark mode"  role="radio" aria-checked="false" aria-label="Dark mode"><i class="fa-solid fa-moon"></i></button>
      <button class="theme-btn" data-t="system" onclick="setTheme('system')" title="System default" role="radio" aria-checked="false" aria-label="System theme"><i class="fa-solid fa-circle-half-stroke"></i></button>
    </div>
  </div>
</nav>

<header class="hero">
  <h1 class="hero-title">Security Risk Report</h1>
  <div class="hero-sub">Project · {PROJECT_KEY}</div>
  <div class="type-pills">{type_pills}</div>
  <div class="score-ring {risk_cls}" role="img" aria-label="Risk score {risk_score}, {level} risk">
    <div class="score-num">{risk_score}</div>
    <div class="score-lbl">Risk Score</div>
  </div>
  <br>
  <span class="level-badge {risk_cls}">{level} Risk</span>
</header>

<main class="page" id="main">

  <section class="card" aria-labelledby="ql-title">
    <h2 class="card-title" id="ql-title">Quick Links</h2>
    <div class="links-row">
      <a class="lnk" href="{SONAR_DASHBOARD}" target="_blank" rel="noreferrer"><i class="fas fa-shield-halved"></i> SonarCloud</a>
      <a class="lnk" href="{PROJECT_REPO}" target="_blank" rel="noreferrer"><i class="fas fa-code-branch"></i> Repository</a>
      <a class="lnk" href="{RUNNING_APP}" target="_blank" rel="noreferrer"><i class="fas fa-circle-play"></i> Application</a>
    </div>
  </section>

  <section class="card" aria-labelledby="lang-title">
    <h2 class="card-title" id="lang-title">Language Distribution</h2>
    <div class="lang-chart-container">
      <div class="lang-chart-wrap"><canvas id="langChart" aria-label="Language distribution chart"></canvas></div>
      <div id="langLegend" class="lang-legend"></div>
    </div>
  </section>

  <section class="card" aria-labelledby="m-title">
    <h2 class="card-title" id="m-title">Metrics Overview</h2>
    <div class="metric-grid">
      <div class="metric-tile"><div class="m-val m-bug">{bugs_count}</div><div class="m-lbl">Bugs</div></div>
      <div class="metric-tile"><div class="m-val m-vuln">{vulns_count}</div><div class="m-lbl">Vulnerabilities</div></div>
      <div class="metric-tile"><div class="m-val m-spot">{hotspots_count}</div><div class="m-lbl">Hotspots</div></div>
      <div class="metric-tile"><div class="m-val m-smell">{smells_count}</div><div class="m-lbl">Code Smells</div></div>
      <div class="metric-tile"><div class="m-val m-cov">{coverage_pct}%</div><div class="m-lbl">Coverage</div></div>
      <div class="metric-tile"><div class="m-val m-dup">{duplication_pct}%</div><div class="m-lbl">Duplication</div></div>
    </div>
    <div class="rating-row">
      <div class="rating-tile"><div class="r-val r-{reliability_rating}">{reliability_rating}</div><div class="r-lbl">Reliability</div></div>
      <div class="rating-tile"><div class="r-val r-{security_rating}">{security_rating}</div><div class="r-lbl">Security</div></div>
      <div class="rating-tile"><div class="r-val r-{maintainability_rating}">{maintainability_rating}</div><div class="r-lbl">Maintainability</div></div>
      <div class="rating-tile"><div class="r-val" style="color:var(--text);">{risk_score}</div><div class="r-lbl">Risk Score</div></div>
    </div>
  </section>

  <section class="card" aria-labelledby="dec-title">
    <h2 class="card-title" id="dec-title">Governance Decision</h2>
    <div class="decision-banner {risk_cls}">
      <div class="d-icon" aria-hidden="true"><i class="{decision_icon_cls}"></i></div>
      <div class="d-body">
        <div class="d-action">{decision}</div>
        <div class="d-summary">{summary_txt}</div>
      </div>
      <div class="d-right"><span class="trend-chip">{trend}</span></div>
    </div>
    <div class="formula-line">
      Risk = (Bugs × {WEIGHT_BUGS}) + (Vulns × {WEIGHT_VULNS}) + (Hotspots × {WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; ({bugs_count}×{WEIGHT_BUGS}) + ({vulns_count}×{WEIGHT_VULNS}) + ({hotspots_count}×{WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; <strong style="color:var(--text);">{risk_score}</strong>
    </div>
  </section>

  <section class="card" aria-labelledby="iss-title">
    <h2 class="card-title" id="iss-title">Issue Details</h2>
    <div class="tab-bar" role="tablist" aria-label="Issue category">
      <button class="tab-btn active" role="tab" aria-selected="true" aria-controls="tab-bugs" id="t-bugs" onclick="switchTab('bugs',this)"><span class="tab-badge" id="badge-bugs">{bugs_count}</span> Bugs</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-vulns" id="t-vulns" onclick="switchTab('vulns',this)"><span class="tab-badge" id="badge-vulns">{vulns_count}</span> Vulnerabilities</button>
      <button class="tab-btn" role="tab" aria-selected="false" aria-controls="tab-hotspots" id="t-hotspots" onclick="switchTab('hotspots',this)"><span class="tab-badge" id="badge-hotspots">{hotspots_count}</span> Hotspots</button>
    </div>
    <div id="tab-bugs"     class="tab-pane active" role="tabpanel" aria-labelledby="t-bugs">{bugs_html}</div>
    <div id="tab-vulns"    class="tab-pane"        role="tabpanel" aria-labelledby="t-vulns">{vulns_html}</div>
    <div id="tab-hotspots" class="tab-pane"        role="tabpanel" aria-labelledby="t-hotspots">{hotspots_html}</div>
  </section>

  <section class="card" aria-labelledby="trend-title">
    <h2 class="card-title" id="trend-title">Risk Score Trend</h2>
    <div class="chart-wrap"><canvas id="riskChart" aria-label="Risk score trend chart"></canvas></div>
  </section>

</main>

<div class="footer">Generated by Intelligent Risk-Adaptive DevSecOps · {now_str}</div>

<script>
/* Theme management */
var MEDIA = window.matchMedia('(prefers-color-scheme: dark)');
function resolveTheme(p) {{
  if (p === 'system') return MEDIA.matches ? 'dark' : 'light';
  return p || 'light';
}}
function syncToggleButtons(saved) {{
  document.querySelectorAll('.theme-btn').forEach(function(b) {{
    var active = b.dataset.t === saved;
    b.classList.toggle('active', active);
    b.setAttribute('aria-checked', active ? 'true' : 'false');
  }});
}}
function applyTheme(saved) {{
  var resolved = resolveTheme(saved);
  document.documentElement.setAttribute('data-theme', resolved);
  syncToggleButtons(saved);
  rebuildChart(resolved);
  rebuildLangChart();
}}
function setTheme(p) {{
  try {{ localStorage.setItem('dso-theme', p); }} catch(e) {{}}
  applyTheme(p);
}}
(function() {{
  var saved = window.__dsoSavedPref || 'light';
  syncToggleButtons(saved);
}})();
MEDIA.addEventListener('change', function() {{
  var saved = '';
  try {{ saved = localStorage.getItem('dso-theme') || ''; }} catch(e) {{}}
  if ((saved || 'light') === 'system') applyTheme('system');
}});

/* Tabs */
function switchTab(name, btn) {{
  document.querySelectorAll('.tab-pane').forEach(function(p) {{ p.classList.remove('active'); }});
  document.querySelectorAll('.tab-btn').forEach(function(b) {{
    b.classList.remove('active');
    b.setAttribute('aria-selected', 'false');
  }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  btn.setAttribute('aria-selected', 'true');
}}

/* Fix-row toggle */
function toggleRow(uid) {{
  var row  = document.getElementById(uid);
  var trig = row.previousElementSibling;
  var open = row.classList.contains('open');
  row.classList.toggle('open', !open);
  trig.classList.toggle('expanded', !open);
}}

/* Resolve actions — moves the row to the Resolved section in-page */
var RES_META = {{
  'FIXED':          {{label: 'Fixed',          color: '#15803D'}},
  'FALSE-POSITIVE': {{label: 'False Positive', color: '#6B6883'}},
  'WONTFIX':        {{label: "Won't Fix",      color: '#B45309'}},
  'CONFIRM':        {{label: 'Confirmed',      color: '#1D4ED8'}}
}};

function resolveIssue(issueKey, transition, kind, event) {{
  event.stopPropagation();
  var meta = RES_META[transition] || {{label: transition, color: '#6B6883'}};
  if (!confirm('Mark issue ' + issueKey + ' as "' + meta.label + '"?')) return;

  var btn = event.target.closest('.resolve-btn');
  if (btn) {{
    btn.disabled = true;
    var orig = btn.innerHTML;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing…';

    setTimeout(function() {{
      moveToResolved(issueKey, kind, meta);
      btn.disabled = false;
      btn.innerHTML = orig;
    }}, 350);
  }}
}}

function moveToResolved(issueKey, kind, meta) {{
  var row = document.getElementById('row-' + issueKey);
  var fixRow = document.getElementById('fix-' + issueKey);
  if (!row) return;

  // Build a minimal closed-row from the original row data
  var sevCell = row.cells[0].innerHTML;
  var msgCell = row.cells[1].textContent.trim();
  var ruleCell = row.cells[3].innerHTML;

  var closedBody = document.getElementById('closed-body-' + kind);
  if(!closedBody) return;
  var tr = document.createElement('tr');
  tr.className = 'closed-row';
  tr.innerHTML =
    '<td>' + sevCell + '</td>' +
    '<td>' + msgCell + '</td>' +
    '<td><span class="res-chip" style="--res-fg:' + meta.color + ';">' + meta.label + '</span></td>' +
    '<td>' + ruleCell + '</td>';
  closedBody.appendChild(tr);

  // Remove originals
  row.remove();
  if (fixRow) fixRow.remove();

  // Update counters
  var countEl = document.getElementById('closed-count-' + kind);
  if (countEl) countEl.textContent = String(parseInt(countEl.textContent || '0', 10) + 1);

  var badge = document.getElementById('badge-' + kind);
  if (badge) badge.textContent = String(Math.max(0, parseInt(badge.textContent, 10) - 1));

  // Open the resolved details so the user sees where it went
  var det = document.getElementById('closed-' + kind);
  if (det) det.open = true;
}}

/* Language doughnut */
var LANG_DATA = {lang_chart_data};
var langChartInstance = null;

function langPalette() {{
  var dark = document.documentElement.getAttribute('data-theme') === 'dark';
  return dark
    ? ['#A5B4FC','#93C5FD','#4ADE80','#FBBF24','#F87171','#C4B5FD']
    : ['#4F46E5','#1D4ED8','#15803D','#B45309','#B91C1C','#7C3AED'];
}}

function buildLangChart() {{
  if (!LANG_DATA || LANG_DATA.length === 0) return;
  var canvas = document.getElementById('langChart');
  if (!canvas || typeof Chart === 'undefined') return;
  var total = LANG_DATA.reduce(function(s,i) {{ return s + i.lines; }}, 0);
  var COLORS = langPalette();
  if (langChartInstance) {{ langChartInstance.destroy(); langChartInstance = null; }}
  langChartInstance = new Chart(canvas.getContext('2d'), {{
    type: 'doughnut',
    data: {{
      labels: LANG_DATA.map(function(i) {{ return i.lang.toUpperCase(); }}),
      datasets: [{{
        data: LANG_DATA.map(function(i) {{ return i.lines; }}),
        backgroundColor: LANG_DATA.map(function(_, idx) {{ return COLORS[idx % COLORS.length]; }}),
        borderWidth: 0
      }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false, cutout: '65%',
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: function(ctx) {{
              var pct = ((ctx.parsed/total)*100).toFixed(1);
              return ctx.label + ': ' + pct + '% (' + ctx.parsed.toLocaleString() + ' lines)';
            }}
          }}
        }}
      }}
    }}
  }});
  var legend = document.getElementById('langLegend');
  if (legend) {{
    legend.innerHTML = LANG_DATA.map(function(item, idx) {{
      var pct = ((item.lines/total)*100).toFixed(1);
      var color = COLORS[idx % COLORS.length];
      return '<div class="lang-legend-item">' +
        '<div class="lang-color" style="background:' + color + ';"></div>' +
        '<div class="lang-info">' +
        '<span class="lang-name">' + item.lang.toUpperCase() + '</span>' +
        '<div class="lang-stats"><span class="lang-pct">' + pct + '%</span>' +
        '<span>' + item.lines.toLocaleString() + ' lines</span></div>' +
        '</div></div>';
    }}).join('');
  }}
}}
function rebuildLangChart() {{ if (typeof Chart !== 'undefined') buildLangChart(); }}

/* Risk trend */
var CHART_DATA = {{ labels: {h_labels}, scores: {h_scores}, levels: {h_levels} }};
var chartInstance = null;
function levelColor(l, a) {{
  var k = (l||'').toUpperCase().trim();
  var dark = document.documentElement.getAttribute('data-theme') === 'dark';
  var map = dark
    ? {{ HIGH:'rgba(248,113,113,'+a+')', MEDIUM:'rgba(251,191,36,'+a+')', LOW:'rgba(74,222,128,'+a+')' }}
    : {{ HIGH:'rgba(185,28,28,'+a+')',   MEDIUM:'rgba(180,83,9,'+a+')',   LOW:'rgba(21,128,61,'+a+')' }};
  return map[k] || ('rgba(107,104,131,'+a+')');
}}
function buildChart(theme) {{
  var canvas = document.getElementById('riskChart');
  if (!canvas || typeof Chart === 'undefined') return;
  var isDark = theme === 'dark';
  var grid   = isDark ? 'rgba(255,255,255,0.06)' : 'rgba(0,0,0,0.06)';
  var tick   = isDark ? '#8B8BA3' : '#6B6883';
  var tipBg  = isDark ? '#1B1B2E' : '#FFFFFF';
  var tipBor = isDark ? '#2D2D45' : '#E2DFD5';
  var tipTx  = isDark ? '#F1F1F7' : '#1A1830';
  var tipMut = isDark ? '#C8C8D6' : '#4A4766';
  var line   = isDark ? '#A5B4FC' : '#4F46E5';
  var fill   = isDark ? 'rgba(165,180,252,0.10)' : 'rgba(79,70,229,0.10)';
  if (chartInstance) {{ chartInstance.destroy(); chartInstance = null; }}
  chartInstance = new Chart(canvas.getContext('2d'), {{
    type: 'line',
    data: {{
      labels: CHART_DATA.labels,
      datasets: [{{
        label: 'Risk Score', data: CHART_DATA.scores,
        borderColor: line, backgroundColor: fill,
        pointBackgroundColor: CHART_DATA.levels.map(function(l) {{ return levelColor(l, 1); }}),
        pointBorderColor: '#fff', pointBorderWidth: 1.5,
        pointRadius: 5, pointHoverRadius: 8,
        tension: 0.38, fill: true, borderWidth: 2
      }}]
    }},
    options: {{
      responsive: true, maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          backgroundColor: tipBg, borderColor: tipBor, borderWidth: 1,
          titleColor: tipTx, bodyColor: tipMut, padding: 10,
          callbacks: {{ afterBody: function(items) {{
            var l = (CHART_DATA.levels[items[0].dataIndex]||'').toUpperCase().trim();
            return ['Risk Level: ' + (l || 'UNKNOWN')];
          }} }}
        }}
      }},
      scales: {{
        x: {{ ticks: {{ color: tick, font: {{ family: "'IBM Plex Mono'", size: 10 }} }}, grid: {{ color: grid }}, border: {{ color: grid }} }},
        y: {{ beginAtZero: true, ticks: {{ color: tick, font: {{ family: "'IBM Plex Mono'", size: 10 }} }}, grid: {{ color: grid }}, border: {{ color: grid }} }}
      }}
    }}
  }});
}}
function rebuildChart(theme) {{ if (typeof Chart !== 'undefined') buildChart(theme); }}

(function initWhenReady() {{
  var MAX = 10000, start = Date.now();
  var theme = window.__dsoInitialTheme || 'light';
  function attempt() {{
    if (typeof Chart !== 'undefined') {{ buildChart(theme); buildLangChart(); return; }}
    if (Date.now() - start > MAX) {{
      var w = document.querySelector('.chart-wrap');
      if (w) w.innerHTML = '<div class="chart-error">Chart.js failed to load — check your network or CSP settings.</div>';
      return;
    }}
    setTimeout(attempt, 150);
  }}
  attempt();
}})();
</script>
</body>
</html>"""

with open("reports/security-report.html", "w") as f:
    f.write(html)

print("Report written → reports/security-report.html")
sys.exit(exit_code)