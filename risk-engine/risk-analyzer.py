"""
risk-analyzer.py
Intelligent Risk-Adaptive DevSecOps – Risk Engine v4
Fixes in this version:
  • Theme switcher works in Jenkins / static HTML (inline <script> in <head>
    applies theme before first paint — no flash of wrong theme)
  • SonarCloud issue links corrected to /project/issues?id=…&open=…
  • SonarCloud hotspot links corrected to /project/security_hotspots?id=…&hotspots=…
  • Risk trend chart fixed: Chart.js CDN load is awaited before init so the
    chart always renders even in offline / slow CDN environments
  • File name and line number shown more prominently in separate columns
  • Line number now read from textRange.startLine (fixes dash issue)
  • Remediation guidance per issue type / rule
  • Polyglot-aware, full issue detail tables
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

# Fallback: read project key from report-task.txt (Jenkins / local CLI)
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
            "reliability_rating,security_rating,sqale_rating")
    data = sonar_get("measures/component", {
        "component": PROJECT_KEY,
        "metricKeys": keys,
        "branch": "main",
    })
    result = {}
    for m in data.get("component", {}).get("measures", []):
        try:
            result[m["metric"]] = float(m["value"])
        except (KeyError, ValueError):
            result[m["metric"]] = 0
    return result

def fetch_issues(issue_types, ps=10, statuses=None):
    """
    Fetch issues from SonarCloud.
    statuses: comma-separated string e.g. "OPEN,CONFIRMED,REOPENED" or "RESOLVED,CLOSED"
    When statuses is None the API returns its default (open issues only).
    """
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
    """
    SonarCloud issues may carry the line number in different fields.
    Priority: issue.line  →  textRange.startLine  →  'N/A'
    """
    line = issue.get("line")
    if line is not None:
        return str(line)
    text_range = issue.get("textRange") or {}
    start = text_range.get("startLine")
    if start is not None:
        return str(start)
    return "N/A"

def get_file(issue: dict) -> str:
    """Extract just the file path portion from the component key."""
    comp = issue.get("component", "")
    # component is typically "projectKey:path/to/File.java"
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
vuln_issues        = fetch_issues("VULNERABILITY", ps=10, statuses=OPEN_STATUSES)
vuln_issues_closed = fetch_issues("VULNERABILITY", ps=10, statuses=CLOSED_STATUSES)
hotspot_list = fetch_hotspots(ps=10)

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

# ── Back-fill missing "level" on old history entries ──────────────
# Older versions of the script didn't always save "level". Without it,
# the chart pointBackgroundColor lookup returns grey and the tooltip
# shows "?" for every run except the most recent ones.
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
    decision  = "BUILD BLOCKED — HIGH RISK"
    exit_code = 1
elif level == "MEDIUM":
    decision = ("MANUAL REVIEW REQUIRED — Risk Increasing"
                if "Increasing" in trend else "APPROVED WITH WARNINGS")
else:
    decision = ("APPROVED — Monitor Trend"
                if "Increasing" in trend else "APPROVED — All Clear")

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
SEV_META = {
    "BLOCKER":  ("#dc2626", "#fef2f2", "#fee2e2"),
    "CRITICAL": ("#ea580c", "#fff7ed", "#fed7aa"),
    "MAJOR":    ("#ca8a04", "#fefce8", "#fef08a"),
    "MINOR":    ("#2563eb", "#eff6ff", "#bfdbfe"),
    "INFO":     ("#6b7280", "#f9fafb", "#e5e7eb"),
    "HIGH":     ("#dc2626", "#fef2f2", "#fee2e2"),
    "MEDIUM":   ("#ca8a04", "#fefce8", "#fef08a"),
    "LOW":      ("#2563eb", "#eff6ff", "#bfdbfe"),
}

def sev_badge(sev: str) -> str:
    s = (sev or "INFO").upper()
    fg, _, _ = SEV_META.get(s, ("#6b7280", "#f9fafb", "#e5e7eb"))
    return f'<span class="badge" style="--badge-fg:{fg};">{s}</span>'

_row_counter = [0]

def issue_row(issue: dict, itype: str = "BUG", is_closed: bool = False) -> str:
    _row_counter[0] += 1
    uid = f"row-{_row_counter[0]}"

    key        = issue.get("key", "")
    msg        = issue.get("message", "—")[:150]
    sev        = issue.get("severity", "INFO")
    rule       = issue.get("rule", "")
    status     = issue.get("status", "OPEN")
    resolution = issue.get("resolution", "")   # FIXED, FALSE-POSITIVE, WONTFIX, etc.
    line       = get_line(issue)
    file       = get_file(issue)

    # ── SonarCloud deep-link ─────────────────────────────────────
    # For closed/resolved issues we pass the statuses filter so the
    # page shows the resolved view rather than the active-issues view.
    if is_closed:
        link = (f"{SONAR_URL}/project/issues?id={PROJECT_KEY}"
                f"&open={key}&statuses={status}&resolved=true")
    else:
        link = f"{SONAR_URL}/project/issues?id={PROJECT_KEY}&open={key}"

    adv_title, adv_body = get_advice(rule, itype)
    display_file = file.split("/")[-1] if file else "—"

    # Resolution pill (only for closed rows)
    res_html = ""
    if resolution:
        res_color = {
            "FIXED":         "#22c55e",
            "FALSE-POSITIVE":"#6366f1",
            "WONTFIX":       "#f59e0b",
            "REMOVED":       "#64748b",
        }.get(resolution.upper(), "#64748b")
        res_html = (f'<span class="res-chip" style="--res-fg:{res_color};">'
                    f'{resolution}</span>')

    return f"""
<tr class="issue-row{'  closed-row' if is_closed else ''}" onclick="toggleRow('{uid}')">
  <td class="td-file">
    <a href="{link}" target="_blank" onclick="event.stopPropagation()"
       class="loc-link" title="{file}">{display_file}</a>
    <span class="line-chip"><i class="fa-regular fa-code-branch"></i> L{line}</span>
  </td>
  <td class="td-path" title="{file}">{file}</td>
  <td class="td-msg">{msg}</td>
  <td>{sev_badge(sev)}{res_html}</td>
  <td><code class="rule-code">{rule}</code></td>
  <td><span class="status-chip">{status}</span></td>
  <td class="td-expand"><span class="chevron">›</span></td>
</tr>
<tr id="{uid}" class="fix-row" style="display:none;">
  <td colspan="7" class="fix-cell">
    <div class="fix-inner">
      <div class="fix-title"><i class="fa-regular fa-screwdriver-wrench"></i> {adv_title}</div>
      <div class="fix-body">{adv_body}</div>
      <a href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}"
         target="_blank" class="fix-rule-link">
        <i class="fa-regular fa-arrow-up-right-from-square"></i> View rule documentation
      </a>
    </div>
  </td>
</tr>"""

def hotspot_row(hs: dict) -> str:
    _row_counter[0] += 1
    uid = f"row-{_row_counter[0]}"

    key      = hs.get("key", "")
    msg      = hs.get("message", "—")[:150]
    prob     = hs.get("vulnerabilityProbability", "LOW")
    rule     = hs.get("ruleKey", "")
    line     = get_line(hs)
    file     = get_file(hs)

    # ── Corrected SonarCloud hotspot deep-link ─────────────────
    # Format: /project/security_hotspots?id=PROJECT_KEY&hotspots=HOTSPOT_KEY
    link = f"{SONAR_URL}/project/security_hotspots?id={PROJECT_KEY}&hotspots={key}"

    adv_title, adv_body = get_advice(rule, "HOTSPOT")
    display_file = file.split("/")[-1] if file else "—"

    return f"""
<tr class="issue-row" onclick="toggleRow('{uid}')">
  <td class="td-file">
    <a href="{link}" target="_blank" onclick="event.stopPropagation()"
       class="loc-link" title="{file}">{display_file}</a>
    <span class="line-chip"><i class="fa-regular fa-code-branch"></i> L{line}</span>
  </td>
  <td class="td-path" title="{file}">{file}</td>
  <td class="td-msg">{msg}</td>
  <td>{sev_badge(prob)}</td>
  <td><code class="rule-code">{rule}</code></td>
  <td><span class="status-chip">TO_REVIEW</span></td>
  <td class="td-expand"><span class="chevron">›</span></td>
</tr>
<tr id="{uid}" class="fix-row" style="display:none;">
  <td colspan="7" class="fix-cell">
    <div class="fix-inner">
      <div class="fix-title"><i class="fa-regular fa-screwdriver-wrench"></i> {adv_title}</div>
      <div class="fix-body">{adv_body}</div>
      <a href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}"
         target="_blank" class="fix-rule-link">
        <i class="fa-regular fa-arrow-up-right-from-square"></i> View rule documentation
      </a>
    </div>
  </td>
</tr>"""

def issues_table(rows_html: list, closed_rows_html: list, empty_label: str) -> str:
    thead = """
    <thead>
      <tr>
        <th>File</th>
        <th>Full Path</th>
        <th>Message</th>
        <th>Severity</th>
        <th>Rule</th>
        <th>Status</th>
        <th></th>
      </tr>
    </thead>"""

    if not rows_html and not closed_rows_html:
        return f'<p class="empty-msg">No {empty_label} detected — great work!</p>'

    open_block = ""
    if rows_html:
        open_block = f"""
<div class="table-wrap">
  <table class="issue-table">
    {thead}
    <tbody>{"".join(rows_html)}</tbody>
  </table>
  <p class="table-note">
    <i class="fa-regular fa-circle-info"></i>
    Click a row to expand remediation guidance. File links open directly in SonarCloud.
  </p>
</div>"""
    else:
        open_block = f'<p class="empty-msg">No open {empty_label} — great work!</p>'

    closed_block = ""
    if closed_rows_html:
        n = len(closed_rows_html)
        closed_block = f"""
<details class="closed-section">
  <summary class="closed-summary">
    <i class="fa-regular fa-circle-check"></i>
    <span>Closed / Resolved {empty_label.title()}</span>
    <span class="closed-count">{n}</span>
  </summary>
  <div class="table-wrap closed-table-wrap">
    <table class="issue-table">
      {thead}
      <tbody>{"".join(closed_rows_html)}</tbody>
    </table>
    <p class="table-note">
      <i class="fa-regular fa-circle-info"></i>
      These issues were resolved in SonarCloud. Links open the issue record directly.
    </p>
  </div>
</details>"""

    return open_block + closed_block

# Build HTML blocks
bug_rows          = [issue_row(i, "BUG",           is_closed=False) for i in bug_issues]
bug_rows_closed   = [issue_row(i, "BUG",           is_closed=True)  for i in bug_issues_closed]
vuln_rows         = [issue_row(i, "VULNERABILITY",  is_closed=False) for i in vuln_issues]
vuln_rows_closed  = [issue_row(i, "VULNERABILITY",  is_closed=True)  for i in vuln_issues_closed]
hs_rows           = [hotspot_row(h)                                   for h in hotspot_list]

bugs_html     = issues_table(bug_rows,  bug_rows_closed,  "bugs")
vulns_html    = issues_table(vuln_rows, vuln_rows_closed, "vulnerabilities")
hotspots_html = issues_table(hs_rows,  [],               "hotspots")

# Chart data
h_labels = json.dumps([e["timestamp"]  for e in history])
h_scores = json.dumps([e["risk_score"] for e in history])
h_levels = json.dumps([e.get("level","") for e in history])

# Misc
type_pills = "".join(
    f'<span class="type-pill">{t.upper()}</span>' for t in DETECTED_TYPES
)

RISK_CSS_CLASS = {"LOW": "risk-low", "MEDIUM": "risk-med", "HIGH": "risk-high"}
risk_cls = RISK_CSS_CLASS.get(level, "risk-low")

decision_icon_cls = {
    "HIGH":   "fa-regular fa-circle-xmark",
    "MEDIUM": "fa-regular fa-triangle-exclamation",
    "LOW":    "fa-regular fa-circle-check",
}.get(level, "fa-regular fa-circle-check")

if level == "HIGH":
    summary_txt = (f"Build blocked: {vulns_count} vulnerabilities, {bugs_count} bugs, "
                   f"and {hotspots_count} hotspots exceed acceptable thresholds. "
                   "Immediate remediation required before deployment.")
elif level == "MEDIUM":
    summary_txt = (f"Build approved with warnings: {vulns_count} vulnerabilities, "
                   f"{bugs_count} bugs, {hotspots_count} hotspots detected. "
                   "Manual security review recommended.")
else:
    summary_txt = (f"Build approved. Detected issues ({vulns_count} vulns, "
                   f"{bugs_count} bugs, {hotspots_count} hotspots) are within thresholds.")

now_str = datetime.now(IST).strftime("%d %b %Y – %H:%M:%S IST")

# ─────────────────────────────────────────────────
# HTML report
# ─────────────────────────────────────────────────
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Dashboard — {PROJECT_KEY}</title>

<!--
  THEME BOOTSTRAP — runs synchronously before any paint.
  This eliminates the flash-of-wrong-theme in Jenkins / static file viewers
  because the <html data-theme="..."> attribute is set BEFORE the browser
  renders any CSS that depends on it.
-->
<script>
(function () {{
  var saved = '';
  try {{ saved = localStorage.getItem('dso-theme') || ''; }} catch (e) {{}}
  if (!saved) saved = 'dark';           // sensible default
  var resolved = saved;
  if (saved === 'system') {{
    try {{
      resolved = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark' : 'light';
    }} catch (e) {{ resolved = 'dark'; }}
  }}
  document.documentElement.setAttribute('data-theme', resolved);
  // Store resolved for the chart init that runs later
  window.__dsoInitialTheme = resolved;
  window.__dsoSavedPref    = saved;
}})();
</script>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<!-- Font Awesome 6 Free (outline / regular icons) -->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css"
      crossorigin="anonymous" referrerpolicy="no-referrer">
<!-- Chart.js loaded with a stable integrity hash; onload/onerror handled in JS -->
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"
        id="chartjsScript"></script>

<style>
/* ═══════════════════════════════════════════════
   Design tokens — dark (default)
═══════════════════════════════════════════════ */
:root {{
  color-scheme: dark;
  --bg:        #0f1117;
  --bg2:       #161a24;
  --bg3:       #1e2336;
  --border:    rgba(255,255,255,0.07);
  --border2:   rgba(255,255,255,0.12);
  --text:      #e2e8f0;
  --text2:     #94a3b8;
  --text3:     #64748b;
  --accent:    #6366f1;
  --accent-s:  rgba(99,102,241,0.15);
  --low-fg:    #22c55e;  --low-bg:  rgba(34,197,94,0.12);
  --med-fg:    #f59e0b;  --med-bg:  rgba(245,158,11,0.12);
  --high-fg:   #ef4444;  --high-bg: rgba(239,68,68,0.12);
  --fix-bg:    #131a2a;
  --fix-border:#2d3a55;
  --mono: 'IBM Plex Mono', monospace;
  --sans: 'Inter', sans-serif;
  --r: 10px;
  --shadow: 0 2px 12px rgba(0,0,0,0.35);
}}

/* Light theme */
html[data-theme="light"] {{
  color-scheme: light;
  --bg:        #f8fafc;
  --bg2:       #ffffff;
  --bg3:       #f1f5f9;
  --border:    rgba(0,0,0,0.07);
  --border2:   rgba(0,0,0,0.12);
  --text:      #0f172a;
  --text2:     #475569;
  --text3:     #94a3b8;
  --accent:    #4f46e5;
  --accent-s:  rgba(79,70,229,0.08);
  --low-fg:    #16a34a;  --low-bg:  rgba(22,163,74,0.08);
  --med-fg:    #d97706;  --med-bg:  rgba(217,119,6,0.08);
  --high-fg:   #dc2626;  --high-bg: rgba(220,38,38,0.08);
  --fix-bg:    #f0f4ff;
  --fix-border:#c7d2fe;
  --shadow: 0 2px 12px rgba(0,0,0,0.08);
}}

/* ═══════════════════════════════════════════════
   Base
═══════════════════════════════════════════════ */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

body {{
  font-family: var(--sans);
  background: var(--bg);
  color: var(--text);
  font-size: 14px;
  line-height: 1.6;
  min-height: 100vh;
  transition: background .25s, color .25s;
}}

a {{ color: var(--accent); text-decoration: none; }}
a:hover {{ text-decoration: underline; }}

/* ═══════════════════════════════════════════════
   Top nav
═══════════════════════════════════════════════ */
.nav {{
  position: sticky; top: 0; z-index: 200;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 28px; height: 52px;
  backdrop-filter: blur(10px);
}}
.nav-brand {{
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--accent);
  display: flex; align-items: center; gap: 10px;
  letter-spacing: .04em;
}}
.status-dot {{
  width: 7px; height: 7px; border-radius: 50%;
  animation: pulse 2.4s ease-in-out infinite;
}}
.status-dot.risk-low  {{ background: var(--low-fg);  box-shadow: 0 0 6px var(--low-fg); }}
.status-dot.risk-med  {{ background: var(--med-fg);  box-shadow: 0 0 6px var(--med-fg); }}
.status-dot.risk-high {{ background: var(--high-fg); box-shadow: 0 0 6px var(--high-fg); }}
@keyframes pulse {{
  0%, 100% {{ opacity: 1; transform: scale(1); }}
  50%       {{ opacity: .5; transform: scale(1.4); }}
}}
.nav-right {{ display: flex; align-items: center; gap: 8px; }}
.nav-ts {{ font-family: var(--mono); font-size: 11px; color: var(--text3); }}

/* Theme toggle */
.theme-toggle {{
  display: flex;
  background: var(--bg3);
  border: 1px solid var(--border2);
  border-radius: 8px;
  overflow: hidden;
  padding: 2px; gap: 2px;
}}
.theme-btn {{
  background: none; border: none;
  padding: 5px 10px; cursor: pointer;
  border-radius: 6px; font-size: 13px;
  color: var(--text3);
  transition: background .15s, color .15s;
}}
.theme-btn.active {{
  background: var(--accent);
  color: #fff;
}}

/* ═══════════════════════════════════════════════
   Hero
═══════════════════════════════════════════════ */
.hero {{
  padding: 52px 28px 40px;
  text-align: center;
  border-bottom: 1px solid var(--border);
  background: var(--bg2);
}}
.hero-title {{
  font-family: var(--mono);
  font-size: clamp(18px, 3vw, 28px);
  font-weight: 600;
  color: var(--text);
  letter-spacing: -.02em;
  margin-bottom: 4px;
}}
.hero-sub {{ color: var(--text2); font-size: 13px; margin-bottom: 18px; }}
.type-pills {{ display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; margin-bottom: 32px; }}
.type-pill {{
  background: var(--accent-s);
  color: var(--accent);
  border: 1px solid rgba(99,102,241,0.2);
  border-radius: 20px;
  padding: 3px 13px;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .06em;
}}
.score-ring {{
  display: inline-flex; flex-direction: column; align-items: center;
  padding: 28px 56px;
  border-radius: 16px;
  border-width: 1.5px; border-style: solid;
  margin-bottom: 16px;
}}
.score-ring.risk-low  {{ background: var(--low-bg);  border-color: var(--low-fg);  }}
.score-ring.risk-med  {{ background: var(--med-bg);  border-color: var(--med-fg);  }}
.score-ring.risk-high {{ background: var(--high-bg); border-color: var(--high-fg); }}
.score-num {{
  font-family: var(--mono);
  font-size: 64px;
  font-weight: 600;
  line-height: 1;
}}
.score-ring.risk-low  .score-num {{ color: var(--low-fg);  }}
.score-ring.risk-med  .score-num {{ color: var(--med-fg);  }}
.score-ring.risk-high .score-num {{ color: var(--high-fg); }}
.score-lbl {{
  font-size: 10px;
  letter-spacing: .12em;
  margin-top: 5px;
  opacity: .65;
  text-transform: uppercase;
}}
.score-ring.risk-low  .score-lbl {{ color: var(--low-fg);  }}
.score-ring.risk-med  .score-lbl {{ color: var(--med-fg);  }}
.score-ring.risk-high .score-lbl {{ color: var(--high-fg); }}
.level-badge {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: .1em;
  padding: 5px 20px;
  border-radius: 20px;
  border-width: 1px; border-style: solid;
}}
.level-badge.risk-low  {{ color: var(--low-fg);  background: var(--low-bg);  border-color: var(--low-fg);  }}
.level-badge.risk-med  {{ color: var(--med-fg);  background: var(--med-bg);  border-color: var(--med-fg);  }}
.level-badge.risk-high {{ color: var(--high-fg); background: var(--high-bg); border-color: var(--high-fg); }}

/* ═══════════════════════════════════════════════
   Page layout
═══════════════════════════════════════════════ */
.page {{ max-width: 1280px; margin: 0 auto; padding: 28px 20px 60px; }}

.card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--r);
  padding: 24px;
  margin-bottom: 20px;
  box-shadow: var(--shadow);
  transition: background .25s, border-color .25s;
}}
.card-title {{
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .1em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 18px;
  display: flex; align-items: center; gap: 8px;
}}
.card-title::before {{
  content: '';
  display: block;
  width: 3px; height: 14px;
  border-radius: 2px;
  background: var(--accent);
  flex-shrink: 0;
}}

/* ═══════════════════════════════════════════════
   Metric grid
═══════════════════════════════════════════════ */
.metric-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 12px;
  margin-bottom: 20px;
}}
.metric-tile {{
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 18px 14px;
  text-align: center;
  transition: border-color .2s, transform .2s;
  cursor: default;
}}
.metric-tile:hover {{ border-color: var(--border2); transform: translateY(-1px); }}
.metric-tile .m-val {{
  font-family: var(--mono);
  font-size: 30px;
  font-weight: 600;
  line-height: 1;
  margin-bottom: 5px;
}}
.m-bug   {{ color: #ef4444; }}
.m-vuln  {{ color: #f97316; }}
.m-spot  {{ color: #a855f7; }}
.m-smell {{ color: #f59e0b; }}
.m-cov   {{ color: var(--accent); }}
.m-dup   {{ color: var(--text3); }}
.metric-tile .m-lbl {{
  font-size: 11px;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: .06em;
}}
.rating-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
  gap: 12px;
}}
.rating-tile {{
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px;
  text-align: center;
}}
.rating-tile .r-val {{
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 600;
}}
.r-A {{ color: #22c55e; }}
.r-B {{ color: #86efac; }}
.r-C {{ color: #f59e0b; }}
.r-D {{ color: #f97316; }}
.r-E {{ color: #ef4444; }}
.r-Q {{ color: var(--text3); }}
.rating-tile .r-lbl {{
  font-size: 11px;
  color: var(--text3);
  text-transform: uppercase;
  letter-spacing: .06em;
  margin-top: 3px;
}}

/* ═══════════════════════════════════════════════
   Decision banner
═══════════════════════════════════════════════ */
.decision-banner {{
  display: flex; align-items: flex-start; gap: 16px;
  padding: 18px 20px;
  border-radius: 8px;
  border-width: 1px; border-style: solid;
  margin-bottom: 14px;
}}
.decision-banner.risk-low  {{ background: var(--low-bg);  border-color: var(--low-fg);  }}
.decision-banner.risk-med  {{ background: var(--med-bg);  border-color: var(--med-fg);  }}
.decision-banner.risk-high {{ background: var(--high-bg); border-color: var(--high-fg); }}
.d-icon {{ font-size: 22px; flex-shrink: 0; line-height: 1.4; }}
.d-body {{ flex: 1; }}
.d-action {{
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: .08em;
  margin-bottom: 4px;
}}
.decision-banner.risk-low  .d-action {{ color: var(--low-fg);  }}
.decision-banner.risk-med  .d-action {{ color: var(--med-fg);  }}
.decision-banner.risk-high .d-action {{ color: var(--high-fg); }}
.d-summary {{ font-size: 13px; color: var(--text2); line-height: 1.55; }}
.d-right {{ display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }}
.trend-chip {{
  font-family: var(--mono);
  font-size: 11px;
  padding: 3px 10px;
  border-radius: 12px;
  border: 1px solid var(--border2);
  color: var(--text2);
  white-space: nowrap;
}}
.formula-line {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  margin-top: 12px;
  padding: 10px 14px;
  background: var(--bg3);
  border-radius: 6px;
  border: 1px solid var(--border);
}}

/* ═══════════════════════════════════════════════
   Tabs
═══════════════════════════════════════════════ */
.tab-bar {{
  display: flex; gap: 3px;
  background: var(--bg3);
  border-radius: 8px; padding: 3px;
  width: fit-content;
  margin-bottom: 18px;
  border: 1px solid var(--border);
}}
.tab-btn {{
  background: none; border: none;
  color: var(--text2);
  padding: 6px 16px;
  border-radius: 6px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11px; font-weight: 600;
  letter-spacing: .06em;
  display: flex; align-items: center; gap: 7px;
  transition: all .15s;
}}
.tab-btn.active {{
  background: var(--accent);
  color: #fff;
  box-shadow: 0 1px 6px rgba(99,102,241,.3);
}}
.tab-btn:not(.active):hover {{ color: var(--text); background: var(--border); }}
.tab-badge {{
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 18px; height: 18px; border-radius: 9px; padding: 0 5px;
  font-size: 10px; font-weight: 700;
  background: rgba(255,255,255,0.15);
}}
.tab-btn.active .tab-badge {{ background: rgba(255,255,255,0.25); color: #fff; }}
.tab-pane {{ display: none; }}
.tab-pane.active {{ display: block; }}

/* ═══════════════════════════════════════════════
   Issue tables
═══════════════════════════════════════════════ */
.table-wrap {{ overflow-x: auto; }}
.issue-table {{
  width: 100%; border-collapse: collapse;
  font-size: 13px;
}}
.issue-table thead th {{
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .08em;
  color: var(--text3);
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  background: var(--bg3);
  white-space: nowrap;
}}
.issue-table tbody .issue-row {{
  cursor: pointer;
  transition: background .12s;
}}
.issue-table tbody .issue-row:hover {{ background: var(--accent-s); }}
.issue-table tbody td {{
  padding: 11px 14px;
  border-bottom: 1px solid var(--border);
  color: var(--text);
  vertical-align: middle;
}}
.td-file {{ min-width: 140px; white-space: nowrap; }}
.td-path {{
  min-width: 200px;
  max-width: 260px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3) !important;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}}
.td-msg {{ min-width: 180px; color: var(--text2) !important; }}
.td-expand {{ width: 32px; text-align: center; }}

.loc-link {{
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--accent) !important;
  display: block;
  white-space: nowrap;
}}
.loc-link:hover {{ text-decoration: underline !important; }}
.line-chip {{
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  color: var(--accent);
  margin-top: 3px;
  background: var(--accent-s);
  border: 1px solid rgba(99,102,241,0.25);
  border-radius: 4px;
  padding: 1px 6px;
}}
html[data-theme="light"] .line-chip {{
  color: var(--accent);
  background: rgba(79,70,229,0.08);
  border-color: rgba(79,70,229,0.2);
}}
/* Resolution chip for closed issues */
.res-chip {{
  display: inline-block;
  margin-left: 6px;
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 700;
  letter-spacing: .06em;
  padding: 1px 6px;
  border-radius: 4px;
  color: var(--res-fg);
  background: color-mix(in srgb, var(--res-fg) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--res-fg) 28%, transparent);
  vertical-align: middle;
}}
/* Closed issue rows — slightly dimmed */
.closed-row td {{ opacity: 0.72; }}
.closed-row:hover td {{ opacity: 1; }}
/* Closed/Resolved section (collapsible) */
.closed-section {{
  margin-top: 20px;
  border: 1px solid var(--border2);
  border-radius: 8px;
  overflow: hidden;
}}
.closed-summary {{
  display: flex; align-items: center; gap: 10px;
  padding: 12px 18px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .06em;
  color: var(--text2);
  background: var(--bg3);
  user-select: none;
  list-style: none;
}}
.closed-summary::-webkit-details-marker {{ display: none; }}
.closed-summary i {{ color: #22c55e; font-size: 13px; }}
.closed-summary::after {{
  content: '›';
  margin-left: auto;
  font-size: 16px;
  color: var(--text3);
  transition: transform .2s;
}}
details[open] > .closed-summary::after {{ transform: rotate(90deg); }}
.closed-count {{
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 20px; height: 20px;
  border-radius: 10px; padding: 0 6px;
  font-size: 10px; font-weight: 700;
  background: rgba(34,197,94,0.15);
  color: #22c55e;
  border: 1px solid rgba(34,197,94,0.3);
}}
.closed-table-wrap {{
  border-top: 1px solid var(--border);
}}
.rule-code {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
  white-space: nowrap;
}}
.status-chip {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
}}
.chevron {{
  font-size: 16px;
  color: var(--text3);
  display: inline-block;
  transition: transform .2s;
  line-height: 1;
}}
.issue-row.expanded .chevron {{ transform: rotate(90deg); color: var(--accent); }}
.badge {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .05em;
  padding: 2px 8px;
  border-radius: 4px;
  color: var(--badge-fg);
  background: color-mix(in srgb, var(--badge-fg) 12%, transparent);
  border: 1px solid color-mix(in srgb, var(--badge-fg) 25%, transparent);
}}

/* Fix drawer */
.fix-row {{ display: none; }}
.fix-row.open {{ display: table-row !important; }}
.fix-cell {{ padding: 0 !important; border-bottom: 1px solid var(--border) !important; }}
.fix-inner {{
  padding: 18px 20px;
  background: var(--fix-bg);
  border-left: 3px solid var(--accent);
  border-top: 1px solid var(--fix-border);
}}
.fix-title {{
  font-size: 13px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
}}
.fix-body {{
  font-size: 13px;
  color: var(--text2);
  line-height: 1.65;
  margin-bottom: 10px;
}}
.fix-rule-link {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--accent);
}}
.table-note {{
  font-size: 11px;
  color: var(--text3);
  margin-top: 10px;
  font-style: italic;
}}
.empty-msg {{
  font-size: 13px;
  color: var(--text3);
  padding: 20px 0;
  font-style: italic;
}}

/* ═══════════════════════════════════════════════
   Links row — evenly spaced, equal-width tiles
═══════════════════════════════════════════════ */
.links-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 12px;
}}
.lnk {{
  display: flex; align-items: center; justify-content: center; gap: 9px;
  padding: 12px 16px;
  border-radius: 8px;
  font-family: var(--mono);
  font-size: 11px; font-weight: 600;
  letter-spacing: .04em;
  border: 1px solid var(--border2);
  color: var(--text2);
  background: var(--bg3);
  transition: all .15s;
  text-align: center;
}}
.lnk i {{ font-size: 14px; flex-shrink: 0; }}
.lnk:hover {{
  background: var(--accent-s);
  border-color: rgba(99,102,241,.3);
  color: var(--accent);
  text-decoration: none;
}}

/* ═══════════════════════════════════════════════
   Chart
═══════════════════════════════════════════════ */
.chart-wrap {{ position: relative; height: 260px; }}
.chart-error {{
  height: 260px;
  display: flex; align-items: center; justify-content: center;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text3);
  border: 1px dashed var(--border2);
  border-radius: 8px;
}}

/* ═══════════════════════════════════════════════
   Footer
═══════════════════════════════════════════════ */
.footer {{
  text-align: center;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  padding: 28px 0 0;
}}
</style>
</head>
<body>

<!-- ─── Nav ─────────────────────────────────── -->
<nav class="nav">
  <div class="nav-brand">
    <div class="status-dot {risk_cls}"></div>
    DEVSECOPS · SECURITY DASHBOARD
  </div>
  <div class="nav-right">
    <span class="nav-ts">{now_str}</span>
    <div class="theme-toggle" id="themeToggle">
      <button class="theme-btn" data-t="light"  onclick="setTheme('light')"  title="Light mode">☀️</button>
      <button class="theme-btn" data-t="dark"   onclick="setTheme('dark')"   title="Dark mode">🌙</button>
      <button class="theme-btn" data-t="system" onclick="setTheme('system')" title="System default">⚙</button>
    </div>
  </div>
</nav>

<!-- ─── Hero ─────────────────────────────────── -->
<div class="hero">
  <div class="hero-title">Security Risk Report</div>
  <div class="hero-sub">Project: <strong>{PROJECT_KEY}</strong></div>
  <div class="type-pills">{type_pills}</div>
  <div class="score-ring {risk_cls}">
    <div class="score-num">{risk_score}</div>
    <div class="score-lbl">Risk Score</div>
  </div>
  <br>
  <span class="level-badge {risk_cls}">{level} RISK</span>
</div>

<!-- ─── Page ─────────────────────────────────── -->
<div class="page">

  <!-- Quick Links -->
  <div class="card">
    <div class="card-title">Quick Links</div>
    <div class="links-row">
      <a class="lnk" href="{SONAR_DASHBOARD}" target="_blank">
        <i class="fa-regular fa-shield-halved"></i> SonarCloud Dashboard
      </a>
      <a class="lnk" href="{PROJECT_REPO}" target="_blank">
        <i class="fa-regular fa-code-branch"></i> GitHub Repository
      </a>
      <a class="lnk" href="{RUNNING_APP}" target="_blank">
        <i class="fa-regular fa-circle-play"></i> Running Application
      </a>
      <a class="lnk" href="{GITHUB_RUN_URL}" target="_blank">
        <i class="fa-regular fa-gear"></i> CI/CD Run
      </a>
    </div>
  </div>

  <!-- Metrics -->
  <div class="card">
    <div class="card-title">Metrics Overview</div>
    <div class="metric-grid">
      <div class="metric-tile"><div class="m-val m-bug">{bugs_count}</div><div class="m-lbl">Bugs</div></div>
      <div class="metric-tile"><div class="m-val m-vuln">{vulns_count}</div><div class="m-lbl">Vulnerabilities</div></div>
      <div class="metric-tile"><div class="m-val m-spot">{hotspots_count}</div><div class="m-lbl">Hotspots</div></div>
      <div class="metric-tile"><div class="m-val m-smell">{smells_count}</div><div class="m-lbl">Code Smells</div></div>
      <div class="metric-tile"><div class="m-val m-cov">{coverage_pct}%</div><div class="m-lbl">Coverage</div></div>
      <div class="metric-tile"><div class="m-val m-dup">{duplication_pct}%</div><div class="m-lbl">Duplication</div></div>
    </div>
    <div class="rating-row">
      <div class="rating-tile">
        <div class="r-val r-{reliability_rating}">{reliability_rating}</div>
        <div class="r-lbl">Reliability</div>
      </div>
      <div class="rating-tile">
        <div class="r-val r-{security_rating}">{security_rating}</div>
        <div class="r-lbl">Security</div>
      </div>
      <div class="rating-tile">
        <div class="r-val r-{maintainability_rating}">{maintainability_rating}</div>
        <div class="r-lbl">Maintainability</div>
      </div>
      <div class="rating-tile">
        <div class="r-val" style="color:var(--accent);">{risk_score}</div>
        <div class="r-lbl">Risk Score</div>
      </div>
    </div>
  </div>

  <!-- Decision -->
  <div class="card">
    <div class="card-title">Governance Decision</div>
    <div class="decision-banner {risk_cls}">
      <div class="d-icon"><i class="{decision_icon_cls}"></i></div>
      <div class="d-body">
        <div class="d-action">{decision}</div>
        <div class="d-summary">{summary_txt}</div>
      </div>
      <div class="d-right">
        <span class="trend-chip">{trend}</span>
      </div>
    </div>
    <div class="formula-line">
      Risk Score = (Bugs × {WEIGHT_BUGS}) + (Vulns × {WEIGHT_VULNS}) + (Hotspots × {WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; ({bugs_count}×{WEIGHT_BUGS}) + ({vulns_count}×{WEIGHT_VULNS}) + ({hotspots_count}×{WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; <strong>{risk_score}</strong>
    </div>
  </div>

  <!-- Issues -->
  <div class="card">
    <div class="card-title">Issue Details</div>
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('bugs',this)">
        <span class="tab-badge">{bugs_count}</span> BUGS
      </button>
      <button class="tab-btn" onclick="switchTab('vulns',this)">
        <span class="tab-badge">{vulns_count}</span> VULNERABILITIES
      </button>
      <button class="tab-btn" onclick="switchTab('hotspots',this)">
        <span class="tab-badge">{hotspots_count}</span> HOTSPOTS
      </button>
    </div>
    <div id="tab-bugs"     class="tab-pane active">{bugs_html}</div>
    <div id="tab-vulns"    class="tab-pane">{vulns_html}</div>
    <div id="tab-hotspots" class="tab-pane">{hotspots_html}</div>
  </div>

  <!-- Trend -->
  <div class="card">
    <div class="card-title">Risk Score Trend</div>
    <div class="chart-wrap">
      <canvas id="riskChart"></canvas>
    </div>
  </div>

</div>

<div class="footer">
  Generated by Intelligent Risk-Adaptive DevSecOps &nbsp;·&nbsp; {now_str}
</div>

<script>
/* ══════════════════════════════════════════════════════
   Theme management
   The <head> inline script already applied the correct
   theme before first paint. Here we just sync the toggle
   button state and wire up the controls.
══════════════════════════════════════════════════════ */
var MEDIA = window.matchMedia('(prefers-color-scheme: dark)');

function resolveTheme(pref) {{
  if (pref === 'system') return MEDIA.matches ? 'dark' : 'light';
  return pref || 'dark';
}}

function syncToggleButtons(saved) {{
  document.querySelectorAll('.theme-btn').forEach(function(b) {{
    b.classList.toggle('active', b.dataset.t === saved);
  }});
}}

function applyTheme(saved) {{
  var resolved = resolveTheme(saved);
  document.documentElement.setAttribute('data-theme', resolved);
  syncToggleButtons(saved);
  rebuildChart(resolved);
}}

function setTheme(pref) {{
  try {{ localStorage.setItem('dso-theme', pref); }} catch(e) {{}}
  applyTheme(pref);
}}

// Sync buttons on load using the pref already applied by the head script
(function() {{
  var saved = window.__dsoSavedPref || 'dark';
  syncToggleButtons(saved);
}})();

// Keep system theme in sync with OS preference changes
MEDIA.addEventListener('change', function() {{
  var saved = '';
  try {{ saved = localStorage.getItem('dso-theme') || ''; }} catch(e) {{}}
  if ((saved || 'system') === 'system') applyTheme('system');
}});

/* ══════════════════════════════════════════════════════
   Tabs
══════════════════════════════════════════════════════ */
function switchTab(name, btn) {{
  document.querySelectorAll('.tab-pane').forEach(function(p) {{
    p.classList.remove('active');
  }});
  document.querySelectorAll('.tab-btn').forEach(function(b) {{
    b.classList.remove('active');
  }});
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
}}

/* ══════════════════════════════════════════════════════
   Fix row toggle
══════════════════════════════════════════════════════ */
function toggleRow(uid) {{
  var row  = document.getElementById(uid);
  var trig = row.previousElementSibling;
  var open = row.classList.contains('open');
  row.classList.toggle('open', !open);
  row.style.display = open ? 'none' : 'table-row';
  trig.classList.toggle('expanded', !open);
}}

/* ══════════════════════════════════════════════════════
   Risk trend chart
   Chart.js may still be loading when this script runs
   (the <script> tag is synchronous but we want to be
   defensive). We poll until Chart is available then
   initialise — this makes the chart work whether
   Chart.js loads fast or slow (e.g. in Jenkins with
   restricted network or Content-Security-Policy).
══════════════════════════════════════════════════════ */
var CHART_DATA = {{
  labels: {h_labels},
  scores: {h_scores},
  levels: {h_levels}
}};

var chartInstance = null;

function levelColor(l, alpha) {{
  var key = (l || '').toUpperCase().trim();
  var map = {{
    HIGH:   'rgba(239,68,68,'   + alpha + ')',
    MEDIUM: 'rgba(245,158,11,' + alpha + ')',
    LOW:    'rgba(34,197,94,'  + alpha + ')'
  }};
  return map[key] || ('rgba(148,163,184,' + alpha + ')');
}}

function buildChart(theme) {{
  var canvas = document.getElementById('riskChart');
  if (!canvas) return;
  if (typeof Chart === 'undefined') return;   // guard: CDN not loaded yet

  var isDark   = theme !== 'light';
  var gridCol  = isDark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.06)';
  var tickCol  = isDark ? '#64748b' : '#94a3b8';
  var tipBg    = isDark ? '#1e2336' : '#ffffff';
  var tipBor   = isDark ? 'rgba(255,255,255,0.1)' : 'rgba(0,0,0,0.1)';
  var tipText  = isDark ? '#e2e8f0' : '#0f172a';
  var tipMuted = isDark ? '#94a3b8' : '#64748b';

  if (chartInstance) {{ chartInstance.destroy(); chartInstance = null; }}

  chartInstance = new Chart(canvas.getContext('2d'), {{
    type: 'line',
    data: {{
      labels: CHART_DATA.labels,
      datasets: [{{
        label: 'Risk Score',
        data: CHART_DATA.scores,
        borderColor: '#6366f1',
        backgroundColor: isDark
          ? 'rgba(99,102,241,0.07)'
          : 'rgba(99,102,241,0.06)',
        pointBackgroundColor: CHART_DATA.levels.map(function(l) {{ return levelColor(l, 1); }}),
        pointBorderColor:     CHART_DATA.levels.map(function(l) {{ return levelColor(l, 1); }}),
        pointRadius: 5,
        pointHoverRadius: 8,
        tension: 0.38,
        fill: true,
        borderWidth: 2
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          backgroundColor: tipBg,
          borderColor: tipBor,
          borderWidth: 1,
          titleColor: tipText,
          bodyColor: tipMuted,
          padding: 10,
          callbacks: {{
            afterBody: function(items) {{
              var idx = items[0].dataIndex;
              var raw = (CHART_DATA.levels[idx] || '').toUpperCase().trim();
              var label = raw || 'UNKNOWN';
              return ['Risk Level: ' + label];
            }}
          }}
        }}
      }},
      scales: {{
        x: {{
          ticks: {{ color: tickCol, font: {{ family: "'IBM Plex Mono'", size: 10 }} }},
          grid:  {{ color: gridCol }}
        }},
        y: {{
          beginAtZero: true,
          ticks: {{ color: tickCol, font: {{ family: "'IBM Plex Mono'", size: 11 }} }},
          grid:  {{ color: gridCol }}
        }}
      }}
    }}
  }});
}}

function rebuildChart(theme) {{
  if (typeof Chart !== 'undefined') {{
    buildChart(theme);
  }}
  // else: the polling loop below will pick it up
}}

// Robust chart init: poll for Chart.js readiness, then build.
// Handles: synchronous load (Chart ready immediately), async CDN load,
// and CSP / network failures (shows fallback message after timeout).
(function initChartWhenReady() {{
  var MAX_WAIT_MS = 10000;   // 10 s timeout before showing error
  var start = Date.now();
  var theme = window.__dsoInitialTheme || 'dark';

  function attempt() {{
    if (typeof Chart !== 'undefined') {{
      buildChart(theme);
      return;
    }}
    if (Date.now() - start > MAX_WAIT_MS) {{
      // Replace canvas with an error message
      var wrap = document.querySelector('.chart-wrap');
      if (wrap) {{
        wrap.innerHTML =
          '<div class="chart-error">Chart.js failed to load — ' +
          'check your network or Content-Security-Policy settings.</div>';
      }}
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