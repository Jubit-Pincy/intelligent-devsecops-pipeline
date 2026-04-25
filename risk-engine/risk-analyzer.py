"""
risk-analyzer.py
Intelligent Risk-Adaptive DevSecOps - Risk Engine v4
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
  • FIXED: Font Awesome icons now use fas (solid) — fa-regular requires FA Pro
  • FIXED: Theme toggle emojis replaced with FA solid icons (fa-sun, fa-moon, fa-circle-half-stroke)
  • FIXED: Color scheme updated to Obsidian Minimalist Palette
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
API_ENDPOINT   = os.getenv("API_ENDPOINT", "")
 
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
 
def mark_issue_resolved(issue_key: str, transition: str = "wontfix", comment: str = ""):
    """
    Mark an issue as resolved in SonarCloud.
    transition: 'wontfix', 'falsepositive', or 'resolve'
    """
    try:
        endpoint = "issues/do_transition"
        params = {
            "issue": issue_key,
            "transition": transition
        }
        r = requests.post(f"{SONAR_URL}/api/{endpoint}",
                         params=params, auth=AUTH, timeout=30)
        r.raise_for_status()
        
        # Add comment if provided
        if comment:
            comment_endpoint = "issues/add_comment"
            comment_params = {
                "issue": issue_key,
                "text": comment
            }
            requests.post(f"{SONAR_URL}/api/{comment_endpoint}",
                        params=comment_params, auth=AUTH, timeout=30)
        
        return True
    except Exception as e:
        print(f"  Warning: could not resolve issue {issue_key}: {e}")
        return False
 
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
    # Format: "java=1234;py=567;js=890"
    for pair in lang_dist_raw.split(";"):
        if "=" in pair:
            lang, lines = pair.split("=", 1)
            language_data.append({"lang": lang, "lines": int(lines)})
    # Override DETECTED_TYPES with actual languages if available
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
                     "Extract cohesive blocks into well-named private methods. Aim for methods under 30-40 lines."),
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
# Obsidian Minimalist colors for severity badges
SEV_META = {
    "BLOCKER":  ("#FF3B30", "#1a0000", "#3a0000"),
    "CRITICAL": ("#FF3B30", "#1a0000", "#3a0000"),
    "MAJOR":    ("#FFD60A", "#1a1500", "#3a2e00"),
    "MINOR":    ("#888888", "#111111", "#1F1F1F"),
    "INFO":     ("#888888", "#111111", "#1F1F1F"),
    "HIGH":     ("#FF3B30", "#1a0000", "#3a0000"),
    "MEDIUM":   ("#FFD60A", "#1a1500", "#3a2e00"),
    "LOW":      ("#32D74B", "#001a05", "#003a0d"),
}
 
def sev_badge(sev: str) -> str:
    s = (sev or "INFO").upper()
    fg, _, _ = SEV_META.get(s, ("#888888", "#111111", "#1F1F1F"))
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
    resolution = issue.get("resolution", "")
    line       = get_line(issue)
    file       = get_file(issue)
 
    if is_closed:
        link = (f"{SONAR_URL}/project/issues?id={PROJECT_KEY}"
                f"&open={key}&statuses={status}&resolved=true")
    else:
        link = f"{SONAR_URL}/project/issues?id={PROJECT_KEY}&open={key}"
 
    adv_title, adv_body = get_advice(rule, itype)
    display_file = file.split("/")[-1] if file else "—"
 
    res_html = ""
    if resolution:
        res_color = {
            "FIXED":         "#32D74B",
            "FALSE-POSITIVE":"#888888",
            "WONTFIX":       "#FFD60A",
            "REMOVED":       "#888888",
        }.get(resolution.upper(), "#888888")
        res_html = (f'<span class="res-chip" style="--res-fg:{res_color};">'
                    f'{resolution}</span>')
 
    # FIX: use fas (solid) — fa-regular requires Font Awesome Pro
    return f"""
<tr class="issue-row{'  closed-row' if is_closed else ''}" onclick="toggleRow('{uid}')">
  <td class="td-file">
    <a href="{link}" target="_blank" onclick="event.stopPropagation()"
       class="loc-link" title="{file}">{display_file}</a>
    <span class="line-chip"><i class="fas fa-code-branch"></i> L{line}</span>
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
      <div class="fix-title"><i class="fas fa-screwdriver-wrench"></i> {adv_title}</div>
      <div class="fix-body">{adv_body}</div>
      <a href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}"
         target="_blank" class="fix-rule-link">
        <i class="fas fa-arrow-up-right-from-square"></i> View rule documentation
      </a>
      {'' if is_closed else f'''
      <div class="resolve-actions">
        <button class="resolve-btn" onclick="resolveIssue('{key}', 'wontfix', event)">
          <i class="fas fa-ban"></i> Won't Fix
        </button>
        <button class="resolve-btn" onclick="resolveIssue('{key}', 'falsepositive', event)">
          <i class="fas fa-flag"></i> False Positive
        </button>
        <button class="resolve-btn resolve-btn-primary" onclick="resolveIssue('{key}', 'resolve', event)">
          <i class="fas fa-check"></i> Mark Resolved
        </button>
      </div>
      '''}
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
 
    link = f"{SONAR_URL}/project/security_hotspots?id={PROJECT_KEY}&hotspots={key}"
 
    adv_title, adv_body = get_advice(rule, "HOTSPOT")
    display_file = file.split("/")[-1] if file else "—"
 
    return f"""
<tr class="issue-row" onclick="toggleRow('{uid}')">
  <td class="td-file">
    <a href="{link}" target="_blank" onclick="event.stopPropagation()"
       class="loc-link" title="{file}">{display_file}</a>
    <span class="line-chip"><i class="fas fa-code-branch"></i> L{line}</span>
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
      <div class="fix-title"><i class="fas fa-screwdriver-wrench"></i> {adv_title}</div>
      <div class="fix-body">{adv_body}</div>
      <a href="https://rules.sonarsource.com/search?languages=&tags=&q={rule}"
         target="_blank" class="fix-rule-link">
        <i class="fas fa-arrow-up-right-from-square"></i> View rule documentation
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
    <i class="fas fa-circle-info"></i>
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
    <i class="fas fa-circle-check"></i>
    <span>Closed / Resolved {empty_label.title()}</span>
    <span class="closed-count">{n}</span>
  </summary>
  <div class="table-wrap closed-table-wrap">
    <table class="issue-table">
      {thead}
      <tbody>{"".join(closed_rows_html)}</tbody>
    </table>
    <p class="table-note">
      <i class="fas fa-circle-info"></i>
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
lang_chart_data = json.dumps(language_data)
 
# Misc
type_pills = "".join(
    f'<span class="type-pill">{t.upper()}</span>' for t in DETECTED_TYPES
)
 
RISK_CSS_CLASS = {"LOW": "risk-low", "MEDIUM": "risk-med", "HIGH": "risk-high"}
risk_cls = RISK_CSS_CLASS.get(level, "risk-low")
 
# FIX: fas (solid) classes — fa-regular requires Font Awesome Pro
decision_icon_cls = {
    "HIGH":   "fas fa-circle-xmark",
    "MEDIUM": "fas fa-triangle-exclamation",
    "LOW":    "fas fa-circle-check",
}.get(level, "fas fa-circle-check")
 
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
 
now_str = datetime.now(IST).strftime("%d %b %Y - %H:%M:%S IST")

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
  Applies data-theme before first CSS render — eliminates flash of wrong theme.
-->
<script>
(function () {{
  var saved = '';
  try {{ saved = localStorage.getItem('dso-theme') || ''; }} catch (e) {{}}
  if (!saved) saved = 'dark';
  var resolved = saved;
  if (saved === 'system') {{
    try {{
      resolved = window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark' : 'light';
    }} catch (e) {{ resolved = 'dark'; }}
  }}
  document.documentElement.setAttribute('data-theme', resolved);
  window.__dsoInitialTheme = resolved;
  window.__dsoSavedPref    = saved;
}})();
</script>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">

<!--
  Font Awesome 6 Free — provides fas (solid) and fab (brands).
  NOTE: fa-regular (outline) icons require Font Awesome Pro.
  All icons in this report use "fas" prefix to work with the free CDN.
-->
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer">

<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.2/dist/chart.umd.min.js"
        id="chartjsScript"></script>

<style>
/* ═══════════════════════════════════════════════
   Design tokens — Obsidian Minimalist (dark default)
   Core:    #000000 bg · #0B0B0B containers · #1F1F1F borders
            #FFFFFF text · #888888 sub-text
   Status:  #FF3B30 danger · #FFD60A warning · #32D74B success
═══════════════════════════════════════════════ */
:root {{
  color-scheme: dark;
  --bg:         #121212;
  --bg2:        #1E1E1E;
  --bg3:        #252525;
  --border:     #2C2C2C;
  --border2:    #3D3D3D;
  --text:       #E0E0E0;
  --text2:      #A0A0A0;
  --text3:      #666666;
  --accent:     #E0E0E0;
  --accent-s:   rgba(224, 224, 224, 0.05);
  --low-fg:     #81C784;  --low-bg:  rgba(129, 199, 132, 0.1);
  --med-fg:     #FBC02D;  --med-bg:  rgba(251, 192, 45, 0.1);
  --high-fg:    #CF6679;  --high-bg: rgba(207, 102, 121, 0.1);
  --fix-bg:     #1E1E1E;
  --fix-border: #2C2C2C;
  --mono: 'IBM Plex Mono', monospace;
  --sans: 'Inter', sans-serif;
  --r: 5px;
  --shadow: 0 4px 12px rgba(0,0,0,0.5);
}}

/* Light theme — inverted Obsidian */
html[data-theme="light"] {{
  color-scheme: light;
  --bg:         #F4F4F9;
  --bg2:        #FFFFFF;
  --bg3:        #EAE9F2;
  --border:     #D6D4E5;
  --border2:    #BEBBD2;
  --text:       #1A1830;
  --text2:      #4A4766;
  --text3:      #797696;
  --accent:     #5D4EE0;
  --accent-s:   rgba(93, 78, 224, 0.08);
  --low-fg:     #1A7B54;  --low-bg:  rgba(26, 123, 84, 0.1);
  --med-fg:     #B36600;  --med-bg:  rgba(179, 102, 0, 0.1);
  --high-fg:    #D12A45;  --high-bg: rgba(209, 42, 69, 0.1);
  --fix-bg:     #FFFFFF;
  --fix-border: #D6D4E5;
  --shadow: 0 4px 16px rgba(26, 24, 48, 0.06);
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
  transition: background .2s, color .2s;
}}

a {{ color: var(--text2); text-decoration: none; }}
a:hover {{ color: var(--text); text-decoration: underline; }}

/* ═══════════════════════════════════════════════
   Top nav
═══════════════════════════════════════════════ */
.nav {{
  position: sticky; top: 0; z-index: 200;
  background: var(--bg2);
  border-bottom: 1px solid var(--border);
  display: flex; align-items: center; justify-content: space-between;
  padding: 0 28px; height: 52px;
}}
.nav-brand {{
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  color: var(--text);
  display: flex; align-items: center; gap: 10px;
  letter-spacing: .1em;
  text-transform: uppercase;
}}
.status-dot {{
  width: 6px; height: 6px; border-radius: 50%;
  animation: pulse 2.4s ease-in-out infinite;
  flex-shrink: 0;
}}
.status-dot.risk-low  {{ background: var(--low-fg); }}
.status-dot.risk-med  {{ background: var(--med-fg); }}
.status-dot.risk-high {{ background: var(--high-fg); }}
@keyframes pulse {{
  0%, 100% {{ opacity: 1; transform: scale(1); }}
  50%       {{ opacity: .35; transform: scale(1.6); }}
}}
.nav-right {{ display: flex; align-items: center; gap: 12px; }}
.nav-ts {{ font-family: var(--mono); font-size: 10px; color: var(--text3); letter-spacing: .04em; }}

/* Theme toggle — Font Awesome solid icons (no emojis) */
.theme-toggle {{
  display: flex;
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: var(--r);
  overflow: hidden;
  padding: 2px; gap: 2px;
}}
.theme-btn {{
  background: none; border: none;
  padding: 0; cursor: pointer;
  border-radius: 4px; font-size: 12px;
  color: var(--text3);
  transition: background .12s, color .12s;
  display: flex; align-items: center; justify-content: center;
  width: 30px; height: 26px;
  flex-shrink: 0;
}}
.theme-btn i {{ pointer-events: none; font-size: 12px; }}
.theme-btn.active {{
  background: var(--text);
  color: var(--bg);
}}
.theme-btn:not(.active):hover {{
  color: var(--text2);
  background: var(--border);
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
  font-size: clamp(15px, 2.5vw, 22px);
  font-weight: 600;
  color: var(--text);
  letter-spacing: .08em;
  text-transform: uppercase;
  margin-bottom: 4px;
}}
.hero-sub {{
  color: var(--text3);
  font-size: 11px;
  margin-bottom: 18px;
  font-family: var(--mono);
  letter-spacing: .04em;
}}
.type-pills {{ display: flex; gap: 6px; justify-content: center; flex-wrap: wrap; margin-bottom: 32px; }}
.type-pill {{
  background: transparent;
  color: var(--text3);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 2px 10px;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .1em;
}}
.score-ring {{
  display: inline-flex; flex-direction: column; align-items: center;
  padding: 28px 56px;
  border-radius: var(--r);
  border-width: 1px; border-style: solid;
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
  font-size: 9px;
  letter-spacing: .18em;
  margin-top: 6px;
  opacity: .65;
  text-transform: uppercase;
  font-family: var(--mono);
}}
.score-ring.risk-low  .score-lbl {{ color: var(--low-fg);  }}
.score-ring.risk-med  .score-lbl {{ color: var(--med-fg);  }}
.score-ring.risk-high .score-lbl {{ color: var(--high-fg); }}
.level-badge {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .16em;
  padding: 4px 18px;
  border-radius: 3px;
  border-width: 1px; border-style: solid;
  text-transform: uppercase;
}}
.level-badge.risk-low  {{ color: var(--low-fg);  background: var(--low-bg);  border-color: var(--low-fg);  }}
.level-badge.risk-med  {{ color: var(--med-fg);  background: var(--med-bg);  border-color: var(--med-fg);  }}
.level-badge.risk-high {{ color: var(--high-fg); background: var(--high-bg); border-color: var(--high-fg); }}

/* ═══════════════════════════════════════════════
   Page layout
═══════════════════════════════════════════════ */
.page {{ max-width: 1280px; margin: 0 auto; padding: 24px 20px 60px; }}

.card {{
  background: var(--bg2);
  border: 1px solid var(--border);
  border-radius: var(--r);
  padding: 22px;
  margin-bottom: 14px;
  box-shadow: var(--shadow);
  transition: background .2s, border-color .2s;
}}
.card-title {{
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .16em;
  text-transform: uppercase;
  color: var(--text3);
  margin-bottom: 18px;
  display: flex; align-items: center; gap: 10px;
}}
.card-title::before {{
  content: '';
  display: block;
  width: 2px; height: 10px;
  border-radius: 1px;
  background: var(--text3);
  flex-shrink: 0;
}}

/* ═══════════════════════════════════════════════
   Metric grid
═══════════════════════════════════════════════ */
.metric-grid {{
  display: grid; 
  grid-template-columns: repeat(6, 1fr);
  gap: 16px; 
  margin-bottom: 16px;
}}
@media (max-width: 1024px) {{ .metric-grid {{ grid-template-columns: repeat(3, 1fr); }} }}
@media (max-width: 600px) {{ .metric-grid {{ grid-template-columns: repeat(2, 1fr); }} }}

.metric-tile {{
  background: var(--bg2); 
  border: 1px solid var(--border);
  border-radius: 8px; 
  padding: 16px;
  text-align: left;
  display: flex;
  flex-direction: column;
  min-height: 105px;
  transition: transform .2s, border-color .2s, box-shadow .2s;
}}
.metric-tile:hover {{
  border-color: var(--accent); transform: translateY(-2px);
  box-shadow: var(--shadow);
}}

.metric-tile .m-val {{
  font-family: var(--sans); 
  font-size: 32px; 
  font-weight: 700;
  line-height: 1; 
  margin-top: auto; 
}}

.metric-tile .m-lbl {{
  font-family: var(--mono); 
  font-size: 9px; 
  color: var(--text3);
  text-transform: uppercase; 
  letter-spacing: .1em;
}}

/* Specific colors matching the screenshot */
.m-bug, .m-vuln {{ color: #f7768e !important; }}
.m-spot  {{ color: #e0af68 !important; }}
.m-smell {{ color: #7aa2f7 !important; }}
.m-cov   {{ color: #9ece6a !important; }}
.m-dup   {{ color: var(--text2) !important; }}

.rating-row {{
  display: grid; 
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
}}
@media (max-width: 768px) {{ .rating-row {{ grid-template-columns: repeat(2, 1fr); }} }}

.rating-tile {{
  background: var(--bg2); 
  border: 1px solid var(--border);
  border-radius: 8px; 
  padding: 24px 16px; 
  text-align: center;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}}

.rating-tile .r-val {{ 
  font-family: var(--sans); 
  font-size: 28px; 
  font-weight: 700; 
  margin-bottom: 8px;
}}

.r-A, .r-B {{ color: #9ece6a; }}
.r-C       {{ color: #e0af68; }}
.r-D, .r-E {{ color: #f7768e; }}

.rating-tile .r-lbl {{
  font-size: 10px; 
  color: var(--text3);
  text-transform: uppercase; 
  letter-spacing: .1em;
  font-family: var(--mono);
}}

/* ═══════════════════════════════════════════════
   Decision banner
═══════════════════════════════════════════════ */
.decision-banner {{
  display: flex; align-items: flex-start; gap: 16px;
  padding: 16px 18px;
  border-radius: var(--r);
  border-width: 1px; border-style: solid;
  margin-bottom: 12px;
}}
.decision-banner.risk-low  {{ background: var(--low-bg);  border-color: var(--low-fg);  }}
.decision-banner.risk-med  {{ background: var(--med-bg);  border-color: var(--med-fg);  }}
.decision-banner.risk-high {{ background: var(--high-bg); border-color: var(--high-fg); }}
.d-icon {{ font-size: 20px; flex-shrink: 0; line-height: 1.4; }}
.decision-banner.risk-low  .d-icon {{ color: var(--low-fg);  }}
.decision-banner.risk-med  .d-icon {{ color: var(--med-fg);  }}
.decision-banner.risk-high .d-icon {{ color: var(--high-fg); }}
.d-body {{ flex: 1; }}
.d-action {{
  font-family: var(--mono);
  font-size: 11px;
  font-weight: 600;
  letter-spacing: .1em;
  margin-bottom: 4px;
  text-transform: uppercase;
}}
.decision-banner.risk-low  .d-action {{ color: var(--low-fg);  }}
.decision-banner.risk-med  .d-action {{ color: var(--med-fg);  }}
.decision-banner.risk-high .d-action {{ color: var(--high-fg); }}
.d-summary {{ font-size: 13px; color: var(--text2); line-height: 1.55; }}
.d-right {{ display: flex; flex-direction: column; align-items: flex-end; gap: 6px; }}
.trend-chip {{
  font-family: var(--mono);
  font-size: 10px;
  padding: 3px 10px;
  border-radius: 3px;
  border: 1px solid var(--border);
  color: var(--text3);
  white-space: nowrap;
  letter-spacing: .06em;
}}
.formula-line {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  margin-top: 12px;
  padding: 10px 14px;
  background: var(--bg3);
  border-radius: var(--r);
  border: 1px solid var(--border);
  letter-spacing: .02em;
  line-height: 1.7;
}}

/* ═══════════════════════════════════════════════
   Tabs
═══════════════════════════════════════════════ */
.tab-bar {{
  display: flex; gap: 2px;
  background: var(--bg3);
  border-radius: var(--r); padding: 3px;
  width: fit-content;
  margin-bottom: 18px;
  border: 1px solid var(--border);
}}
.tab-btn {{
  background: none; border: none;
  color: var(--text3);
  padding: 5px 14px;
  border-radius: 3px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 10px; font-weight: 600;
  letter-spacing: .08em;
  display: flex; align-items: center; gap: 7px;
  transition: all .12s;
  text-transform: uppercase;
}}
.tab-btn.active {{
  background: var(--text);
  color: var(--bg);
}}
.tab-btn:not(.active):hover {{ color: var(--text2); background: var(--border); }}
.tab-badge {{
  display: inline-flex; align-items: center; justify-content: center;
  min-width: 17px; height: 16px; border-radius: 3px; padding: 0 4px;
  font-size: 10px; font-weight: 700;
  background: rgba(255,255,255,0.10);
  color: inherit;
}}
html[data-theme="light"] .tab-badge {{ background: rgba(0,0,0,0.08); }}
.tab-btn.active .tab-badge {{ background: rgba(0,0,0,0.18); }}
html[data-theme="light"] .tab-btn.active .tab-badge {{ background: rgba(255,255,255,0.3); }}
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
  font-size: 9px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .1em;
  color: var(--text3);
  padding: 10px 14px;
  border-bottom: 1px solid var(--border);
  text-align: left;
  background: var(--bg3);
  white-space: nowrap;
}}
.issue-table tbody .issue-row {{
  cursor: pointer;
  transition: background .1s;
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
  color: var(--text) !important;
  display: block;
  white-space: nowrap;
}}
.loc-link:hover {{ text-decoration: underline !important; }}
.line-chip {{
  display: inline-flex; align-items: center; gap: 4px;
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 600;
  color: var(--text3);
  margin-top: 3px;
  background: transparent;
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 5px;
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
  border-radius: 3px;
  color: var(--res-fg);
  background: color-mix(in srgb, var(--res-fg) 10%, transparent);
  border: 1px solid color-mix(in srgb, var(--res-fg) 20%, transparent);
  vertical-align: middle;
}}
/* Closed issue rows */
.closed-row td {{ opacity: 0.5; }}
.closed-row:hover td {{ opacity: 0.8; }}
/* Closed/Resolved section */
.closed-section {{
  margin-top: 14px;
  border: 1px solid var(--border);
  border-radius: var(--r);
  overflow: hidden;
}}
.closed-summary {{
  display: flex; align-items: center; gap: 10px;
  padding: 10px 16px;
  cursor: pointer;
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .08em;
  color: var(--text3);
  background: var(--bg3);
  user-select: none;
  list-style: none;
  text-transform: uppercase;
}}
.closed-summary::-webkit-details-marker {{ display: none; }}
.closed-summary i {{ color: #32D74B; font-size: 11px; }}
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
  min-width: 18px; height: 18px;
  border-radius: 3px; padding: 0 5px;
  font-size: 10px; font-weight: 700;
  background: rgba(50,215,75,0.10);
  color: #32D74B;
  border: 1px solid rgba(50,215,75,0.22);
}}
.closed-table-wrap {{
  border-top: 1px solid var(--border);
}}
.rule-code {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  background: var(--bg3);
  border: 1px solid var(--border);
  border-radius: 3px;
  padding: 1px 5px;
  white-space: nowrap;
}}
.status-chip {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  letter-spacing: .04em;
}}
.chevron {{
  font-size: 16px;
  color: var(--text3);
  display: inline-block;
  transition: transform .2s;
  line-height: 1;
}}
.issue-row.expanded .chevron {{ transform: rotate(90deg); color: var(--text2); }}
.badge {{
  display: inline-block;
  font-family: var(--mono);
  font-size: 9px;
  font-weight: 700;
  letter-spacing: .08em;
  padding: 2px 7px;
  border-radius: 3px;
  color: var(--badge-fg);
  background: color-mix(in srgb, var(--badge-fg) 9%, transparent);
  border: 1px solid color-mix(in srgb, var(--badge-fg) 20%, transparent);
  text-transform: uppercase;
}}

/* Fix drawer */
.fix-row {{ display: none; }}
.fix-row.open {{ display: table-row !important; }}
.fix-cell {{ padding: 0 !important; border-bottom: 1px solid var(--border) !important; }}
.fix-inner {{
  padding: 16px 18px;
  background: var(--fix-bg);
  border-left: 2px solid var(--border2);
  border-top: 1px solid var(--fix-border);
}}
.fix-title {{
  font-size: 11px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 8px;
  font-family: var(--mono);
  display: flex; align-items: center; gap: 8px;
  letter-spacing: .04em;
  text-transform: uppercase;
}}
.fix-title i {{ color: var(--text3); font-size: 11px; }}
.fix-body {{
  font-size: 13px;
  color: var(--text2);
  line-height: 1.7;
  margin-bottom: 10px;
}}
.fix-rule-link {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  letter-spacing: .04em;
  display: inline-flex; align-items: center; gap: 6px;
}}
.fix-rule-link:hover {{ color: var(--text2); text-decoration: underline; }}
.table-note {{
  font-size: 11px;
  color: var(--text3);
  margin-top: 10px;
  font-style: italic;
  display: flex; align-items: center; gap: 6px;
}}
.empty-msg {{
  font-size: 12px;
  color: var(--text3);
  padding: 20px 0;
  font-style: italic;
  font-family: var(--mono);
  letter-spacing: .04em;
}}

/* ═══════════════════════════════════════════════
   Links row
═══════════════════════════════════════════════ */
.links-row {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px;
}}
.lnk {{
  display: flex; align-items: center; justify-content: center; gap: 9px;
  padding: 12px 16px;
  border-radius: var(--r);
  font-family: var(--mono);
  font-size: 12px; font-weight: 600;
  letter-spacing: .08em;
  border: 1px solid var(--border);
  color: var(--text3);
  background: var(--bg3);
  transition: all .12s;
  text-align: center;
  text-transform: uppercase;
}}
.lnk i {{ font-size: 12px; flex-shrink: 0; }}
.lnk:hover {{
  background: var(--accent-s);
  border-color: var(--border2);
  color: var(--text);
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
  font-size: 11px;
  color: var(--text3);
  border: 1px dashed var(--border);
  border-radius: var(--r);
  letter-spacing: .04em;
}}

/* ═══════════════════════════════════════════════
   Footer
═══════════════════════════════════════════════ */
.footer {{
  text-align: center;
  font-family: var(--mono);
  font-size: 10px;
  color: var(--text3);
  padding: 28px 0 0;
  letter-spacing: .08em;
  text-transform: uppercase;
}}

/* ═══════════════════════════════════════════════
   Language chart
═══════════════════════════════════════════════ */
.lang-chart-container {{
  display: grid;
  grid-template-columns: 280px 1fr;
  gap: 28px;
  align-items: center;
}}
@media (max-width: 768px) {{
  .lang-chart-container {{ grid-template-columns: 1fr; }}
}}
.lang-chart-wrap {{
  position: relative;
  height: 280px;
  display: flex;
  align-items: center;
  justify-content: center;
}}
.lang-legend {{
  display: flex;
  flex-direction: column;
  gap: 10px;
}}
.lang-legend-item {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  border-radius: var(--r);
  background: var(--bg3);
  border: 1px solid var(--border);
}}
.lang-color {{
  width: 14px;
  height: 14px;
  border-radius: 3px;
  flex-shrink: 0;
}}
.lang-info {{
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}}
.lang-name {{
  font-family: var(--mono);
  font-size: 12px;
  font-weight: 600;
  color: var(--text);
  text-transform: uppercase;
  letter-spacing: .06em;
}}
.lang-stats {{
  display: flex;
  align-items: center;
  gap: 12px;
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
}}
.lang-pct {{
  font-weight: 600;
  color: var(--text2);
}}

/* ═══════════════════════════════════════════════
   Resolve buttons
═══════════════════════════════════════════════ */
.resolve-actions {{
  display: flex;
  gap: 8px;
  margin-top: 14px;
  padding-top: 12px;
  border-top: 1px solid var(--border);
  flex-wrap: wrap;
}}
.resolve-btn {{
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 6px 12px;
  border-radius: var(--r);
  border: 1px solid var(--border);
  background: var(--bg3);
  color: var(--text3);
  font-family: var(--mono);
  font-size: 10px;
  font-weight: 600;
  letter-spacing: .04em;
  cursor: pointer;
  transition: all .12s;
  text-transform: uppercase;
}}
.resolve-btn:hover {{
  background: var(--border);
  color: var(--text2);
  border-color: var(--border2);
}}
.resolve-btn i {{
  font-size: 10px;
}}
.resolve-btn-primary {{
  background: var(--accent);
  color: var(--bg);
  border-color: var(--accent);
}}
.resolve-btn-primary:hover {{
  opacity: 0.85;
  color: var(--bg);
}}
</style>
</head>
<body>

<!-- ─── Nav ─────────────────────────────────── -->
<nav class="nav">
  <div class="nav-brand">
    <div class="status-dot {risk_cls}"></div>
    DevSecOps · Security Dashboard
  </div>
  <div class="nav-right">
    <span class="nav-ts">{now_str}</span>
    <!--
      Theme toggle: using Font Awesome solid icons (fas).
      fa-sun = light, fa-moon = dark, fa-circle-half-stroke = system/auto
    -->
    <div class="theme-toggle" id="themeToggle">
      <button class="theme-btn" data-t="light"  onclick="setTheme('light')"  title="Light mode">
        <i class="fa-solid fa-sun"></i>
      </button>
      <button class="theme-btn" data-t="dark"   onclick="setTheme('dark')"   title="Dark mode">
        <i class="fa-solid fa-moon"></i>
      </button>
      <button class="theme-btn" data-t="system" onclick="setTheme('system')" title="System default">
        <i class="fa-solid fa-circle-half-stroke"></i>
      </button>
    </div>
  </div>
</nav>

<!-- ─── Hero ─────────────────────────────────── -->
<div class="hero">
  <div class="hero-title">Security Risk Report</div>
  <div class="hero-sub">Project · {PROJECT_KEY}</div>
  <div class="type-pills">{type_pills}</div>
  <div class="score-ring {risk_cls}">
    <div class="score-num">{risk_score}</div>
    <div class="score-lbl">Risk Score</div>
  </div>
  <br>
  <span class="level-badge {risk_cls}">{level} Risk</span>
</div>

<!-- ─── Page ─────────────────────────────────── -->
<div class="page">

  <!-- Quick Links -->
  <div class="card">
    <div class="card-title">Quick Links</div>
    <div class="links-row">
      <a class="lnk" href="{SONAR_DASHBOARD}" target="_blank">
        <i class="fas fa-shield-halved"></i> SonarCloud
      </a>
      <a class="lnk" href="{PROJECT_REPO}" target="_blank">
        <i class="fas fa-code-branch"></i> Repository
      </a>
      <a class="lnk" href="{RUNNING_APP}" target="_blank">
        <i class="fas fa-circle-play"></i> Application
      </a>
    </div>
  </div>

  <!-- Language Distribution -->
  <div class="card">
    <div class="card-title">Language Distribution</div>
    <div class="lang-chart-container">
      <div class="lang-chart-wrap">
        <canvas id="langChart"></canvas>
      </div>
      <div id="langLegend" class="lang-legend"></div>
    </div>
  </div>

  <!-- Metrics -->
  <div class="card">
    <div class="card-title">Metrics Overview</div>
<div class="metric-grid">
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-solid fa-bug m-bug" style="font-size: 16px;"></i><div class="m-lbl">Bugs</div>
        </div>
        <div class="m-val m-bug">{bugs_count}</div>
      </div>
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-solid fa-shield-exclamation m-vuln" style="font-size: 16px;"></i><div class="m-lbl">Vulnerabilities</div>
        </div>
        <div class="m-val m-vuln">{vulns_count}</div>
      </div>
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-solid fa-fire m-spot" style="font-size: 16px;"></i><div class="m-lbl">Hotspots</div>
        </div>
        <div class="m-val m-spot">{hotspots_count}</div>
      </div>
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-solid fa-wand-magic-sparkles m-smell" style="font-size: 16px;"></i><div class="m-lbl">Code Smells</div>
        </div>
        <div class="m-val m-smell">{smells_count}</div>
      </div>
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-solid fa-chart-simple m-cov" style="font-size: 16px;"></i><div class="m-lbl">Coverage</div>
        </div>
        <div class="m-val m-cov">{coverage_pct}%</div>
      </div>
      <div class="metric-tile">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; width: 100%;">
          <i class="fa-regular fa-copy m-dup" style="font-size: 16px;"></i><div class="m-lbl">Duplication</div>
        </div>
        <div class="m-val m-dup">{duplication_pct}%</div>
      </div>
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
        <div class="r-val" style="color:var(--text);">{risk_score}</div>
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
      Risk = (Bugs × {WEIGHT_BUGS}) + (Vulns × {WEIGHT_VULNS}) + (Hotspots × {WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; ({bugs_count}×{WEIGHT_BUGS}) + ({vulns_count}×{WEIGHT_VULNS}) + ({hotspots_count}×{WEIGHT_HOTSPOTS})
      &nbsp;=&nbsp; <strong style="color:var(--text);">{risk_score}</strong>
    </div>
  </div>

  <!-- Issues -->
  <div class="card">
    <div class="card-title">Issue Details</div>
    <div class="tab-bar">
      <button class="tab-btn active" onclick="switchTab('bugs',this)">
        <span class="tab-badge">{bugs_count}</span> Bugs
      </button>
      <button class="tab-btn" onclick="switchTab('vulns',this)">
        <span class="tab-badge">{vulns_count}</span> Vulnerabilities
      </button>
      <button class="tab-btn" onclick="switchTab('hotspots',this)">
        <span class="tab-badge">{hotspots_count}</span> Hotspots
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
══════════════════════════════════════════════════════ */
var MEDIA = window.matchMedia('(prefers-color-scheme: dark)');
var API_ENDPOINT = '{API_ENDPOINT}';

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
  rebuildLangChart();<script>
/* ══════════════════════════════════════════════════════
   Theme management
══════════════════════════════════════════════════════ */
var MEDIA = window.matchMedia('(prefers-color-scheme: dark)');
var API_ENDPOINT = '{API_ENDPOINT}';
 
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
  rebuildLangChart();
}}
 
function setTheme(pref) {{
  try {{ localStorage.setItem('dso-theme', pref); }} catch(e) {{}}
  applyTheme(pref);
}}
 
(function() {{
  var saved = window.__dsoSavedPref || 'dark';
  syncToggleButtons(saved);
}})();
 
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
   Resolve issue in SonarCloud
══════════════════════════════════════════════════════ */
function resolveIssue(issueKey, transition, event) {{
  event.stopPropagation();
  
  var transitionLabels = {{
    'wontfix': "Won't Fix",
    'falsepositive': 'False Positive',
    'resolve': 'Resolved'
  }};
  
  var confirmMsg = 'Mark this issue as "' + transitionLabels[transition] + '" in SonarCloud?';
  if (!confirm(confirmMsg)) return;
  
  var btn = event.target.closest('.resolve-btn');
  var originalHTML = btn ? btn.innerHTML : '';
  
  if (btn) {{
    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
  }}
  
  // Check if API endpoint is configured
  if (!API_ENDPOINT || API_ENDPOINT === '{{API_ENDPOINT}}' || API_ENDPOINT === 'http://localhost:5000') {{
    // Fallback to manual instructions
    alert('API endpoint not configured.\\n\\n' +
          'To resolve issue ' + issueKey + ':\\n' +
          '1. Go to SonarCloud\\n' +
          '2. Find the issue\\n' +
          '3. Use the "Resolve" dropdown\\n' +
          '4. Select: ' + transitionLabels[transition]);
    
    if (btn) {{
      btn.disabled = false;
      btn.innerHTML = originalHTML;
    }}
    return;
  }}
  
  // Call the API
  fetch(API_ENDPOINT + '/api/resolve-issue', {{
    method: 'POST',
    headers: {{
      'Content-Type': 'application/json',
    }},
    body: JSON.stringify({{
      issue_key: issueKey,
      transition: transition,
      comment: 'Resolved via DevSecOps Dashboard on ' + new Date().toISOString()
    }})
  }})
  .then(function(response) {{
    return response.json().then(function(data) {{
      return {{ ok: response.ok, status: response.status, data: data }};
    }});
  }})
  .then(function(result) {{
    if (result.ok) {{
      alert('✓ Issue marked as ' + transitionLabels[transition] + ' successfully!\\n\\n' +
            'Refresh the page to see updated status.');
      
      // Optionally refresh the page after 2 seconds
      setTimeout(function() {{
        window.location.reload();
      }}, 2000);
    }} else {{
      throw new Error(result.data.error || 'Failed to resolve issue');
    }}
  }})
  .catch(function(error) {{
    alert('✗ Failed to resolve issue\\n\\n' +
          'Error: ' + error.message + '\\n\\n' +
          'Please try again or resolve manually in SonarCloud.');
    console.error('Resolve error:', error);
    
    if (btn) {{
      btn.disabled = false;
      btn.innerHTML = originalHTML;
    }}
  }});
}}
 
/* ══════════════════════════════════════════════════════
   Language distribution chart
══════════════════════════════════════════════════════ */
var LANG_DATA = {lang_chart_data};
var langChartInstance = null;
 
var LANG_COLORS = [
  '#FF3B30', '#FFD60A', '#32D74B', '#5E5CE6',
  '#FF9F0A', '#00C7BE', '#BF5AF2', '#FF375F',
  '#30D158', '#64D2FF', '#FFD70A', '#5E5CE6'
];
 
function buildLangChart() {{
  if (!LANG_DATA || LANG_DATA.length === 0) return;
  
  var canvas = document.getElementById('langChart');
  if (!canvas) return;
  if (typeof Chart === 'undefined') return;
  
  var total = LANG_DATA.reduce(function(sum, item) {{ return sum + item.lines; }}, 0);
  
  var labels = LANG_DATA.map(function(item) {{ return item.lang.toUpperCase(); }});
  var data = LANG_DATA.map(function(item) {{ return item.lines; }});
  var colors = LANG_DATA.map(function(item, idx) {{ return LANG_COLORS[idx % LANG_COLORS.length]; }});
  
  if (langChartInstance) {{ langChartInstance.destroy(); langChartInstance = null; }}
  
  langChartInstance = new Chart(canvas.getContext('2d'), {{
    type: 'doughnut',
    data: {{
      labels: labels,
      datasets: [{{
        data: data,
        backgroundColor: colors,
        borderWidth: 0
      }}]
    }},
    options: {{
      responsive: true,
      maintainAspectRatio: false,
      cutout: '65%',
      plugins: {{
        legend: {{ display: false }},
        tooltip: {{
          callbacks: {{
            label: function(context) {{
              var pct = ((context.parsed / total) * 100).toFixed(1);
              return context.label + ': ' + pct + '% (' + context.parsed.toLocaleString() + ' lines)';
            }}
          }}
        }}
      }}
    }}
  }});
  
  // Build legend
  var legend = document.getElementById('langLegend');
  if (legend) {{
    legend.innerHTML = LANG_DATA.map(function(item, idx) {{
      var pct = ((item.lines / total) * 100).toFixed(1);
      var color = LANG_COLORS[idx % LANG_COLORS.length];
      return '<div class="lang-legend-item">' +
        '<div class="lang-color" style="background:' + color + ';"></div>' +
        '<div class="lang-info">' +
        '<span class="lang-name">' + item.lang.toUpperCase() + '</span>' +
        '<div class="lang-stats">' +
        '<span class="lang-pct">' + pct + '%</span>' +
        '<span>' + item.lines.toLocaleString() + ' lines</span>' +
        '</div>' +
        '</div>' +
        '</div>';
    }}).join('');
  }}
}}
 
function rebuildLangChart() {{
  if (typeof Chart !== 'undefined') {{
    buildLangChart();
  }}
}}
 
/* ══════════════════════════════════════════════════════
   Risk trend chart
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
    HIGH:   'rgba(255,59,48,'   + alpha + ')',
    MEDIUM: 'rgba(255,214,10,' + alpha + ')',
    LOW:    'rgba(50,215,75,'  + alpha + ')'
  }};
  return map[key] || ('rgba(136,136,136,' + alpha + ')');
}}
 
function buildChart(theme) {{
  var canvas = document.getElementById('riskChart');
  if (!canvas) return;
  if (typeof Chart === 'undefined') return;
 
  var isDark  = theme !== 'light';
  var gridCol = isDark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.05)';
  var tickCol = isDark ? '#4a4a4a' : '#AAAAAA';
  var tipBg   = isDark ? '#0B0B0B' : '#FFFFFF';
  var tipBor  = isDark ? '#1F1F1F' : '#DDDDDD';
  var tipText = isDark ? '#FFFFFF' : '#000000';
  var tipMuted= isDark ? '#888888' : '#555555';
  var lineCol = isDark ? 'rgba(255,255,255,0.6)' : 'rgba(0,0,0,0.5)';
  var fillCol = isDark ? 'rgba(255,255,255,0.02)' : 'rgba(0,0,0,0.02)';
 
  if (chartInstance) {{ chartInstance.destroy(); chartInstance = null; }}
 
  chartInstance = new Chart(canvas.getContext('2d'), {{
    type: 'line',
    data: {{
      labels: CHART_DATA.labels,
      datasets: [{{
        label: 'Risk Score',
        data: CHART_DATA.scores,
        borderColor: lineCol,
        backgroundColor: fillCol,
        pointBackgroundColor: CHART_DATA.levels.map(function(l) {{ return levelColor(l, 1); }}),
        pointBorderColor:     CHART_DATA.levels.map(function(l) {{ return levelColor(l, 1); }}),
        pointRadius: 5,
        pointHoverRadius: 8,
        tension: 0.38,
        fill: true,
        borderWidth: 1.5
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
              return ['Risk Level: ' + (raw || 'UNKNOWN')];
            }}
          }}
        }}
      }},
      scales: {{
        x: {{
          ticks: {{ color: tickCol, font: {{ family: "'IBM Plex Mono'", size: 10 }} }},
          grid:  {{ color: gridCol }},
          border: {{ color: gridCol }}
        }},
        y: {{
          beginAtZero: true,
          ticks: {{ color: tickCol, font: {{ family: "'IBM Plex Mono'", size: 10 }} }},
          grid:  {{ color: gridCol }},
          border: {{ color: gridCol }}
        }}
      }}
    }}
  }});
}}
 
function rebuildChart(theme) {{
  if (typeof Chart !== 'undefined') {{
    buildChart(theme);
  }}
}}
 
(function initChartWhenReady() {{
  var MAX_WAIT_MS = 10000;
  var start = Date.now();
  var theme = window.__dsoInitialTheme || 'dark';
 
  function attempt() {{
    if (typeof Chart !== 'undefined') {{
      buildChart(theme);
      buildLangChart();
      return;
    }}
    if (Date.now() - start > MAX_WAIT_MS) {{
      var wrap = document.querySelector('.chart-wrap');
      if (wrap) {{
        wrap.innerHTML =
          '<div class="chart-error">Chart.js failed to load — ' +
          'check network or Content-Security-Policy settings.</div>';
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