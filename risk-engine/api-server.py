"""
api-server.py
Backend API for DevSecOps Dashboard - Issue Resolution
Provides REST endpoints for marking SonarCloud issues as resolved
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for GitHub Pages / static HTML

SONAR_URL = os.getenv("SONAR_URL", "https://sonarcloud.io")
SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
PROJECT_KEY = os.getenv("PROJECT_KEY", "")

if not SONAR_TOKEN:
    print("WARNING: SONAR_TOKEN not set - API will not work")

AUTH = (SONAR_TOKEN, "")

@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "devsecops-api"}), 200

@app.route('/api/resolve-issue', methods=['POST'])
def resolve_issue():
    """
    Resolve an issue in SonarCloud
    
    Request body:
    {
        "issue_key": "AY...",
        "transition": "wontfix" | "falsepositive" | "resolve",
        "comment": "Optional comment"
    }
    """
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        issue_key = data.get('issue_key')
        transition = data.get('transition', 'wontfix')
        comment = data.get('comment', '')
        
        if not issue_key:
            return jsonify({"error": "issue_key is required"}), 400
        
        # Valid transitions in SonarCloud
        valid_transitions = ['wontfix', 'falsepositive', 'resolve', 'confirm', 'unconfirm']
        if transition not in valid_transitions:
            return jsonify({
                "error": f"Invalid transition. Must be one of: {', '.join(valid_transitions)}"
            }), 400
        
        # Step 1: Apply transition
        endpoint = f"{SONAR_URL}/api/issues/do_transition"
        params = {
            "issue": issue_key,
            "transition": transition
        }
        
        response = requests.post(endpoint, params=params, auth=AUTH, timeout=30)
        
        if response.status_code != 200:
            return jsonify({
                "error": "Failed to resolve issue in SonarCloud",
                "details": response.text,
                "status_code": response.status_code
            }), response.status_code
        
        # Step 2: Add comment if provided
        if comment:
            comment_endpoint = f"{SONAR_URL}/api/issues/add_comment"
            comment_params = {
                "issue": issue_key,
                "text": comment
            }
            comment_response = requests.post(
                comment_endpoint, 
                params=comment_params, 
                auth=AUTH, 
                timeout=30
            )
            
            if comment_response.status_code != 200:
                return jsonify({
                    "warning": "Issue resolved but comment failed to add",
                    "issue_key": issue_key,
                    "transition": transition
                }), 200
        
        return jsonify({
            "success": True,
            "issue_key": issue_key,
            "transition": transition,
            "message": f"Issue {issue_key} marked as {transition}"
        }), 200
        
    except requests.exceptions.RequestException as e:
        return jsonify({
            "error": "Network error communicating with SonarCloud",
            "details": str(e)
        }), 503
        
    except Exception as e:
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/api/issue-status/<issue_key>', methods=['GET'])
def get_issue_status(issue_key):
    """Get current status of an issue"""
    try:
        endpoint = f"{SONAR_URL}/api/issues/search"
        params = {
            "issues": issue_key
        }
        
        response = requests.get(endpoint, params=params, auth=AUTH, timeout=30)
        
        if response.status_code != 200:
            return jsonify({"error": "Failed to fetch issue status"}), response.status_code
        
        data = response.json()
        issues = data.get('issues', [])
        
        if not issues:
            return jsonify({"error": "Issue not found"}), 404
        
        issue = issues[0]
        return jsonify({
            "issue_key": issue_key,
            "status": issue.get('status'),
            "resolution": issue.get('resolution'),
            "severity": issue.get('severity'),
            "type": issue.get('type')
        }), 200
        
    except Exception as e:
        return jsonify({
            "error": "Failed to fetch issue status",
            "details": str(e)
        }), 500

if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)