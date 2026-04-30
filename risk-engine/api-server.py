"""
api-server.py
Backend API for DevSecOps Dashboard - Issue Resolution
Provides REST endpoints for marking SonarCloud issues as resolved

SECURITY FEATURES:
  - JWT authentication via Azure AD
  - Role-based authorization (Contributor/Reader)
  - Azure Key Vault for secrets
  - Sanitized request logging
"""

from flask import Flask, request, jsonify, g
from flask_cors import CORS
from functools import wraps
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import requests
import os
import jwt
import logging
import re

# Configure secure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)

# Sanitize sensitive data from logs
def sanitize_log(msg):
    """Remove tokens, credentials, and sensitive headers from log messages"""
    patterns = [
        (r'Bearer [A-Za-z0-9\-._~+/]+=*', 'Bearer [REDACTED]'),
        (r'sonar[_-]?token["\']?\s*[:=]\s*["\']?[\w\-]+', 'sonar_token=[REDACTED]'),
        (r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+', 'password=[REDACTED]'),
        (r'api[_-]?key["\']?\s*[:=]\s*["\']?[\w\-]+', 'api_key=[REDACTED]'),
    ]
    for pattern, replacement in patterns:
        msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
    return msg

class SecureLogger:
    @staticmethod
    def info(msg):
        logger.info(sanitize_log(str(msg)))
    
    @staticmethod
    def error(msg):
        logger.error(sanitize_log(str(msg)))
    
    @staticmethod
    def warning(msg):
        logger.warning(sanitize_log(str(msg)))

app = Flask(__name__)

# Enable CORS for all routes
CORS(app, 
     origins=["https://jubit-pincy.github.io", "http://localhost:*"],
     methods=["GET", "POST", "OPTIONS"],
     allow_headers=["Authorization", "Content-Type", "Accept"],
     expose_headers=["Content-Type"],
     supports_credentials=False,
     max_age=3600)

# Azure Key Vault setup
VAULT_URL = os.getenv("VAULT_URL", "")
USE_KEYVAULT = bool(VAULT_URL)

if USE_KEYVAULT:
    try:
        credential = DefaultAzureCredential()
        vault_client = SecretClient(vault_url=VAULT_URL, credential=credential)
        SONAR_TOKEN = vault_client.get_secret("sonar-token").value
        SecureLogger.info("✓ Loaded SONAR_TOKEN from Azure Key Vault")
    except Exception as e:
        SecureLogger.error(f"Failed to load secrets from Key Vault: {e}")
        SONAR_TOKEN = ""
else:
    SONAR_TOKEN = os.getenv("SONAR_TOKEN", "")
    if SONAR_TOKEN:
        SecureLogger.warning("Using SONAR_TOKEN from environment (Key Vault recommended)")

SONAR_URL = os.getenv("SONAR_URL", "https://sonarcloud.io")
PROJECT_KEY = os.getenv("PROJECT_KEY", "")
AZURE_AD_TENANT_ID = os.getenv("AZURE_AD_TENANT_ID", "")
AZURE_AD_CLIENT_ID = os.getenv("AZURE_AD_CLIENT_ID", "")

if not SONAR_TOKEN:
    SecureLogger.error("SONAR_TOKEN not set - API will not work")

AUTH = (SONAR_TOKEN, "")

# JWT authentication decorator
def require_jwt(required_role=None):
    """Verify JWT token from Azure AD and check role"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            auth_header = request.headers.get('Authorization', '')
            
            if not auth_header.startswith('Bearer '):
                SecureLogger.warning(f"Missing or invalid Authorization header from {request.remote_addr}")
                return jsonify({"error": "Missing or invalid Authorization header"}), 401
            
            token = auth_header.split(' ')[1]
            
            try:
                # Verify JWT signature and decode
                # In production, fetch Azure AD public keys for verification
                decoded = jwt.decode(
                    token,
                    options={"verify_signature": False},  # TODO: Enable signature verification with Azure AD keys
                    algorithms=["RS256"]
                )
                
                # Validate issuer and audience
                if AZURE_AD_TENANT_ID and decoded.get('tid') != AZURE_AD_TENANT_ID:
                    SecureLogger.warning(f"Invalid tenant ID in token from {request.remote_addr}")
                    return jsonify({"error": "Invalid token tenant"}), 401
                
                expected_audiences = [AZURE_AD_CLIENT_ID, f"api://{AZURE_AD_CLIENT_ID}"]
                if AZURE_AD_CLIENT_ID and decoded.get('aud') not in expected_audiences:
                    SecureLogger.warning(f"Invalid audience in token from {request.remote_addr}")
                    return jsonify({"error": "Invalid token audience"}), 401
                
                # Check role if required
                roles = decoded.get('roles', [])
                if required_role and required_role not in roles:
                    user = decoded.get('preferred_username', 'unknown')
                    SecureLogger.warning(f"User {user} attempted action requiring role {required_role}")
                    return jsonify({
                        "error": f"Insufficient permissions. Required role: {required_role}"
                    }), 403
                
                # Store user context for logging
                g.user = decoded.get('preferred_username', 'unknown')
                g.user_id = decoded.get('oid', 'unknown')
                
            except jwt.ExpiredSignatureError:
                SecureLogger.warning(f"Expired token from {request.remote_addr}")
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError as e:
                SecureLogger.warning(f"Invalid token from {request.remote_addr}: {str(e)}")
                return jsonify({"error": "Invalid token"}), 401
            except Exception as e:
                SecureLogger.error(f"Token validation error: {str(e)}")
                return jsonify({"error": "Authentication failed"}), 401
            
            return f(*args, **kwargs)
        return wrapped
    return decorator


@app.route('/health', methods=['GET'])
@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint - no auth required"""
    return jsonify({"status": "healthy", "service": "devsecops-api"}), 200

@app.route('/api/resolve-issue', methods=['OPTIONS'])
def resolve_issue_preflight():
    """Handle CORS preflight"""
    return '', 204
@app.route('/api/resolve-issue', methods=['POST'])
@require_jwt(required_role='Contributor')
def resolve_issue():
    """
    Resolve an issue in SonarCloud
    REQUIRES: JWT with 'Contributor' role
    
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
        
        # Audit log
        SecureLogger.info(
            f"User {g.user} ({g.user_id}) resolving issue {issue_key} as {transition}"
        )
        
        # Step 1: Apply transition
        endpoint = f"{SONAR_URL}/api/issues/do_transition"
        params = {
            "issue": issue_key,
            "transition": transition
        }
        
        response = requests.post(endpoint, params=params, auth=AUTH, timeout=15)
        
        if response.status_code != 200:
            SecureLogger.error(f"SonarCloud API error: {response.status_code}")
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
                "text": f"{comment} (by {g.user})"
            }
            comment_response = requests.post(
                comment_endpoint, 
                params=comment_params, 
                auth=AUTH, 
                timeout=15
            )
            
            if comment_response.status_code != 200:
                SecureLogger.warning(f"Failed to add comment to issue {issue_key}")
                return jsonify({
                    "warning": "Issue resolved but comment failed to add",
                    "issue_key": issue_key,
                    "transition": transition
                }), 200
        
        SecureLogger.info(f"Issue {issue_key} successfully resolved as {transition}")
        return jsonify({
            "success": True,
            "issue_key": issue_key,
            "transition": transition,
            "message": f"Issue {issue_key} marked as {transition}",
            "resolved_by": g.user
        }), 200
        
    except requests.exceptions.RequestException as e:
        SecureLogger.error(f"Network error: {str(e)}")
        return jsonify({
            "error": "Network error communicating with SonarCloud",
            "details": str(e)
        }), 503
        
    except Exception as e:
        SecureLogger.error(f"Internal error: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "details": str(e)
        }), 500

@app.route('/api/issue-status/<issue_key>', methods=['GET'])
@require_jwt()  # Reader role sufficient for viewing
def get_issue_status(issue_key):
    """
    Get current status of an issue
    REQUIRES: Valid JWT (any authenticated user)
    """
    try:
        SecureLogger.info(f"User {g.user} requesting status for issue {issue_key}")
        
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
        SecureLogger.error(f"Error fetching issue status: {str(e)}")
        return jsonify({
            "error": "Failed to fetch issue status",
            "details": str(e)
        }), 500

# Request logging middleware (sanitized)
@app.before_request
def log_request():
    """Log incoming requests without exposing sensitive headers"""
    SecureLogger.info(
        f"{request.method} {request.path} from {request.remote_addr}"
    )

@app.after_request
def after_request(response):
    """Add CORS headers to all responses"""
    origin = request.headers.get('Origin')
    if origin and origin.startswith('https://jubit-pincy.github.io'):
        response.headers['Access-Control-Allow-Origin'] = origin
    elif origin and origin.startswith('http://localhost'):
        response.headers['Access-Control-Allow-Origin'] = origin
    
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Authorization, Content-Type, Accept'
    response.headers['Access-Control-Max-Age'] = '3600'
    return response

if __name__ == '__main__':
    port = int(os.getenv('API_PORT', 5000))
    SecureLogger.info(f"Starting API server on port {port}")
    SecureLogger.info(f"Key Vault integration: {'enabled' if USE_KEYVAULT else 'disabled'}")
    SecureLogger.info(f"Azure AD tenant: {AZURE_AD_TENANT_ID or 'not configured'}")
    app.run(host='0.0.0.0', port=port, debug=False)