# DevSecOps Risk Analysis Engine

Plug-and-play security analysis for any repo.

## Quick Install

### 1. Copy to your repo:
```bash
mkdir -p .github/workflows
cp -r risk-engine .github/workflows/devsecops.yml your-repo/
```

### 2. Set GitHub Secrets:
- `SONAR_TOKEN` - Your SonarCloud token
- Go to repo Settings → Secrets → Actions → New secret

### 3. Configure:
Edit `.github/workflows/devsecops.yml`:
```yaml
env:
  SONAR_ORG: your-org-name  # ← Change this
```

### 4. Push and run:
```bash
git add .
git commit -m "Add DevSecOps analysis"
git push
```

Dashboard will be at:
`https://YOUR_USERNAME.github.io/YOUR_REPO/security-report.html`

## Standalone API Server

Run the analysis API locally:
```bash
cd risk-engine
pip install -r requirements-api.txt
export SONAR_TOKEN="xxx"
export PROJECT_KEY="xxx"
python api-server.py
```

Or via Docker:
```bash
cd risk-engine
docker build -t risk-engine .
docker run -p 5000:5000 \
  -e SONAR_TOKEN="xxx" \
  -e PROJECT_KEY="xxx" \
  risk-engine
```

## What it does:
- ✅ Scans ALL languages (Python, Java, .NET, Node, Go, etc.)
- ✅ Generates HTML security dashboard
- ✅ Blocks HIGH risk deployments
- ✅ Publishes report to GitHub Pages
- ✅ Provides API for issue resolution