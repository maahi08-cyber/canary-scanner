# Canary Scanner - Complete Setup Guide
=============================================

This guide provides step-by-step instructions for setting up and running the Canary Scanner in different environments.

## 📋 Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Local Installation](#local-installation)
- [Docker Setup](#docker-setup)
- [GitHub Actions Setup](#github-actions-setup)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

## 🚀 Quick Start

For the impatient - get scanning in 3 commands:

```bash
# Clone and setup
git clone <repository-url>
cd canary-scanner
python -m venv venv && source venv/bin/activate

# Install and run
pip install -r requirements.txt
python canary.py .
```

## 📋 Prerequisites

### System Requirements
- **Python**: 3.11 or higher (3.9+ supported but 3.11 recommended)
- **Operating System**: Linux, macOS, or Windows
- **Memory**: Minimum 512MB RAM (2GB+ recommended for large repositories)
- **Disk Space**: 100MB for installation, additional space for scan results

### Optional Requirements
- **Docker**: For containerized execution
- **Git**: For version control integration
- **GitHub Account**: For CI/CD integration

### Check Your System
```bash
# Check Python version
python --version  # Should be 3.9+

# Check pip
pip --version

# Check Docker (optional)
docker --version
```

## 💻 Local Installation

### Step 1: Clone the Repository
```bash
git clone <repository-url>
cd canary-scanner
```

### Step 2: Create Virtual Environment
```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate

# On Windows:
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
# Upgrade pip first
pip install --upgrade pip

# Install project dependencies
pip install -r requirements.txt

# Verify installation
python canary.py --version
```

### Step 4: Verify Installation
```bash
# Test with version check
python canary.py --version

# Test with help
python canary.py --help

# Test pattern loading
python -c "from scanner.patterns import load_patterns; print(f'Loaded {len(load_patterns("patterns.yml"))} patterns')"
```

## 🐳 Docker Setup

### Step 1: Build Docker Image
```bash
# Build the image
docker build -t canary-scanner .

# Verify build
docker images | grep canary-scanner
```

### Step 2: Test Docker Image
```bash
# Test version
docker run --rm canary-scanner --version

# Test pattern loading
docker run --rm canary-scanner --help
```

### Step 3: Run Scanner with Docker
```bash
# Scan current directory
docker run --rm -v "$(pwd):/scan" canary-scanner /scan

# Scan with JSON output
docker run --rm -v "$(pwd):/scan" canary-scanner /scan --output-json

# Scan with CI mode
docker run --rm -v "$(pwd):/scan" canary-scanner /scan --ci-mode
```

## ⚙️ GitHub Actions Setup

### Step 1: Repository Configuration
1. Ensure your repository has Actions enabled
2. Go to **Settings** → **Actions** → **General**
3. Set **Actions permissions** to "Allow all actions and reusable workflows"

### Step 2: Branch Protection Rules
1. Go to **Settings** → **Branches**
2. Add rule for `main` branch:
   - ✅ Require status checks to pass before merging
   - ✅ Require branches to be up to date before merging
   - Add "Secret Scanning" as required status check

### Step 3: Workflow Configuration
The workflow is automatically configured via `.github/workflows/secret-scan.yml`. No additional setup required!

### Step 4: Test the Workflow
```bash
# Create a test commit
echo "test_api_key = 'AKIAIOSFODNN7EXAMPLE'" > test_secrets.py
git add test_secrets.py
git commit -m "Test: Add sample secret for testing"
git push origin main

# Check Actions tab in GitHub to see workflow execution
```

## 🔧 Configuration

### Pattern Configuration (patterns.yml)

The scanner uses `patterns.yml` for secret detection rules:

```yaml
- rule_id: CUSTOM-001
  description: "My Company API Key"
  regex: 'mycompany_[a-zA-Z0-9]{32}'
  confidence: "High"
```

### Environment Variables

You can configure the scanner using environment variables:

```bash
# Set custom patterns file
export CANARY_PATTERNS_FILE="/path/to/custom/patterns.yml"

# Set default failure threshold
export CANARY_FAIL_ON="medium"

# Enable verbose logging
export CANARY_VERBOSE=1
```

### Command Line Options

```bash
# Basic usage
python canary.py /path/to/scan

# Advanced options
python canary.py . \
  --output-json \           # JSON output for automation
  --ci-mode \               # CI/CD optimized output  
  --fail-on medium \        # Only fail on medium+ confidence
  --verbose \               # Show full secret values (dangerous!)
  --patterns-file custom.yml # Use custom patterns file
```

## 📚 Usage Examples

### Example 1: Basic Local Scan
```bash
# Scan current directory
python canary.py .

# Scan specific directory
python canary.py /path/to/project

# Scan single file
python canary.py src/config.py
```

### Example 2: CI/CD Integration
```bash
# CI mode with medium threshold (recommended)
python canary.py . --ci-mode --fail-on medium

# JSON output for processing
python canary.py . --output-json > scan-results.json

# Check exit code
python canary.py . && echo "No secrets found" || echo "Secrets detected!"
```

### Example 3: Docker Usage
```bash
# Basic Docker scan
docker run --rm -v "$(pwd):/scan" canary-scanner /scan

# Advanced Docker scan with options
docker run --rm \
  -v "$(pwd):/scan" \
  -v "$(pwd)/results:/output" \
  canary-scanner /scan --ci-mode --fail-on high > /output/results.json
```

### Example 4: Custom Patterns
```bash
# Use custom patterns file
python canary.py . --patterns-file my-patterns.yml

# Validate patterns file
python -c "
from scanner.patterns import validate_patterns_file
result = validate_patterns_file('patterns.yml')
print(f'Valid: {result["valid"]}, Patterns: {result["pattern_count"]}')
"
```

## 🔍 Understanding Output

### Console Output
```
🚨 SECURITY ALERT: 2 Potential Secret(s) Detected!

🔴 CRITICAL: 1 high-confidence secrets found
🟡 MEDIUM: 1 medium-confidence secrets found

┏━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Priority  ┃ File                  ┃ Line ┃ Rule ID       ┃ Description                     ┃ Secret Preview            ┃
┡━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 🔴 CRITICAL │ src/config.py         │ 15   │ AWS-001       │ AWS Access Key ID               │ AKIA************         │
│ 🟡 MEDIUM   │ src/database.py       │ 28   │ POSTGRES-001  │ PostgreSQL Connection String    │ post************         │
└───────────┴───────────────────────┴──────┴───────────────┴─────────────────────────────────┴───────────────────────────┘

⚠️  IMMEDIATE ACTION REQUIRED:
1. 🛑 DO NOT MERGE this code until secrets are removed
2. 🔄 Rotate any exposed credentials immediately
3. 🗑️  Remove secrets from source code
4. 🔐 Use environment variables or secure vaults
5. 📚 Review your organization's secrets management policy
```

### JSON Output
```json
{
  "scan_metadata": {
    "scanner_version": "2.0.0",
    "scan_timestamp": "2025-10-12 10:30:45 UTC",
    "total_findings": 2
  },
  "severity_breakdown": {
    "critical": 1,
    "medium": 1,
    "low": 0
  },
  "findings": [
    {
      "file_path": "src/config.py",
      "line_number": 15,
      "rule_id": "AWS-001",
      "description": "AWS Access Key ID",
      "confidence": "High",
      "secret_preview": "AKIA************"
    }
  ]
}
```

## 🔧 Troubleshooting

### Common Issues

#### 1. "No module named 'scanner'"
```bash
# Solution: Ensure you're in the project directory
cd canary-scanner
python canary.py --version
```

#### 2. "Pattern file not found"
```bash
# Solution: Ensure patterns.yml exists
ls -la patterns.yml

# Or specify custom patterns file
python canary.py . --patterns-file /path/to/patterns.yml
```

#### 3. Docker permission issues
```bash
# Solution: Fix file permissions
sudo chown -R $USER:$USER /path/to/project

# Or run with user mapping
docker run --rm -u $(id -u):$(id -g) -v "$(pwd):/scan" canary-scanner /scan
```

#### 4. GitHub Actions not triggering
- Check that workflow file is in `.github/workflows/`
- Verify branch names match trigger conditions
- Ensure Actions are enabled in repository settings

#### 5. High memory usage on large repositories
```bash
# Solution: Use directory filtering
python canary.py . | grep -v "node_modules\|.git"

# Or scan specific directories
python canary.py src/ tests/
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
# Enable Python logging
export PYTHONUNBUFFERED=1

# Run with verbose output
python canary.py . --verbose

# Check Docker logs
docker run --rm -v "$(pwd):/scan" canary-scanner /scan --verbose
```

### Performance Optimization

For large repositories:

```bash
# Scan only source directories
python canary.py src/ lib/ --ci-mode

# Use Docker for isolation
docker run --rm --memory=1g -v "$(pwd):/scan" canary-scanner /scan

# Exclude large directories
python canary.py . | grep -v "Skipping.*node_modules"
```

## 📊 Performance Benchmarks

### Typical Performance (on modern hardware):
- **Small project** (< 100 files): 1-3 seconds
- **Medium project** (100-1000 files): 5-15 seconds  
- **Large project** (1000+ files): 30-60 seconds
- **Very large project** (10000+ files): 2-5 minutes

### Optimization Tips:
1. Use `.gitignore` to exclude unnecessary files
2. Run scans on specific directories rather than entire repositories
3. Use Docker for consistent performance
4. Consider parallel scanning for very large codebases

## 🆘 Getting Help

If you encounter issues:

1. **Check this troubleshooting guide**
2. **Review GitHub Issues**: Search existing issues in the repository
3. **Enable debug mode**: Run with `--verbose` flag
4. **Check system requirements**: Ensure Python 3.11+ and dependencies
5. **Create an issue**: Include logs, environment details, and reproduction steps

## 🔗 Additional Resources

- **Architecture Documentation**: `ARCHITECTURE.md`
- **API Documentation**: `docs/API.md`
- **Contributing Guide**: `docs/CONTRIBUTING.md`
- **Pattern Examples**: `examples/custom_patterns.yml`

---

**Happy Scanning! 🔍**
