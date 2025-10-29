# Agentic OWASP Security Scanner 🤖🔐

An autonomous AI-powered web application security testing tool that implements comprehensive OWASP Top 10 vulnerability assessments using Google's Gemini Flash.

## 🚀 Features

- **Fully Autonomous**: No human intervention required during testing
- **OWASP Top 10 Coverage**: Complete assessment of all 2021 OWASP Top 10 vulnerabilities
- **AI-Powered Analysis**: Leverages Gemini Flash for intelligent reasoning and pattern recognition
- **Agentic Architecture**: Multi-agent system with specialized testing capabilities
- **Adaptive Learning**: Continuously improves testing methodologies
- **Comprehensive Reporting**: Detailed reports with actionable remediation guidance

## 🏗️ Architecture

The system follows a sophisticated agentic AI architecture with the following core components:

### Core Modules
- **Planning & Goal Management**: Strategic task decomposition and execution planning
- **Perception & Data Collection**: Automated reconnaissance and intelligence gathering
- **Memory & Knowledge Management**: Persistent context and learning repository
- **Cognitive Reasoning Engine**: Gemini Flash-powered analysis and decision making
- **Action Execution**: Concrete security testing operations

### OWASP Top 10 Testing Agents
- **A01**: Broken Access Control Testing Agent
- **A02**: Cryptographic Failures Detection Agent
- **A03**: Injection Vulnerability Scanner Agent
- **A04**: Insecure Design Pattern Analyzer
- **A05**: Security Misconfiguration Scanner
- **A06**: Vulnerable Component Analyzer
- **A07**: Authentication and Session Management Tester
- **A08**: Software and Data Integrity Validator
- **A09**: Security Logging and Monitoring Evaluator
- **A10**: Server-Side Request Forgery (SSRF) Scanner

## 📋 Prerequisites

- Python 3.10 or higher
- Google AI API key (for Gemini Flash access)
- Redis (for caching and session management)
- SQLite (for local data storage)

## 🛠️ Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/streetquant/agentic-owasp-security-scanner.git
cd agentic-owasp-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Using pip (coming soon)

```bash
pip install agentic-owasp-scanner
```

## ⚙️ Configuration

1. **Set up environment variables:**

```bash
# Required
export GOOGLE_AI_API_KEY="your-gemini-api-key"

# Optional
export REDIS_URL="redis://localhost:6379"
export LOG_LEVEL="INFO"
export MAX_CONCURRENT_TESTS="10"
```

2. **Create configuration file** (optional):

```yaml
# config.yaml
api:
  google_ai_key: "your-api-key"
  rate_limit: 60  # requests per minute

testing:
  max_depth: 5
  timeout: 30
  user_agent: "Agentic-OWASP-Scanner/0.1.0"

reporting:
  format: "html"  # html, json, pdf
  output_dir: "./reports"

logging:
  level: "INFO"
  file: "scanner.log"
```

## 🚀 Quick Start

### Command Line Interface

```bash
# Basic scan
agentic-scanner scan https://example.com

# Scan with specific OWASP categories
agentic-scanner scan https://example.com --categories A01,A03,A10

# Comprehensive scan with custom config
agentic-scanner scan https://example.com --config config.yaml --output reports/

# Interactive mode
agentic-scanner interactive
```

### Python API

```python
import asyncio
from agentic_scanner import AgenticScanner, ScannerConfig

async def main():
    # Initialize scanner with configuration
    config = ScannerConfig(
        target_url="https://example.com",
        google_ai_key="your-api-key",
        max_depth=5
    )
    
    scanner = AgenticScanner(config)
    
    # Run comprehensive OWASP Top 10 assessment
    results = await scanner.run_full_assessment()
    
    # Generate report
    report = await scanner.generate_report(results, format="html")
    print(f"Report saved to: {report.output_path}")

if __name__ == "__main__":
    asyncio.run(main())
```

## 📊 Example Output

```
🤖 Agentic OWASP Security Scanner v0.1.0
🎯 Target: https://example.com
📅 Started: 2025-10-29 05:36:00 IST

🔍 Phase 1: Reconnaissance and Discovery
├── 🌐 Technology Stack Detection: Completed
├── 🗺️  Application Mapping: 127 endpoints discovered
├── 🔐 Authentication Analysis: 3 auth mechanisms found
└── 📋 Input Parameter Enumeration: 45 parameters identified

🧠 Phase 2: AI-Powered Vulnerability Analysis
├── 🚨 A01 - Broken Access Control: 3 HIGH, 2 MEDIUM findings
├── 🔒 A02 - Cryptographic Failures: 1 CRITICAL finding
├── 💉 A03 - Injection: 5 HIGH, 8 MEDIUM findings
├── 🏗️  A04 - Insecure Design: 2 MEDIUM findings
├── ⚙️  A05 - Security Misconfiguration: 4 HIGH findings
├── 📦 A06 - Vulnerable Components: 12 vulnerabilities found
├── 🆔 A07 - Auth Failures: 2 HIGH, 1 MEDIUM findings
├── 🛡️  A08 - Data Integrity: 1 HIGH finding
├── 📝 A09 - Logging Failures: 3 MEDIUM findings
└── 🌐 A10 - SSRF: 1 CRITICAL, 2 HIGH findings

✅ Assessment Complete!
📊 Total Findings: 2 CRITICAL, 21 HIGH, 18 MEDIUM, 5 LOW
📄 Report: reports/example_com_20251029_053600.html
```

## 🔧 Development

### Setting up Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/

# Type checking
mypy src/

# Code formatting
black src/ tests/
isort src/ tests/
```

### Project Structure

```
agentic-owasp-security-scanner/
├── src/agentic_scanner/
│   ├── core/                    # Core architecture components
│   │   ├── scanner.py          # Main orchestrator
│   │   ├── config.py           # Configuration management
│   │   ├── memory.py           # Memory and knowledge systems
│   │   ├── planning.py         # Planning and goal management
│   │   └── reasoning.py        # Gemini Flash integration
│   ├── agents/                 # OWASP Top 10 testing agents
│   │   ├── base.py            # Base agent class
│   │   ├── a01_access_control.py
│   │   ├── a02_crypto_failures.py
│   │   ├── a03_injection.py
│   │   ├── a04_insecure_design.py
│   │   ├── a05_misconfiguration.py
│   │   ├── a06_vulnerable_components.py
│   │   ├── a07_auth_failures.py
│   │   ├── a08_data_integrity.py
│   │   ├── a09_logging_failures.py
│   │   └── a10_ssrf.py
│   ├── utils/                  # Utility modules
│   │   ├── http_client.py     # HTTP handling
│   │   ├── payloads.py        # Attack payloads
│   │   ├── parsing.py         # Response parsing
│   │   └── reporting.py       # Report generation
│   └── cli.py                 # Command-line interface
├── tests/                     # Test suite
├── docs/                      # Documentation
├── examples/                  # Usage examples
├── requirements.txt          # Dependencies
├── pyproject.toml           # Project configuration
└── README.md                # This file
```

## 📖 Documentation

- [Architecture Overview](docs/architecture.md)
- [Agent Development Guide](docs/agent-development.md)
- [Configuration Reference](docs/configuration.md)
- [API Documentation](docs/api.md)
- [Contributing Guidelines](docs/contributing.md)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Development Roadmap

- [ ] Core architecture implementation
- [ ] Gemini Flash integration
- [ ] OWASP Top 10 agent development
- [ ] Memory and learning systems
- [ ] Web UI dashboard
- [ ] CI/CD pipeline integration
- [ ] Docker containerization
- [ ] Kubernetes deployment
- [ ] Plugin system for custom agents
- [ ] Enterprise features (RBAC, SSO, etc.)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing only. Users are responsible for ensuring they have proper authorization before testing any web applications. The authors are not responsible for any misuse of this tool.

## 🙏 Acknowledgments

- [OWASP Foundation](https://owasp.org/) for the Top 10 vulnerability classifications
- [Google AI](https://ai.google.dev/) for Gemini Flash capabilities
- The cybersecurity community for continuous research and knowledge sharing

## 📧 Contact

- **Author**: Shayan Banerjee
- **GitHub**: [@streetquant](https://github.com/streetquant)
- **Project**: [agentic-owasp-security-scanner](https://github.com/streetquant/agentic-owasp-security-scanner)

---

⭐ **Star this repository if you find it useful!** ⭐