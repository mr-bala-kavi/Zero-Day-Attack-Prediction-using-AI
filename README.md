# 🛡️ EasyGuard - AI-Powered Code Security Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)
![AI Powered](https://img.shields.io/badge/AI-Powered-purple.svg)
![Created by](https://img.shields.io/badge/Created%20by-Kavi-ff69b4.svg)

**An AI-powered system to predict potential zero-day vulnerabilities in source code before they are discovered and exploited.**

[Features](#-features) • [Quick Start](#-quick-start) • [Usage](#-usage) • [API](#-api-usage) • [Contributing](#-contributing)

</div>

---

## ✨ Features

### 🖥️ Modern Web Interface
- **Drag & Drop** file uploads
- **Paste Code** directly for instant analysis
- **GitHub Integration** - Clone and scan entire repositories
- Beautiful dark-themed UI with real-time results

### 🤖 Multi-Model Architecture
- **Traditional ML** - Random Forest on hand-crafted features
- **Deep Learning** - CodeBERT-based semantic analysis
- **Pattern Detection** - Rule-based vulnerability matching
- **Ensemble** - Combined predictions for higher accuracy

### 🌐 Multi-Language Support
Supports vulnerability detection across **9 programming languages**:

| Language | Extensions |
|----------|------------|
| C/C++ | `.c`, `.h`, `.cpp`, `.hpp`, `.cc`, `.cxx` |
| Python | `.py`, `.pyw` |
| JavaScript/TypeScript | `.js`, `.ts`, `.jsx`, `.tsx`, `.mjs` |
| PHP | `.php`, `.phtml` |
| Go | `.go` |
| Rust | `.rs` |
| Ruby | `.rb`, `.erb` |
| Java | `.java` |
| Swift/Kotlin | `.swift`, `.kt`, `.kts` |

### 🔍 Comprehensive Vulnerability Detection

Identifies **20+ vulnerability patterns** including:

| Vulnerability | CWE ID | Description |
|--------------|--------|-------------|
| Buffer Overflow | CWE-120 | Unsafe memory operations |
| SQL Injection | CWE-89 | Unsanitized database queries |
| XSS | CWE-79 | Cross-site scripting vectors |
| Command Injection | CWE-78 | OS command execution risks |
| Deserialization | CWE-502 | Unsafe object deserialization |
| Path Traversal | CWE-22 | Directory traversal attacks |
| Hardcoded Credentials | CWE-798 | Embedded secrets in code |
| Use After Free | CWE-416 | Memory safety violations |
| Format String | CWE-134 | Printf-style vulnerabilities |
| Weak Cryptography | CWE-328 | Insecure crypto algorithms |

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)
- Git (optional, for GitHub scanning feature)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/Zero-Day-Attack-Prediction-using-AI.git
cd Zero-Day-Attack-Prediction-using-AI

# Install dependencies
pip install -r requirements.txt
```

### Launch Web Interface

```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

---

## 📖 Usage

### Web GUI (Recommended)

The web interface provides three scanning modes:

1. **📁 Upload Files** - Drag and drop or browse for source files
2. **📝 Paste Code** - Copy-paste code snippets for quick analysis
3. **🐙 GitHub Repo** - Enter a repository URL to clone and scan

### Command Line Interface

```bash
# Run a quick demo
python main.py demo

# Scan a single file
python main.py scan --file vulnerable.c

# Scan a directory
python main.py scan --dir ./src --output results.json

# Scan inline code
python main.py scan --code "strcpy(buffer, user_input);"
```

### Training Models

```bash
# Train baseline model (Random Forest)
python main.py train --model baseline

# Train with custom settings
python main.py train --model baseline --samples 1000 --output data/models

# Evaluate a trained model
python main.py evaluate --model data/models/baseline_model.joblib
```

---

## 📁 Project Structure

```
Zero-Day-Attack-Prediction-using-AI/
├── app.py                    # Flask web application
├── main.py                   # CLI entry point
├── requirements.txt          # Python dependencies
├── configs/
│   └── config.yaml           # Configuration settings
├── data/
│   ├── raw/                  # Raw CVE/NVD data
│   ├── processed/            # Processed datasets
│   └── models/               # Trained model files
├── scripts/
│   ├── download_cve_data.py  # CVE data downloader
│   ├── train.py              # Training utilities
│   ├── evaluate.py           # Evaluation scripts
│   └── predict.py            # Prediction CLI
├── src/
│   ├── data/                 # Data handling modules
│   ├── features/             # Feature extraction
│   ├── models/               # ML model implementations
│   └── utils/                # Utility functions
└── tests/                    # Unit tests
```

---

## 🔌 API Usage

### Pattern Detection (No Training Required)

```python
from src.features.pattern_detector import PatternDetector

detector = PatternDetector()
matches = detector.detect(code, language="c")
score = detector.get_vulnerability_score(matches)

for match in matches:
    print(f"[{match.severity}] {match.pattern_name} at line {match.line_number}")
    print(f"  CWE: {match.cwe_id}")
    print(f"  Fix: {match.fix_suggestion}")
```

### ML-Based Detection

```python
from src.models.baseline import BaselineModel

model = BaselineModel()
model.load("data/models/baseline_model.joblib")

result = model.analyze_code(code, language="c")
print(f"Vulnerable: {result['vulnerable']}")
print(f"Confidence: {result['confidence']:.2%}")
```

### REST API

```bash
# Scan code via API
curl -X POST http://localhost:5000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"code": "strcpy(buffer, input);", "language": "c"}'
```

---

## ⚙️ Configuration

Edit `configs/config.yaml` to customize behavior:

```yaml
# Model parameters
models:
  baseline:
    n_estimators: 200
    max_depth: 20
    class_weight: "balanced"

# Feature extraction settings
features:
  dangerous_functions:
    c: [strcpy, gets, sprintf, scanf]
    python: [eval, exec, pickle.loads]
```

---

## 🧪 Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=src --cov-report=html
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get started:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Add tests** for new functionality
4. **Commit** your changes (`git commit -m 'Add amazing feature'`)
5. **Push** to the branch (`git push origin feature/amazing-feature`)
6. **Open** a Pull Request

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 📚 References

- [NVD - National Vulnerability Database](https://nvd.nist.gov/)
- [CVE - Common Vulnerabilities and Exposures](https://cve.mitre.org/)
- [CWE - Common Weakness Enumeration](https://cwe.mitre.org/)
- [CodeBERT - Pre-trained Model for Programming Languages](https://github.com/microsoft/CodeBERT)

---

<div align="center">

**Created with ❤️ by Kavi**

Made for the security community

⭐ Star this repo if you find it useful!

</div>
