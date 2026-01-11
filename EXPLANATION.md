# 🛡️ EasyGuard: Zero-Day Vulnerability Prediction using AI

## Project Explanation & Technical Documentation

---

## 📋 Table of Contents

1. [Project Overview](#-project-overview)
2. [Complete Workflow](#-complete-workflow)
3. [Technical Standards](#-technical-standards-used)
4. [Where AI Is Used](#-where-ai-is-used)
5. [How It Determines Security](#-how-it-determines-secure-vs-vulnerable)
6. [Why Zero-Day Prediction](#-why-zero-day-vulnerability-prediction-using-ai)
7. [Key Source Files](#-key-source-files)

---

## 🎯 Project Overview

**EasyGuard** is an AI-powered code security scanner that predicts potential zero-day vulnerabilities in source code before they are discovered and exploited by attackers.

### What Makes It Special?
- **Proactive Detection**: Finds vulnerabilities before they become known CVEs
- **Multi-Model AI**: Combines ML, Deep Learning, and Pattern Analysis
- **Multi-Language**: Supports 9 programming languages
- **Real-time Analysis**: Instant feedback through web interface

---

## 🔄 Complete Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│                        USER INPUT                                │
│   Upload Files  │  Paste Code  │  GitHub URL                    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CODE PREPROCESSING                            │
│   • Language Detection (C, Python, JS, etc.)                    │
│   • Code Normalization & Tokenization                           │
│   • AST (Abstract Syntax Tree) Parsing                          │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                   FEATURE EXTRACTION                             │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│   │   Static     │  │    Code      │  │  Semantic    │         │
│   │  Analysis    │  │   Metrics    │  │  Embeddings  │         │
│   │  Patterns    │  │  (Complexity)│  │  (CodeBERT)  │         │
│   └──────────────┘  └──────────────┘  └──────────────┘         │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    AI/ML PREDICTION                              │
│   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │
│   │   Pattern    │  │   Random     │  │   CodeBERT   │         │
│   │  Detection   │  │   Forest     │  │  Transformer │         │
│   │  (Rule-based)│  │    (ML)      │  │    (DL)      │         │
│   └──────────────┘  └──────────────┘  └──────────────┘         │
│                              │                                   │
│                      ENSEMBLE VOTING                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                       OUTPUT                                     │
│   • Vulnerability Score (0-100%)                                │
│   • Severity Level (CRITICAL/HIGH/MEDIUM/LOW)                   │
│   • CWE Classification                                          │
│   • Line-by-line vulnerability locations                        │
│   • Fix Suggestions                                             │
└─────────────────────────────────────────────────────────────────┘
```

### Detailed Steps:

1. **Input Phase**: User provides code via file upload, paste, or GitHub URL
2. **Preprocessing**: Language detection, normalization, AST parsing
3. **Feature Extraction**: Extract 200+ features from code structure
4. **AI Analysis**: Multiple models analyze the code in parallel
5. **Ensemble Voting**: Combine predictions with weighted voting
6. **Output**: Generate detailed vulnerability report with fixes

---

## 🔬 Technical Standards Used

| Component | Technology | Purpose |
|-----------|------------|---------|
| **Pattern Detection** | Regex + AST Analysis | Identifies 50+ known vulnerability patterns |
| **ML Model** | Random Forest (scikit-learn) | Classification based on code features |
| **Deep Learning** | CodeBERT (Transformers) | Semantic understanding of code |
| **Graph Neural Networks** | PyTorch Geometric | Analyzes code control/data flow graphs |
| **CVE/NVD Integration** | NVD API | Training data from real-world vulnerabilities |
| **CWE Mapping** | MITRE CWE Database | Standard vulnerability classification |
| **Web Framework** | Flask | Modern web interface |
| **Code Parsing** | Tree-sitter | Multi-language AST parsing |

### Security Standards Followed:
- **CWE (Common Weakness Enumeration)**: Industry-standard vulnerability taxonomy
- **OWASP Top 10**: Coverage of most critical web vulnerabilities
- **CVE Database**: Training on real-world vulnerability data
- **CVSS Scoring**: Severity assessment methodology

---

## 🤖 Where AI Is Used

### AI/ML Components in the System:

| Layer | AI/ML Technique | What It Does |
|-------|-----------------|--------------|
| **Feature Extraction** | CodeBERT Embeddings | Converts code into 768-dimensional semantic vectors |
| **Pattern Learning** | Random Forest Classifier | Learns from 200+ code complexity features |
| **Semantic Analysis** | Transformer Attention | Understands code context and relationships |
| **Ensemble Prediction** | Weighted Voting | Combines multiple models for higher accuracy |

### AI Model Details:

#### 1. Pattern Detector (Rule-Based AI)
```
Location: src/features/pattern_detector.py
- 50+ vulnerability patterns
- Language-specific rules
- CWE mapping included
```

#### 2. Random Forest Classifier (Traditional ML)
```
Location: src/models/baseline.py
- 300 decision trees
- 200+ code features as input
- Trained on CVE/NVD data
```

#### 3. CodeBERT Transformer (Deep Learning)
```
Location: src/models/codebert_model.py
- Pre-trained on 6M code samples
- Fine-tuned for vulnerability detection
- 768-dim semantic embeddings
```

#### 4. Ensemble Model (Combined AI)
```
Location: src/models/ensemble.py
Weights:
  - Pattern Detection: 20%
  - Random Forest ML: 40%
  - CodeBERT Deep Learning: 40%
```

---

## 📊 How It Determines "Secure vs Vulnerable"

### Vulnerability Score Calculation:

```
Final Score = (0.2 × Pattern Score) + (0.4 × ML Score) + (0.4 × DL Score)
```

### Risk Assessment Matrix:

| Score Range | Status | Badge | Meaning |
|-------------|--------|-------|---------|
| **0-20%** | SECURE | ✅ | No significant vulnerabilities detected |
| **20-50%** | LOW RISK | ⚠️ | Minor issues, code review recommended |
| **50-75%** | MEDIUM RISK | 🟠 | Potential vulnerabilities found |
| **75-100%** | VULNERABLE | 🔴 | Critical security issues detected |

### Severity Levels:

| Level | Description | Example Vulnerabilities |
|-------|-------------|------------------------|
| **CRITICAL** | Immediate exploitation possible | Buffer overflow, RCE, SQL injection |
| **HIGH** | Significant security risk | Command injection, XSS, path traversal |
| **MEDIUM** | Moderate risk | Information disclosure, weak crypto |
| **LOW** | Minor issues | Code quality, best practices |

---

## 🎯 Why "Zero-Day Vulnerability Prediction using AI"?

### Breaking Down the Name:

| Term | Explanation |
|------|-------------|
| **Zero-Day** | Detects vulnerability *patterns* before they become known CVEs - predicts weaknesses that could become future exploits |
| **Prediction** | Uses ML to identify *potential* vulnerabilities, not just known signatures |
| **AI-Powered** | Combines Pattern Matching + Machine Learning + Deep Learning for intelligent analysis |

### Key AI Capabilities:

1. **Learns from CVE/NVD Data**
   - Trained on 100,000+ real-world vulnerabilities
   - Understands what makes code vulnerable

2. **Pattern Generalization**
   - Detects similar code patterns even if not exact match
   - Identifies vulnerability "families"

3. **Semantic Understanding**
   - CodeBERT understands code meaning, not just syntax
   - Recognizes context-dependent vulnerabilities

4. **Confidence Scoring**
   - Provides probability-based risk assessment
   - Reduces false positives through ensemble voting

### How It Predicts Zero-Days:

```
Known Vulnerability Pattern → Learning → Generalization → New Variant Detection
      (CVE Database)          (ML/DL)    (Feature Space)   (Zero-Day Prediction)
```

---

## 📁 Key Source Files

| File | Role | Description |
|------|------|-------------|
| `app.py` | Web Interface | Flask-based modern UI |
| `main.py` | CLI Entry Point | Command-line interface |
| `src/features/pattern_detector.py` | Pattern Detection | 50+ vulnerability pattern rules |
| `src/features/code_features.py` | Feature Extraction | Code complexity metrics |
| `src/features/ast_features.py` | AST Analysis | Abstract Syntax Tree features |
| `src/models/baseline.py` | ML Model | Random Forest classifier |
| `src/models/codebert_model.py` | DL Model | Transformer-based model |
| `src/models/ensemble.py` | Ensemble | Combines all models |
| `src/data/nvd_collector.py` | Data Collection | Fetches NVD/CVE training data |
| `configs/config.yaml` | Configuration | Model and feature settings |

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run web interface
python app.py

# Open http://localhost:5000 in browser
```

---

## 📈 Model Performance Metrics

| Metric | Target | Description |
|--------|--------|-------------|
| **Precision** | >85% | Reduce false positives |
| **Recall** | >70% | Catch most vulnerabilities |
| **F1 Score** | >75% | Balanced performance |
| **Processing Speed** | 10,000+ LOC/min | Real-time analysis |

---

## 🔐 Supported Vulnerability Types

| CWE ID | Vulnerability Type | Languages |
|--------|-------------------|-----------|
| CWE-120 | Buffer Overflow | C, C++ |
| CWE-89 | SQL Injection | Python, JS, PHP, Go |
| CWE-79 | Cross-Site Scripting (XSS) | JS, PHP |
| CWE-78 | Command Injection | C, Python, PHP |
| CWE-502 | Deserialization | Python, PHP, Ruby |
| CWE-22 | Path Traversal | JS, Go |
| CWE-798 | Hardcoded Credentials | All |
| CWE-416 | Use After Free | C, C++ |
| CWE-134 | Format String | C, C++ |
| CWE-328 | Weak Cryptography | Go, Python |

---

## 👨‍💻 Created By

**Kavi** - Cyber Security Researcher

---

> This project demonstrates how AI can be used proactively in cybersecurity to predict and prevent vulnerabilities before they become exploited zero-day attacks.
