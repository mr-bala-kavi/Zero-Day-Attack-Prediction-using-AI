#!/usr/bin/env python3
"""
Zero-Day Vulnerability Scanner - Web GUI

A modern web interface for scanning code files for vulnerabilities.
Features:
- Upload files
- Paste code directly
- Clone and scan GitHub repositories
- Scan local directories

Usage:
    python app.py
    Then open http://localhost:5000 in your browser
"""

import os
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from flask import Flask, render_template_string, request, jsonify
from werkzeug.utils import secure_filename

from src.features.pattern_detector import PatternDetector
from src.features.code_features import CodeFeatureExtractor

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max
app.config['SECRET_KEY'] = 'vulnerability-scanner-secret-key'

# Initialize detector
detector = PatternDetector()
feature_extractor = CodeFeatureExtractor()

# Allowed file extensions
ALLOWED_EXTENSIONS = {
    '.c', '.h', '.cpp', '.cc', '.cxx', '.hpp',  # C/C++
    '.py', '.pyw',                               # Python
    '.js', '.ts', '.jsx', '.tsx', '.mjs',        # JavaScript/TypeScript
    '.php', '.phtml', '.php5',                   # PHP
    '.go',                                       # Go
    '.rs',                                       # Rust
    '.rb', '.erb',                               # Ruby
    '.java',                                     # Java
    '.cs',                                       # C#
    '.swift',                                    # Swift
    '.kt', '.kts',                               # Kotlin
}

# Language mapping from extension
EXTENSION_TO_LANGUAGE = {
    '.c': 'c', '.h': 'c',
    '.cpp': 'cpp', '.cc': 'cpp', '.cxx': 'cpp', '.hpp': 'cpp',
    '.py': 'python', '.pyw': 'python',
    '.js': 'javascript', '.mjs': 'javascript',
    '.ts': 'typescript', '.jsx': 'javascript', '.tsx': 'typescript',
    '.php': 'php', '.phtml': 'php', '.php5': 'php',
    '.go': 'go',
    '.rs': 'rust',
    '.rb': 'ruby', '.erb': 'ruby',
    '.java': 'java',
    '.cs': 'cpp',
    '.swift': 'c',
    '.kt': 'java', '.kts': 'java',
}

# Modern HTML Template
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EasyGuard - AI-Powered Code Security Scanner</title>
    <link rel="icon" type="image/png" href="/static/favicon.png">
    <link rel="apple-touch-icon" href="/static/favicon.png">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&family=Outfit:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-primary: #0a0a0f;
            --bg-secondary: #12121a;
            --bg-card: #1a1a25;
            --bg-hover: #252535;
            --accent-blue: #3b82f6;
            --accent-purple: #8b5cf6;
            --accent-pink: #ec4899;
            --accent-green: #10b981;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
            --text-primary: #ffffff;
            --text-secondary: #94a3b8;
            --text-muted: #64748b;
            --border-color: rgba(255,255,255,0.1);
            --gradient-1: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%);
            --gradient-2: linear-gradient(135deg, #10b981 0%, #3b82f6 100%);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Outfit', 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            min-height: 100vh;
            overflow-x: hidden;
            scroll-behavior: smooth;
        }

        /* Animated background */
        .bg-animation {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: -1;
            background:
                radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.15) 0%, transparent 50%),
                radial-gradient(ellipse at 80% 80%, rgba(139, 92, 246, 0.15) 0%, transparent 50%),
                radial-gradient(ellipse at 50% 50%, rgba(236, 72, 153, 0.1) 0%, transparent 50%);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            position: relative;
        }

        /* Header */
        header {
            text-align: center;
            padding: 60px 0 40px;
        }

        .logo {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 15px;
            margin-bottom: 20px;
        }

        .logo-icon {
            width: 70px;
            height: 70px;
            border-radius: 18px;
            display: flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 15px 50px rgba(139, 92, 246, 0.4);
            overflow: hidden;
            animation: pulse-glow 3s ease-in-out infinite;
        }

        .logo-icon img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }

        @keyframes pulse-glow {
            0%, 100% { box-shadow: 0 15px 50px rgba(139, 92, 246, 0.4); }
            50% { box-shadow: 0 20px 60px rgba(59, 130, 246, 0.5); }
        }

        h1 {
            font-size: 3.5em;
            font-weight: 800;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -2px;
            text-shadow: 0 0 80px rgba(139, 92, 246, 0.3);
        }

        h1 span.highlight {
            color: #10b981;
            -webkit-text-fill-color: #10b981;
        }

        .tagline {
            color: var(--text-secondary);
            font-size: 1.2em;
            margin-top: 10px;
            font-weight: 300;
        }

        /* Stats bar */
        .stats-bar {
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 30px 0;
            flex-wrap: wrap;
        }

        .stat-item {
            text-align: center;
        }

        .stat-value {
            font-size: 2em;
            font-weight: 700;
            background: var(--gradient-1);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        .stat-label {
            color: var(--text-muted);
            font-size: 0.9em;
            margin-top: 5px;
        }

        /* Main scanner card */
        .scanner-card {
            background: var(--bg-card);
            border-radius: 24px;
            padding: 0;
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            overflow: hidden;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
        }

        /* Tabs */
        .tabs {
            display: flex;
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
        }

        .tab-btn {
            flex: 1;
            padding: 20px;
            border: none;
            background: transparent;
            color: var(--text-secondary);
            font-size: 1em;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
            border-bottom: 3px solid transparent;
            font-family: inherit;
        }

        .tab-btn:hover {
            background: var(--bg-hover);
            color: var(--text-primary);
        }

        .tab-btn.active {
            color: var(--text-primary);
            background: var(--bg-card);
            border-bottom-color: var(--accent-blue);
        }

        .tab-icon {
            font-size: 1.3em;
        }

        .tab-content {
            display: none;
            padding: 30px;
        }

        .tab-content.active {
            display: block;
        }

        /* Upload area */
        .upload-area {
            border: 2px dashed var(--border-color);
            border-radius: 16px;
            padding: 60px 40px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s;
            background: rgba(59, 130, 246, 0.02);
        }

        .upload-area:hover {
            border-color: var(--accent-blue);
            background: rgba(59, 130, 246, 0.05);
            transform: translateY(-2px);
        }

        .upload-area.dragover {
            border-color: var(--accent-purple);
            background: rgba(139, 92, 246, 0.1);
            transform: scale(1.02);
        }

        .upload-icon {
            font-size: 4em;
            margin-bottom: 20px;
            filter: grayscale(0.5);
        }

        .upload-text {
            font-size: 1.3em;
            font-weight: 500;
            margin-bottom: 10px;
        }

        .upload-hint {
            color: var(--text-muted);
            font-size: 0.95em;
        }

        #file-input {
            display: none;
        }

        .file-selected {
            margin-top: 20px;
            padding: 15px 20px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 10px;
            color: var(--accent-green);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        /* Code input */
        .code-container {
            position: relative;
        }

        textarea {
            width: 100%;
            height: 350px;
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 20px;
            color: var(--text-primary);
            font-family: 'JetBrains Mono', monospace;
            font-size: 14px;
            resize: vertical;
            transition: all 0.3s;
        }

        textarea:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        textarea::placeholder {
            color: var(--text-muted);
        }

        .input-row {
            display: flex;
            gap: 15px;
            margin-top: 20px;
            flex-wrap: wrap;
        }

        .input-group {
            flex: 1;
            min-width: 200px;
        }

        .input-group label {
            display: block;
            margin-bottom: 8px;
            color: var(--text-secondary);
            font-size: 0.9em;
            font-weight: 500;
        }

        select, input[type="text"] {
            width: 100%;
            padding: 14px 18px;
            border-radius: 10px;
            border: 1px solid var(--border-color);
            background: var(--bg-secondary);
            color: var(--text-primary);
            font-size: 1em;
            font-family: inherit;
            transition: all 0.3s;
        }

        select:focus, input[type="text"]:focus {
            outline: none;
            border-color: var(--accent-blue);
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }

        /* GitHub input */
        .github-input-container {
            display: flex;
            gap: 15px;
            align-items: flex-end;
        }

        .github-input-container .input-group {
            flex: 1;
        }

        .github-hint {
            color: var(--text-muted);
            font-size: 0.85em;
            margin-top: 10px;
        }

        .github-hint code {
            background: var(--bg-secondary);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
        }

        /* Scan button */
        .scan-btn {
            width: 100%;
            padding: 18px;
            margin-top: 25px;
            border: none;
            border-radius: 12px;
            background: var(--gradient-1);
            color: white;
            font-size: 1.1em;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
            font-family: inherit;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .scan-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 40px rgba(139, 92, 246, 0.4);
        }

        .scan-btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .scan-btn:active {
            transform: translateY(0);
        }

        /* Results */
        .results-container {
            display: none;
        }

        .results-container.show {
            display: block;
        }

        .results-card {
            background: var(--bg-card);
            border-radius: 24px;
            border: 1px solid var(--border-color);
            overflow: hidden;
            margin-bottom: 20px;
        }

        .results-header {
            padding: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid var(--border-color);
            flex-wrap: wrap;
            gap: 20px;
        }

        .status-section {
            display: flex;
            align-items: center;
            gap: 20px;
        }

        .status-badge {
            padding: 12px 28px;
            border-radius: 50px;
            font-weight: 600;
            font-size: 1em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .status-safe {
            background: rgba(16, 185, 129, 0.15);
            color: var(--accent-green);
            border: 1px solid rgba(16, 185, 129, 0.3);
        }

        .status-vulnerable {
            background: rgba(239, 68, 68, 0.15);
            color: var(--accent-red);
            border: 1px solid rgba(239, 68, 68, 0.3);
        }

        .scan-info {
            color: var(--text-secondary);
            font-size: 0.95em;
        }

        .score-section {
            text-align: right;
        }

        .score-label {
            color: var(--text-muted);
            font-size: 0.85em;
            margin-bottom: 5px;
        }

        .score-value {
            font-size: 2.5em;
            font-weight: 700;
        }

        .score-safe { color: var(--accent-green); }
        .score-low { color: var(--accent-orange); }
        .score-high { color: var(--accent-red); }

        /* Summary stats */
        .summary-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            padding: 25px 30px;
            background: var(--bg-secondary);
        }

        .summary-stat {
            text-align: center;
            padding: 15px;
            background: var(--bg-card);
            border-radius: 12px;
        }

        .summary-stat-value {
            font-size: 1.8em;
            font-weight: 700;
        }

        .summary-stat-label {
            color: var(--text-muted);
            font-size: 0.85em;
            margin-top: 5px;
        }

        /* Vulnerability list */
        .vuln-list {
            padding: 20px;
        }

        .vuln-item {
            background: var(--bg-secondary);
            border-radius: 16px;
            padding: 20px 25px;
            margin-bottom: 15px;
            border-left: 4px solid;
            transition: all 0.3s;
        }

        .vuln-item:hover {
            transform: translateX(5px);
            background: var(--bg-hover);
        }

        .vuln-item.critical { border-left-color: var(--accent-red); }
        .vuln-item.high { border-left-color: var(--accent-orange); }
        .vuln-item.medium { border-left-color: #eab308; }
        .vuln-item.low { border-left-color: var(--text-muted); }

        .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
            flex-wrap: wrap;
            gap: 10px;
        }

        .vuln-title {
            display: flex;
            align-items: center;
            gap: 12px;
            flex-wrap: wrap;
        }

        .vuln-name {
            font-weight: 600;
            font-size: 1.05em;
        }

        .vuln-file {
            color: var(--text-muted);
            font-size: 0.85em;
            font-family: 'JetBrains Mono', monospace;
        }

        .severity-badge {
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 0.75em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .severity-critical { background: var(--accent-red); color: white; }
        .severity-high { background: var(--accent-orange); color: white; }
        .severity-medium { background: #eab308; color: black; }
        .severity-low { background: var(--text-muted); color: white; }

        .vuln-meta {
            display: flex;
            gap: 20px;
            flex-wrap: wrap;
            color: var(--text-secondary);
            font-size: 0.9em;
            margin-bottom: 12px;
        }

        .vuln-meta span {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .vuln-code {
            background: var(--bg-primary);
            padding: 12px 16px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            margin: 12px 0;
            border: 1px solid var(--border-color);
        }

        .vuln-description {
            color: var(--text-secondary);
            margin-bottom: 12px;
            line-height: 1.6;
        }

        .vuln-fix {
            background: rgba(16, 185, 129, 0.1);
            padding: 12px 16px;
            border-radius: 8px;
            color: var(--accent-green);
            font-size: 0.9em;
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .vuln-fix strong {
            color: var(--accent-green);
        }

        /* No vulnerabilities */
        .no-vulns {
            text-align: center;
            padding: 60px 40px;
        }

        .no-vulns-icon {
            font-size: 5em;
            margin-bottom: 20px;
        }

        .no-vulns h3 {
            font-size: 1.5em;
            margin-bottom: 10px;
            color: var(--accent-green);
        }

        .no-vulns p {
            color: var(--text-secondary);
        }

        /* Loading */
        .loading {
            text-align: center;
            padding: 60px;
        }

        .spinner {
            width: 60px;
            height: 60px;
            border: 4px solid var(--bg-hover);
            border-top-color: var(--accent-blue);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 25px;
        }

        @keyframes spin {
            to { transform: rotate(360deg); }
        }

        .loading-text {
            color: var(--text-secondary);
            font-size: 1.1em;
        }

        .loading-subtext {
            color: var(--text-muted);
            font-size: 0.9em;
            margin-top: 10px;
        }

        /* Footer */
        footer {
            text-align: center;
            padding: 40px 20px;
            color: var(--text-muted);
            font-size: 0.9em;
        }

        .language-badges {
            display: flex;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
            margin-top: 20px;
        }

        .lang-badge {
            padding: 8px 16px;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 20px;
            font-size: 0.85em;
            color: var(--text-secondary);
            transition: all 0.3s;
        }

        .lang-badge:hover {
            border-color: var(--accent-blue);
            color: var(--accent-blue);
        }

        /* File list for repo scan */
        .file-list {
            max-height: 400px;
            overflow-y: auto;
            padding: 10px;
        }

        .file-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 12px 15px;
            background: var(--bg-secondary);
            border-radius: 8px;
            margin-bottom: 8px;
            font-size: 0.9em;
        }

        .file-item.vulnerable {
            border-left: 3px solid var(--accent-red);
        }

        .file-item.safe {
            border-left: 3px solid var(--accent-green);
        }

        .file-path {
            font-family: 'JetBrains Mono', monospace;
            color: var(--text-secondary);
        }

        .file-issues {
            font-weight: 600;
        }

        /* Responsive */
        @media (max-width: 768px) {
            h1 { font-size: 2em; }
            .tabs { flex-wrap: wrap; }
            .tab-btn { padding: 15px; font-size: 0.9em; }
            .results-header { flex-direction: column; text-align: center; }
            .score-section { text-align: center; }
            .github-input-container { flex-direction: column; }
        }
    </style>
</head>
<body>
    <div class="bg-animation"></div>

    <div class="container">
        <header>
            <div class="logo">
                <div class="logo-icon"><img src="/static/favicon.png" alt="EasyGuard Logo"></div>
                <h1>Easy<span class="highlight">Guard</span></h1>
            </div>
            <p class="tagline">AI-Powered Code Security Scanner • Detect Vulnerabilities Before Hackers Do</p>

            <div class="stats-bar">
                <div class="stat-item">
                    <div class="stat-value">9</div>
                    <div class="stat-label">Languages</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">50+</div>
                    <div class="stat-label">Vulnerability Patterns</div>
                </div>
                <div class="stat-item">
                    <div class="stat-value">20+</div>
                    <div class="stat-label">CWE Categories</div>
                </div>
            </div>
        </header>

        <div class="scanner-card">
            <div class="tabs">
                <button class="tab-btn active" onclick="switchTab('upload')">
                    <span class="tab-icon">&#128194;</span>
                    Upload Files
                </button>
                <button class="tab-btn" onclick="switchTab('paste')">
                    <span class="tab-icon">&#128221;</span>
                    Paste Code
                </button>
                <button class="tab-btn" onclick="switchTab('github')">
                    <span class="tab-icon">&#128025;</span>
                    GitHub Repo
                </button>
            </div>

            <!-- Upload Tab -->
            <div id="upload-tab" class="tab-content active">
                <div class="upload-area" id="drop-zone" onclick="document.getElementById('file-input').click()">
                    <div class="upload-icon">&#128194;</div>
                    <div class="upload-text">Drop files here or click to browse</div>
                    <div class="upload-hint">Supports: C, C++, Python, JavaScript, PHP, Go, Rust, Ruby, Java and more</div>
                    <input type="file" id="file-input" multiple accept=".c,.h,.cpp,.cc,.cxx,.hpp,.py,.pyw,.js,.ts,.jsx,.tsx,.mjs,.php,.phtml,.go,.rs,.rb,.erb,.java,.cs,.swift,.kt,.kts">
                </div>
                <div id="file-list-preview" style="display: none;"></div>
                <button class="scan-btn" id="scan-upload-btn" onclick="scanUploadedFiles()" disabled>
                    <span>&#128270;</span>
                    Scan Files
                </button>
            </div>

            <!-- Paste Tab -->
            <div id="paste-tab" class="tab-content">
                <div class="code-container">
                    <textarea id="code-input" placeholder="// Paste your code here...
// Example vulnerable code:

void process(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // Buffer overflow!
    printf(buffer);         // Format string vulnerability!
}"></textarea>
                </div>
                <div class="input-row">
                    <div class="input-group">
                        <label for="language">Language</label>
                        <select id="language">
                            <option value="auto">Auto Detect</option>
                            <option value="c">C</option>
                            <option value="cpp">C++</option>
                            <option value="python">Python</option>
                            <option value="javascript">JavaScript</option>
                            <option value="typescript">TypeScript</option>
                            <option value="php">PHP</option>
                            <option value="go">Go</option>
                            <option value="rust">Rust</option>
                            <option value="ruby">Ruby</option>
                            <option value="java">Java</option>
                        </select>
                    </div>
                </div>
                <button class="scan-btn" onclick="scanPastedCode()">
                    <span>&#128270;</span>
                    Scan Code
                </button>
            </div>

            <!-- GitHub Tab -->
            <div id="github-tab" class="tab-content">
                <div class="github-input-container">
                    <div class="input-group">
                        <label for="github-url">GitHub Repository URL</label>
                        <input type="text" id="github-url" placeholder="https://github.com/username/repository">
                    </div>
                </div>
                <p class="github-hint">
                    Enter a GitHub URL like <code>https://github.com/user/repo</code> - we'll clone and scan all source files
                </p>
                <button class="scan-btn" onclick="scanGitHub()">
                    <span>&#128270;</span>
                    Clone & Scan Repository
                </button>
            </div>
        </div>

        <!-- Results -->
        <div class="results-container" id="results-container">
            <div id="loading" class="results-card" style="display: none;">
                <div class="loading">
                    <div class="spinner"></div>
                    <div class="loading-text">Analyzing code for vulnerabilities...</div>
                    <div class="loading-subtext" id="loading-status">Initializing scanner...</div>
                </div>
            </div>

            <div class="results-card" id="results-card" style="display: none;">
                <div class="results-header">
                    <div class="status-section">
                        <div class="status-badge" id="status-badge">
                            <span id="status-icon"></span>
                            <span id="status-text"></span>
                        </div>
                        <div class="scan-info" id="scan-info"></div>
                    </div>
                    <div class="score-section">
                        <div class="score-label">Risk Score</div>
                        <div class="score-value" id="score-value">0%</div>
                    </div>
                </div>

                <div class="summary-stats" id="summary-stats"></div>

                <div class="vuln-list" id="vuln-list"></div>
            </div>
        </div>

        <footer>
            <p style="font-size: 1.1em; font-weight: 600; margin-bottom: 8px;">EasyGuard - AI-Powered Code Security Scanner</p>
            <p style="color: var(--text-muted); margin-bottom: 20px;">Created with ❤️ by <span style="color: var(--accent-purple); font-weight: 600;">Kavi</span></p>
            <div class="language-badges">
                <span class="lang-badge">C/C++</span>
                <span class="lang-badge">Python</span>
                <span class="lang-badge">JavaScript</span>
                <span class="lang-badge">PHP</span>
                <span class="lang-badge">Go</span>
                <span class="lang-badge">Rust</span>
                <span class="lang-badge">Ruby</span>
                <span class="lang-badge">Java</span>
                <span class="lang-badge">TypeScript</span>
            </div>
            <p style="margin-top: 20px; font-size: 0.85em; color: var(--text-muted);">© 2026 EasyGuard. All rights reserved.</p>
        </footer>
    </div>

    <script>
        let selectedFiles = [];

        function switchTab(tab) {
            document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            event.target.closest('.tab-btn').classList.add('active');
            document.getElementById(`${tab}-tab`).classList.add('active');
        }

        // File upload handling
        const dropZone = document.getElementById('drop-zone');
        const fileInput = document.getElementById('file-input');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.add('dragover'));
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => dropZone.classList.remove('dragover'));
        });

        dropZone.addEventListener('drop', (e) => {
            const files = e.dataTransfer.files;
            handleFiles(files);
        });

        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });

        function handleFiles(files) {
            selectedFiles = Array.from(files);
            updateFilePreview();
        }

        function updateFilePreview() {
            const preview = document.getElementById('file-list-preview');
            const scanBtn = document.getElementById('scan-upload-btn');

            if (selectedFiles.length === 0) {
                preview.style.display = 'none';
                scanBtn.disabled = true;
                return;
            }

            scanBtn.disabled = false;
            preview.style.display = 'block';
            preview.innerHTML = `
                <div class="file-selected">
                    <span>&#128206;</span>
                    <span>${selectedFiles.length} file(s) selected: ${selectedFiles.map(f => f.name).join(', ')}</span>
                </div>
            `;
        }

        async function scanUploadedFiles() {
            if (selectedFiles.length === 0) return;

            showLoading('Scanning uploaded files...');

            const formData = new FormData();
            selectedFiles.forEach(file => formData.append('files', file));

            try {
                const response = await fetch('/scan/files', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                displayResults(result);
            } catch (error) {
                showError(error.message);
            }
        }

        async function scanPastedCode() {
            const code = document.getElementById('code-input').value;
            const language = document.getElementById('language').value;

            if (!code.trim()) {
                showError('Please enter some code to scan.');
                return;
            }

            showLoading('Analyzing code...');

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `code=${encodeURIComponent(code)}&language=${language}`
                });
                const result = await response.json();
                displayResults(result);
            } catch (error) {
                showError(error.message);
            }
        }

        async function scanGitHub() {
            const url = document.getElementById('github-url').value.trim();

            if (!url) {
                showError('Please enter a GitHub repository URL.');
                return;
            }

            if (!url.includes('github.com')) {
                showError('Please enter a valid GitHub URL.');
                return;
            }

            showLoading('Cloning repository...');
            updateLoadingStatus('This may take a moment for large repositories...');

            try {
                const response = await fetch('/scan/github', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: url })
                });
                const result = await response.json();
                displayResults(result);
            } catch (error) {
                showError(error.message);
            }
        }

        function showLoading(message) {
            document.getElementById('results-container').classList.add('show');
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results-card').style.display = 'none';
            document.querySelector('.loading-text').textContent = message;
        }

        function updateLoadingStatus(status) {
            document.getElementById('loading-status').textContent = status;
        }

        function showError(message) {
            document.getElementById('loading').style.display = 'none';
            document.getElementById('results-card').style.display = 'block';
            document.getElementById('results-card').innerHTML = `
                <div style="padding: 40px; text-align: center; color: var(--accent-red);">
                    <div style="font-size: 3em; margin-bottom: 15px;">&#9888;</div>
                    <h3>Error</h3>
                    <p style="color: var(--text-secondary); margin-top: 10px;">${escapeHtml(message)}</p>
                </div>
            `;
        }

        function displayResults(result) {
            document.getElementById('loading').style.display = 'none';
            document.getElementById('results-card').style.display = 'block';

            if (result.error) {
                showError(result.error);
                return;
            }

            const isVulnerable = result.vulnerable;
            const score = Math.round((result.vulnerability_score || 0) * 100);
            const patterns = result.patterns || [];
            const filesScanned = result.files_scanned || 1;
            const totalIssues = result.total_issues || patterns.length;

            // Status badge
            const statusBadge = document.getElementById('status-badge');
            const statusIcon = document.getElementById('status-icon');
            const statusText = document.getElementById('status-text');

            statusBadge.className = `status-badge ${isVulnerable ? 'status-vulnerable' : 'status-safe'}`;
            statusIcon.innerHTML = isVulnerable ? '&#9888;' : '&#10004;';
            statusText.textContent = isVulnerable ? 'VULNERABLE' : 'SECURE';

            // Scan info
            document.getElementById('scan-info').innerHTML = `
                ${filesScanned} file(s) scanned &bull; ${result.language || 'Multiple languages'}
            `;

            // Score
            const scoreValue = document.getElementById('score-value');
            scoreValue.textContent = `${score}%`;
            scoreValue.className = `score-value ${score < 20 ? 'score-safe' : score < 50 ? 'score-low' : 'score-high'}`;

            // Summary stats
            const criticalCount = patterns.filter(p => p.severity === 'CRITICAL').length;
            const highCount = patterns.filter(p => p.severity === 'HIGH').length;
            const mediumCount = patterns.filter(p => p.severity === 'MEDIUM').length;
            const lowCount = patterns.filter(p => p.severity === 'LOW').length;

            document.getElementById('summary-stats').innerHTML = `
                <div class="summary-stat">
                    <div class="summary-stat-value" style="color: var(--accent-red);">${criticalCount}</div>
                    <div class="summary-stat-label">Critical</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value" style="color: var(--accent-orange);">${highCount}</div>
                    <div class="summary-stat-label">High</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value" style="color: #eab308;">${mediumCount}</div>
                    <div class="summary-stat-label">Medium</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value" style="color: var(--text-muted);">${lowCount}</div>
                    <div class="summary-stat-label">Low</div>
                </div>
                <div class="summary-stat">
                    <div class="summary-stat-value" style="color: var(--accent-blue);">${filesScanned}</div>
                    <div class="summary-stat-label">Files</div>
                </div>
            `;

            // Vulnerability list
            const vulnList = document.getElementById('vuln-list');

            if (patterns.length === 0) {
                vulnList.innerHTML = `
                    <div class="no-vulns">
                        <div class="no-vulns-icon">&#9989;</div>
                        <h3>No Vulnerabilities Detected!</h3>
                        <p>Your code appears to be free of common security issues.</p>
                    </div>
                `;
            } else {
                vulnList.innerHTML = patterns.map(vuln => `
                    <div class="vuln-item ${vuln.severity.toLowerCase()}">
                        <div class="vuln-header">
                            <div class="vuln-title">
                                <span class="vuln-name">${escapeHtml(vuln.name)}</span>
                                ${vuln.file ? `<span class="vuln-file">${escapeHtml(vuln.file)}</span>` : ''}
                            </div>
                            <span class="severity-badge severity-${vuln.severity.toLowerCase()}">${vuln.severity}</span>
                        </div>
                        <div class="vuln-meta">
                            <span>&#128204; Line ${vuln.line}</span>
                            <span>&#128196; ${escapeHtml(vuln.type)}</span>
                            ${vuln.cwe ? `<span>&#128274; ${vuln.cwe}</span>` : ''}
                        </div>
                        <div class="vuln-code">${escapeHtml(vuln.code || '')}</div>
                        <div class="vuln-description">${escapeHtml(vuln.description)}</div>
                        ${vuln.fix ? `<div class="vuln-fix"><strong>&#128161; Fix:</strong> ${escapeHtml(vuln.fix)}</div>` : ''}
                    </div>
                `).join('');
            }
        }

        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
    </script>
</body>
</html>
'''


def get_language_from_extension(filename):
    """Get language from file extension."""
    ext = Path(filename).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(ext, 'auto')


def analyze_code(code, language='auto', filename=None):
    """Analyze code for vulnerabilities."""
    if language == 'auto':
        language = detector._detect_language(code)

    matches = detector.detect(code, language)
    score = detector.get_vulnerability_score(matches)

    patterns = []
    for m in matches:
        patterns.append({
            'name': m.pattern_name,
            'type': m.vulnerability_type,
            'severity': m.severity,
            'line': m.line_number,
            'code': m.code_snippet[:150] + ('...' if len(m.code_snippet) > 150 else ''),
            'cwe': m.cwe_id,
            'description': m.description,
            'fix': m.fix_suggestion,
            'file': filename,
        })

    return {
        'vulnerable': score > 0.2 or len(matches) > 0,
        'vulnerability_score': score,
        'language': language,
        'patterns': patterns,
        'total_issues': len(matches),
    }


def scan_directory(directory_path):
    """Scan all source files in a directory."""
    all_patterns = []
    files_scanned = 0
    total_score = 0

    for root, dirs, files in os.walk(directory_path):
        # Skip hidden directories and common non-source directories
        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                   ['node_modules', 'vendor', 'venv', '__pycache__', 'target', 'build', 'dist']]

        for file in files:
            ext = Path(file).suffix.lower()
            if ext in ALLOWED_EXTENSIONS:
                file_path = os.path.join(root, file)
                relative_path = os.path.relpath(file_path, directory_path)

                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()

                    if len(code) > 500000:  # Skip files > 500KB
                        continue

                    language = get_language_from_extension(file)
                    result = analyze_code(code, language, relative_path)

                    for pattern in result['patterns']:
                        pattern['file'] = relative_path
                        all_patterns.append(pattern)

                    total_score += result['vulnerability_score']
                    files_scanned += 1

                except Exception as e:
                    continue

    avg_score = total_score / files_scanned if files_scanned > 0 else 0

    return {
        'vulnerable': len(all_patterns) > 0,
        'vulnerability_score': min(avg_score * 2, 1.0),  # Amplify for visibility
        'patterns': sorted(all_patterns, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4)),
        'total_issues': len(all_patterns),
        'files_scanned': files_scanned,
        'language': 'Multiple',
    }


def clone_github_repo(url):
    """Clone a GitHub repository to a temporary directory."""
    # Parse GitHub URL
    url = url.strip().rstrip('/')
    if url.endswith('.git'):
        url = url[:-4]

    # Create temp directory
    temp_dir = tempfile.mkdtemp(prefix='zeroday_scan_')

    try:
        # Clone the repository
        result = subprocess.run(
            ['git', 'clone', '--depth', '1', url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            shutil.rmtree(temp_dir, ignore_errors=True)
            raise Exception(f"Failed to clone repository: {result.stderr}")

        return temp_dir

    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception("Repository clone timed out. Try a smaller repository.")
    except FileNotFoundError:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise Exception("Git is not installed. Please install Git to use this feature.")


@app.route('/')
def index():
    """Render the main page."""
    return render_template_string(HTML_TEMPLATE)


@app.route('/scan', methods=['POST'])
def scan():
    """Scan code from form submission."""
    try:
        if 'file' in request.files:
            file = request.files['file']
            if file.filename:
                language = get_language_from_extension(file.filename)
                code = file.read().decode('utf-8', errors='ignore')
                result = analyze_code(code, language, secure_filename(file.filename))
                result['files_scanned'] = 1
                return jsonify(result)

        if 'code' in request.form:
            code = request.form['code']
            language = request.form.get('language', 'auto')

            if not code.strip():
                return jsonify({'error': 'No code provided'})

            result = analyze_code(code, language)
            result['files_scanned'] = 1
            return jsonify(result)

        return jsonify({'error': 'No file or code provided'})

    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/scan/files', methods=['POST'])
def scan_files():
    """Scan multiple uploaded files."""
    try:
        files = request.files.getlist('files')

        if not files:
            return jsonify({'error': 'No files provided'})

        all_patterns = []
        total_score = 0
        files_scanned = 0

        for file in files:
            if file.filename:
                ext = Path(file.filename).suffix.lower()
                if ext in ALLOWED_EXTENSIONS:
                    language = get_language_from_extension(file.filename)
                    code = file.read().decode('utf-8', errors='ignore')
                    result = analyze_code(code, language, secure_filename(file.filename))

                    for pattern in result['patterns']:
                        all_patterns.append(pattern)

                    total_score += result['vulnerability_score']
                    files_scanned += 1

        if files_scanned == 0:
            return jsonify({'error': 'No supported source files found'})

        avg_score = total_score / files_scanned

        return jsonify({
            'vulnerable': len(all_patterns) > 0,
            'vulnerability_score': avg_score,
            'patterns': sorted(all_patterns, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}.get(x['severity'], 4)),
            'total_issues': len(all_patterns),
            'files_scanned': files_scanned,
            'language': 'Multiple',
        })

    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/scan/github', methods=['POST'])
def scan_github():
    """Clone and scan a GitHub repository."""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()

        if not url:
            return jsonify({'error': 'No URL provided'})

        if 'github.com' not in url:
            return jsonify({'error': 'Please provide a valid GitHub URL'})

        # Clone the repository
        temp_dir = clone_github_repo(url)

        try:
            # Scan the cloned repository
            result = scan_directory(temp_dir)
            result['repository'] = url
            return jsonify(result)

        finally:
            # Cleanup
            shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for programmatic access."""
    try:
        data = request.get_json()

        if not data or 'code' not in data:
            return jsonify({'error': 'Missing "code" field'}), 400

        code = data['code']
        language = data.get('language', 'auto')

        result = analyze_code(code, language)
        result['files_scanned'] = 1
        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  \033[95m🛡️  EasyGuard\033[0m - AI-Powered Code Security Scanner")
    print("  Created by Kavi")
    print("=" * 60)
    print("\n  Starting server...")
    print("  Open \033[96mhttp://localhost:5000\033[0m in your browser")
    print("\n  Features:")
    print("    🔼 Upload single or multiple files")
    print("    📝 Paste code directly")
    print("    🐙 Clone & scan GitHub repositories")
    print("\n  Supported: C, C++, Python, JavaScript, PHP, Go, Rust, Ruby, Java")
    print("\n  Press Ctrl+C to stop")
    print("=" * 60 + "\n")

    app.run(host='0.0.0.0', port=5000, debug=True)
