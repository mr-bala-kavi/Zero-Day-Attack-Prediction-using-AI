"""
Vulnerability pattern detector.

Detects known vulnerability patterns in source code using
rule-based matching and heuristics.
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..utils.config import get_config
from ..utils.logger import get_logger


@dataclass
class VulnerabilityMatch:
    """Represents a detected vulnerability pattern."""
    pattern_name: str
    vulnerability_type: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    line_number: int
    code_snippet: str
    description: str
    cwe_id: Optional[str] = None
    fix_suggestion: Optional[str] = None


class PatternDetector:
    """
    Detects vulnerability patterns in source code.

    Uses a rule-based approach to identify common vulnerability
    patterns across different programming languages.
    """

    def __init__(self):
        """Initialize the pattern detector."""
        self.config = get_config()
        self.logger = get_logger("pattern_detector")
        self._init_patterns()

    def _init_patterns(self) -> None:
        """Initialize vulnerability patterns for all supported languages."""

        # C/C++ patterns
        self.c_patterns = [
            {
                "name": "buffer_overflow_strcpy",
                "pattern": r'\bstrcpy\s*\([^,]+,\s*[^)]+\)',
                "type": "buffer_overflow",
                "severity": "HIGH",
                "cwe": "CWE-120",
                "description": "Use of strcpy() without bounds checking",
                "fix": "Use strncpy() or strlcpy() with proper length limits",
            },
            {
                "name": "buffer_overflow_gets",
                "pattern": r'\bgets\s*\([^)]+\)',
                "type": "buffer_overflow",
                "severity": "CRITICAL",
                "cwe": "CWE-120",
                "description": "Use of gets() which has no bounds checking",
                "fix": "Use fgets() with explicit buffer size",
            },
            {
                "name": "format_string_printf",
                "pattern": r'\bprintf\s*\(\s*\w+\s*\)',
                "type": "format_string",
                "severity": "HIGH",
                "cwe": "CWE-134",
                "description": "Format string passed directly as variable",
                "fix": "Use printf(\"%s\", variable) instead",
            },
            {
                "name": "buffer_overflow_sprintf",
                "pattern": r'\bsprintf\s*\([^,]+,',
                "type": "buffer_overflow",
                "severity": "HIGH",
                "cwe": "CWE-120",
                "description": "Use of sprintf() without bounds checking",
                "fix": "Use snprintf() with explicit buffer size",
            },
            {
                "name": "unsafe_scanf",
                "pattern": r'\bscanf\s*\(\s*"%s"',
                "type": "buffer_overflow",
                "severity": "HIGH",
                "cwe": "CWE-120",
                "description": "scanf with %s has no bounds checking",
                "fix": "Use scanf with width specifier: %Ns where N is buffer size - 1",
            },
            {
                "name": "use_after_free",
                "pattern": r'free\s*\(\s*\w+\s*\)',
                "type": "use_after_free",
                "severity": "CRITICAL",
                "cwe": "CWE-416",
                "description": "Potential use after free vulnerability",
                "fix": "Set pointer to NULL after freeing",
            },
            {
                "name": "null_pointer_deref",
                "pattern": r'\*\s*\(\s*\w+\s*\)\s*(?!if)',
                "type": "null_pointer",
                "severity": "MEDIUM",
                "cwe": "CWE-476",
                "description": "Pointer dereference without null check",
                "fix": "Add null pointer check before dereference",
            },
            {
                "name": "integer_overflow",
                "pattern": r'malloc\s*\(\s*\w+\s*\*\s*\w+\s*\)',
                "type": "integer_overflow",
                "severity": "HIGH",
                "cwe": "CWE-190",
                "description": "Integer overflow in malloc size calculation",
                "fix": "Use size_t and check for overflow before multiplication",
            },
            {
                "name": "command_injection",
                "pattern": r'\bsystem\s*\(\s*[^"]+\)',
                "type": "command_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-78",
                "description": "system() call with non-constant argument",
                "fix": "Validate and sanitize input, use exec() family instead",
            },
        ]

        # Python patterns
        self.python_patterns = [
            {
                "name": "sql_injection",
                "pattern": r'execute\s*\(\s*["\'].*%s.*["\'].*%',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with string formatting",
                "fix": "Use parameterized queries with ? or %s placeholders",
            },
            {
                "name": "sql_injection_fstring",
                "pattern": r'execute\s*\(\s*f["\']',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with f-string interpolation",
                "fix": "Use parameterized queries instead of f-strings",
            },
            {
                "name": "sql_injection_concat",
                "pattern": r'(SELECT|INSERT|UPDATE|DELETE).*\+.*\w+',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query built with string concatenation",
                "fix": "Use parameterized queries instead of string concatenation",
            },
            {
                "name": "sql_injection_format",
                "pattern": r'f["\'].*SELECT.*FROM.*\{',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with f-string interpolation",
                "fix": "Use parameterized queries instead of f-strings",
            },
            {
                "name": "command_injection_os",
                "pattern": r'os\.system\s*\(',
                "type": "command_injection",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "description": "Use of os.system() for command execution",
                "fix": "Use subprocess module with shell=False",
            },
            {
                "name": "command_injection_subprocess",
                "pattern": r'subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True',
                "type": "command_injection",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "description": "subprocess with shell=True",
                "fix": "Use shell=False and pass command as list",
            },
            {
                "name": "eval_usage",
                "pattern": r'\beval\s*\(',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "Use of eval() can execute arbitrary code",
                "fix": "Use ast.literal_eval() for safe evaluation",
            },
            {
                "name": "exec_usage",
                "pattern": r'\bexec\s*\(',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "Use of exec() can execute arbitrary code",
                "fix": "Avoid exec(), use safer alternatives",
            },
            {
                "name": "pickle_load",
                "pattern": r'pickle\.(load|loads)\s*\(',
                "type": "deserialization",
                "severity": "HIGH",
                "cwe": "CWE-502",
                "description": "Unsafe deserialization with pickle",
                "fix": "Use JSON or other safe serialization formats",
            },
            {
                "name": "yaml_unsafe_load",
                "pattern": r'yaml\.load\s*\([^)]*(?!Loader)',
                "type": "deserialization",
                "severity": "HIGH",
                "cwe": "CWE-502",
                "description": "yaml.load() without safe Loader",
                "fix": "Use yaml.safe_load() instead",
            },
            {
                "name": "hardcoded_password",
                "pattern": r'password\s*=\s*["\'][^"\']+["\']',
                "type": "hardcoded_credentials",
                "severity": "HIGH",
                "cwe": "CWE-798",
                "description": "Hardcoded password in source code",
                "fix": "Use environment variables or secure vault",
            },
        ]

        # JavaScript patterns
        self.javascript_patterns = [
            {
                "name": "xss_innerhtml",
                "pattern": r'\.innerHTML\s*=',
                "type": "xss",
                "severity": "HIGH",
                "cwe": "CWE-79",
                "description": "Direct innerHTML assignment",
                "fix": "Use textContent or sanitize HTML with DOMPurify",
            },
            {
                "name": "xss_document_write",
                "pattern": r'document\.write\s*\(',
                "type": "xss",
                "severity": "HIGH",
                "cwe": "CWE-79",
                "description": "Use of document.write()",
                "fix": "Use DOM manipulation methods instead",
            },
            {
                "name": "eval_usage",
                "pattern": r'\beval\s*\(',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "Use of eval() can execute arbitrary code",
                "fix": "Use JSON.parse() for data, avoid eval()",
            },
            {
                "name": "dangerous_function_constructor",
                "pattern": r'new\s+Function\s*\(',
                "type": "code_injection",
                "severity": "HIGH",
                "cwe": "CWE-95",
                "description": "Function constructor can execute arbitrary code",
                "fix": "Avoid dynamic function creation",
            },
            {
                "name": "sql_injection",
                "pattern": r'query\s*\(\s*[`"\'].*\$\{',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with template literal interpolation",
                "fix": "Use parameterized queries",
            },
            {
                "name": "path_traversal",
                "pattern": r'(readFile|writeFile|createReadStream)\s*\(\s*[^\'"][^)]+\)',
                "type": "path_traversal",
                "severity": "HIGH",
                "cwe": "CWE-22",
                "description": "File operation with unsanitized path",
                "fix": "Validate and sanitize file paths",
            },
            {
                "name": "prototype_pollution",
                "pattern": r'Object\.assign\s*\(\s*[^,]+,\s*\w+\s*\)',
                "type": "prototype_pollution",
                "severity": "MEDIUM",
                "cwe": "CWE-1321",
                "description": "Potential prototype pollution",
                "fix": "Validate object keys, use Object.create(null)",
            },
        ]

        # PHP patterns
        self.php_patterns = [
            {
                "name": "sql_injection_mysql",
                "pattern": r'mysql_query\s*\(\s*["\'].*\$',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with variable interpolation",
                "fix": "Use prepared statements with PDO or mysqli",
            },
            {
                "name": "sql_injection_concat",
                "pattern": r'mysqli_query\s*\([^,]+,\s*["\'].*\.\s*\$',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with string concatenation",
                "fix": "Use prepared statements with mysqli_prepare()",
            },
            {
                "name": "command_injection_exec",
                "pattern": r'\b(exec|shell_exec|system|passthru|popen)\s*\(',
                "type": "command_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-78",
                "description": "Command execution function usage",
                "fix": "Use escapeshellarg() and escapeshellcmd(), avoid if possible",
            },
            {
                "name": "command_injection_backtick",
                "pattern": r'`.*\$.*`',
                "type": "command_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-78",
                "description": "Backtick command execution with variable",
                "fix": "Avoid backtick execution, use escapeshellarg()",
            },
            {
                "name": "code_injection_eval",
                "pattern": r'\beval\s*\(',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "Use of eval() can execute arbitrary code",
                "fix": "Avoid eval(), use safer alternatives",
            },
            {
                "name": "code_injection_preg",
                "pattern": r'preg_replace\s*\(\s*["\'][^"\']*\/e',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "preg_replace with /e modifier executes code",
                "fix": "Use preg_replace_callback() instead",
            },
            {
                "name": "file_inclusion_lfi",
                "pattern": r'\b(include|require|include_once|require_once)\s*\(\s*\$',
                "type": "file_inclusion",
                "severity": "CRITICAL",
                "cwe": "CWE-98",
                "description": "Dynamic file inclusion vulnerability",
                "fix": "Use whitelist of allowed files, avoid user input in paths",
            },
            {
                "name": "xss_echo",
                "pattern": r'echo\s+\$_(GET|POST|REQUEST|COOKIE)',
                "type": "xss",
                "severity": "HIGH",
                "cwe": "CWE-79",
                "description": "Unescaped output of user input",
                "fix": "Use htmlspecialchars() or htmlentities()",
            },
            {
                "name": "deserialization",
                "pattern": r'\bunserialize\s*\(\s*\$',
                "type": "deserialization",
                "severity": "CRITICAL",
                "cwe": "CWE-502",
                "description": "Unsafe deserialization of user input",
                "fix": "Use JSON instead, or validate input strictly",
            },
            {
                "name": "file_upload",
                "pattern": r'move_uploaded_file\s*\(',
                "type": "file_upload",
                "severity": "MEDIUM",
                "cwe": "CWE-434",
                "description": "File upload - ensure proper validation",
                "fix": "Validate file type, size, and use random filenames",
            },
        ]

        # Go patterns
        self.go_patterns = [
            {
                "name": "sql_injection",
                "pattern": r'(Query|Exec)\s*\(\s*["\`].*\+',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with string concatenation",
                "fix": "Use parameterized queries with ? placeholders",
            },
            {
                "name": "sql_injection_fmt",
                "pattern": r'(Query|Exec)\s*\(\s*fmt\.Sprintf',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query built with fmt.Sprintf",
                "fix": "Use parameterized queries instead of fmt.Sprintf",
            },
            {
                "name": "command_injection",
                "pattern": r'exec\.Command\s*\(\s*[^"]+\+',
                "type": "command_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-78",
                "description": "Command execution with dynamic input",
                "fix": "Validate and sanitize input, use allowlists",
            },
            {
                "name": "command_injection_shell",
                "pattern": r'exec\.Command\s*\(\s*["\']*(sh|bash|cmd)["\']',
                "type": "command_injection",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "description": "Shell command execution",
                "fix": "Avoid shell execution, use direct commands",
            },
            {
                "name": "path_traversal",
                "pattern": r'(os\.Open|ioutil\.ReadFile)\s*\(\s*[^"]+\+',
                "type": "path_traversal",
                "severity": "HIGH",
                "cwe": "CWE-22",
                "description": "File operation with dynamic path",
                "fix": "Use filepath.Clean() and validate paths",
            },
            {
                "name": "weak_crypto_md5",
                "pattern": r'md5\.New\s*\(\s*\)|md5\.Sum\s*\(',
                "type": "weak_crypto",
                "severity": "MEDIUM",
                "cwe": "CWE-328",
                "description": "Use of weak MD5 hash",
                "fix": "Use SHA-256 or stronger hash functions",
            },
            {
                "name": "weak_crypto_sha1",
                "pattern": r'sha1\.New\s*\(\s*\)|sha1\.Sum\s*\(',
                "type": "weak_crypto",
                "severity": "MEDIUM",
                "cwe": "CWE-328",
                "description": "Use of weak SHA1 hash",
                "fix": "Use SHA-256 or stronger hash functions",
            },
            {
                "name": "hardcoded_credentials",
                "pattern": r'(password|secret|apikey|api_key)\s*[=:]\s*["\'][^"\']+["\']',
                "type": "hardcoded_credentials",
                "severity": "HIGH",
                "cwe": "CWE-798",
                "description": "Hardcoded credentials in source code",
                "fix": "Use environment variables or secure vault",
            },
            {
                "name": "insecure_tls",
                "pattern": r'InsecureSkipVerify\s*:\s*true',
                "type": "insecure_config",
                "severity": "HIGH",
                "cwe": "CWE-295",
                "description": "TLS certificate verification disabled",
                "fix": "Enable certificate verification in production",
            },
        ]

        # Rust patterns
        self.rust_patterns = [
            {
                "name": "unsafe_block",
                "pattern": r'\bunsafe\s*\{',
                "type": "unsafe_code",
                "severity": "MEDIUM",
                "cwe": "CWE-119",
                "description": "Unsafe block - manual memory safety required",
                "fix": "Minimize unsafe blocks, document safety invariants",
            },
            {
                "name": "raw_pointer_deref",
                "pattern": r'\*\s*(mut|const)\s+\w+',
                "type": "unsafe_code",
                "severity": "MEDIUM",
                "cwe": "CWE-119",
                "description": "Raw pointer usage",
                "fix": "Use safe references where possible",
            },
            {
                "name": "command_injection",
                "pattern": r'Command::new\s*\(\s*[^"]+\)',
                "type": "command_injection",
                "severity": "HIGH",
                "cwe": "CWE-78",
                "description": "Command execution with dynamic input",
                "fix": "Validate input, avoid shell interpretation",
            },
            {
                "name": "sql_injection",
                "pattern": r'(execute|query)\s*\(\s*format!',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query built with format! macro",
                "fix": "Use parameterized queries",
            },
            {
                "name": "unwrap_usage",
                "pattern": r'\.unwrap\s*\(\s*\)',
                "type": "error_handling",
                "severity": "LOW",
                "cwe": "CWE-755",
                "description": "unwrap() can panic on error",
                "fix": "Use proper error handling with ? or match",
            },
            {
                "name": "expect_usage",
                "pattern": r'\.expect\s*\(\s*["\']',
                "type": "error_handling",
                "severity": "LOW",
                "cwe": "CWE-755",
                "description": "expect() can panic on error",
                "fix": "Use proper error handling with ? or match",
            },
            {
                "name": "transmute_usage",
                "pattern": r'mem::transmute',
                "type": "unsafe_code",
                "severity": "HIGH",
                "cwe": "CWE-704",
                "description": "transmute bypasses type safety",
                "fix": "Use safe type conversions, document invariants",
            },
            {
                "name": "forget_usage",
                "pattern": r'mem::forget',
                "type": "memory_leak",
                "severity": "MEDIUM",
                "cwe": "CWE-401",
                "description": "mem::forget can cause memory leaks",
                "fix": "Ensure proper cleanup, use ManuallyDrop if needed",
            },
        ]

        # Ruby patterns
        self.ruby_patterns = [
            {
                "name": "sql_injection",
                "pattern": r'(where|find_by_sql|execute)\s*\(\s*["\'].*#\{',
                "type": "sql_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-89",
                "description": "SQL query with string interpolation",
                "fix": "Use parameterized queries with ? placeholders",
            },
            {
                "name": "command_injection",
                "pattern": r'(`.*#\{|system\s*\(|exec\s*\(|%x\[)',
                "type": "command_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-78",
                "description": "Command execution vulnerability",
                "fix": "Use array form of system(), sanitize input",
            },
            {
                "name": "code_injection_eval",
                "pattern": r'\beval\s*\(',
                "type": "code_injection",
                "severity": "CRITICAL",
                "cwe": "CWE-95",
                "description": "Use of eval() can execute arbitrary code",
                "fix": "Avoid eval, use safer alternatives",
            },
            {
                "name": "deserialization",
                "pattern": r'(Marshal\.load|YAML\.load)\s*\(',
                "type": "deserialization",
                "severity": "CRITICAL",
                "cwe": "CWE-502",
                "description": "Unsafe deserialization",
                "fix": "Use YAML.safe_load or JSON",
            },
            {
                "name": "mass_assignment",
                "pattern": r'\.new\s*\(\s*params',
                "type": "mass_assignment",
                "severity": "MEDIUM",
                "cwe": "CWE-915",
                "description": "Potential mass assignment vulnerability",
                "fix": "Use strong parameters or permit specific attributes",
            },
        ]

    def detect(self, code: str, language: str = "auto") -> List[VulnerabilityMatch]:
        """
        Detect vulnerability patterns in code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            List of detected vulnerability matches
        """
        if language == "auto":
            language = self._detect_language(code)

        patterns = self._get_patterns(language)
        matches = []

        lines = code.split("\n")
        for pattern_def in patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern_def["pattern"], line, re.IGNORECASE):
                    matches.append(VulnerabilityMatch(
                        pattern_name=pattern_def["name"],
                        vulnerability_type=pattern_def["type"],
                        severity=pattern_def["severity"],
                        line_number=i,
                        code_snippet=line.strip(),
                        description=pattern_def["description"],
                        cwe_id=pattern_def.get("cwe"),
                        fix_suggestion=pattern_def.get("fix"),
                    ))

        self.logger.info(f"Detected {len(matches)} potential vulnerabilities")
        return matches

    def _detect_language(self, code: str) -> str:
        """Auto-detect programming language."""
        # C/C++
        if "#include" in code:
            return "cpp" if "iostream" in code or "std::" in code else "c"
        # Rust
        if "fn main()" in code or "fn " in code and "->" in code:
            return "rust"
        if "use std::" in code or "impl " in code:
            return "rust"
        # Go
        if "package main" in code or "func main()" in code:
            return "go"
        if "import (" in code or "func " in code:
            return "go"
        # PHP
        if "<?php" in code or "$_GET" in code or "$_POST" in code:
            return "php"
        # Ruby
        if "def " in code and "end" in code and ":" not in code:
            return "ruby"
        if "require " in code and "'" in code:
            return "ruby"
        # Python
        if "def " in code and ":" in code:
            return "python"
        if "import " in code and ":" in code:
            return "python"
        # JavaScript/TypeScript
        if "function " in code or "const " in code or "=>" in code:
            return "javascript"
        # Java
        if "public class" in code or "public static void main" in code:
            return "java"
        return "c"

    def _get_patterns(self, language: str) -> List[Dict]:
        """Get patterns for a specific language."""
        if language in ("c", "cpp"):
            return self.c_patterns
        elif language == "python":
            return self.python_patterns
        elif language in ("javascript", "typescript"):
            return self.javascript_patterns
        elif language == "php":
            return self.php_patterns
        elif language == "go":
            return self.go_patterns
        elif language == "rust":
            return self.rust_patterns
        elif language == "ruby":
            return self.ruby_patterns
        elif language == "java":
            return self.c_patterns  # Java shares similar patterns with C
        else:
            return self.c_patterns

    def get_vulnerability_score(self, matches: List[VulnerabilityMatch]) -> float:
        """
        Calculate an overall vulnerability score based on matches.

        Args:
            matches: List of vulnerability matches

        Returns:
            Score from 0.0 (safe) to 1.0 (highly vulnerable)
        """
        if not matches:
            return 0.0

        severity_weights = {
            "LOW": 0.1,
            "MEDIUM": 0.3,
            "HIGH": 0.6,
            "CRITICAL": 1.0,
        }

        total_weight = sum(severity_weights.get(m.severity, 0.5) for m in matches)
        # Normalize with diminishing returns for multiple vulnerabilities
        score = 1 - (1 / (1 + total_weight * 0.5))

        return min(score, 1.0)

    def generate_report(self, matches: List[VulnerabilityMatch]) -> str:
        """
        Generate a human-readable report of detected vulnerabilities.

        Args:
            matches: List of vulnerability matches

        Returns:
            Formatted report string
        """
        if not matches:
            return "No vulnerability patterns detected."

        report_lines = [
            "=" * 60,
            "VULNERABILITY SCAN REPORT",
            "=" * 60,
            f"Total issues found: {len(matches)}",
            "",
        ]

        # Group by severity
        by_severity = {}
        for match in matches:
            by_severity.setdefault(match.severity, []).append(match)

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if severity in by_severity:
                report_lines.append(f"\n[{severity}] - {len(by_severity[severity])} issue(s)")
                report_lines.append("-" * 40)

                for match in by_severity[severity]:
                    report_lines.extend([
                        f"  Line {match.line_number}: {match.pattern_name}",
                        f"    Type: {match.vulnerability_type}",
                        f"    CWE: {match.cwe_id or 'N/A'}",
                        f"    Code: {match.code_snippet[:60]}...",
                        f"    Description: {match.description}",
                        f"    Fix: {match.fix_suggestion or 'N/A'}",
                        "",
                    ])

        score = self.get_vulnerability_score(matches)
        report_lines.extend([
            "=" * 60,
            f"Overall Vulnerability Score: {score:.2f}/1.00",
            "=" * 60,
        ])

        return "\n".join(report_lines)

    def to_features(self, matches: List[VulnerabilityMatch]) -> Dict[str, float]:
        """
        Convert matches to numerical features for ML models.

        Args:
            matches: List of vulnerability matches

        Returns:
            Dictionary of feature names to values
        """
        features = {
            "total_matches": len(matches),
            "critical_count": sum(1 for m in matches if m.severity == "CRITICAL"),
            "high_count": sum(1 for m in matches if m.severity == "HIGH"),
            "medium_count": sum(1 for m in matches if m.severity == "MEDIUM"),
            "low_count": sum(1 for m in matches if m.severity == "LOW"),
            "vulnerability_score": self.get_vulnerability_score(matches),
        }

        # Count by vulnerability type
        vuln_types = set(m.vulnerability_type for m in matches)
        for vtype in ["buffer_overflow", "sql_injection", "xss", "command_injection",
                      "code_injection", "deserialization", "path_traversal"]:
            features[f"has_{vtype}"] = 1.0 if vtype in vuln_types else 0.0

        return features
