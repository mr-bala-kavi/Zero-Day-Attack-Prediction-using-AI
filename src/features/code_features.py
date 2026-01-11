"""
Code feature extraction for vulnerability detection.

Extracts numerical features from source code including:
- Complexity metrics (cyclomatic complexity, nesting depth)
- Code characteristics (line counts, token counts)
- Structural features (function counts, branching patterns)
"""

import re
from typing import Dict, List, Optional

import numpy as np

from ..utils.config import get_config
from ..utils.logger import get_logger


class CodeFeatureExtractor:
    """
    Extracts numerical features from source code for ML models.

    These features capture code complexity and patterns that may
    indicate vulnerability risk.
    """

    def __init__(self, language: str = "auto"):
        """
        Initialize the feature extractor.

        Args:
            language: Programming language (c, cpp, python, javascript, java, auto)
        """
        self.language = language
        self.config = get_config()
        self.logger = get_logger("code_features")

        # Keywords for different languages
        self.control_keywords = {
            "c": ["if", "else", "for", "while", "switch", "case", "do"],
            "cpp": ["if", "else", "for", "while", "switch", "case", "do", "try", "catch"],
            "python": ["if", "elif", "else", "for", "while", "try", "except", "with"],
            "javascript": ["if", "else", "for", "while", "switch", "case", "try", "catch"],
            "java": ["if", "else", "for", "while", "switch", "case", "try", "catch"],
        }

        # Dangerous function patterns by language
        self.dangerous_functions = self.config.get("features.dangerous_functions", {})

    def detect_language(self, code: str) -> str:
        """Auto-detect programming language."""
        if "#include" in code:
            return "cpp" if "iostream" in code or "std::" in code else "c"
        if "def " in code and ":" in code:
            return "python"
        if "function " in code or "const " in code:
            return "javascript"
        if "public class" in code:
            return "java"
        return "c"

    def extract_features(self, code: str, language: Optional[str] = None) -> Dict[str, float]:
        """
        Extract all features from code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            Dictionary of feature names to values
        """
        lang = language or self.language
        if lang == "auto":
            lang = self.detect_language(code)

        features = {}

        # Basic metrics
        features.update(self._extract_basic_metrics(code))

        # Complexity metrics
        features.update(self._extract_complexity_metrics(code, lang))

        # Control flow metrics
        features.update(self._extract_control_flow_metrics(code, lang))

        # Dangerous pattern metrics
        features.update(self._extract_dangerous_patterns(code, lang))

        # Memory-related metrics (for C/C++)
        if lang in ("c", "cpp"):
            features.update(self._extract_memory_metrics(code))

        # Input handling metrics
        features.update(self._extract_input_metrics(code, lang))

        return features

    def _extract_basic_metrics(self, code: str) -> Dict[str, float]:
        """Extract basic code metrics."""
        lines = code.split("\n")
        non_empty = [l for l in lines if l.strip()]
        tokens = re.findall(r'\w+', code)

        return {
            "total_lines": len(lines),
            "non_empty_lines": len(non_empty),
            "total_characters": len(code),
            "total_tokens": len(tokens),
            "unique_tokens": len(set(tokens)),
            "avg_line_length": np.mean([len(l) for l in lines]) if lines else 0,
            "max_line_length": max(len(l) for l in lines) if lines else 0,
            "blank_line_ratio": (len(lines) - len(non_empty)) / max(len(lines), 1),
        }

    def _extract_complexity_metrics(self, code: str, language: str) -> Dict[str, float]:
        """Extract complexity-related metrics."""
        # Cyclomatic complexity approximation
        # Count decision points: if, for, while, case, &&, ||, ?:
        decision_patterns = [
            r'\bif\b', r'\bfor\b', r'\bwhile\b', r'\bcase\b',
            r'&&', r'\|\|', r'\?.*:',
            r'\belif\b', r'\bexcept\b', r'\bcatch\b',
        ]

        decision_count = sum(
            len(re.findall(pattern, code))
            for pattern in decision_patterns
        )
        cyclomatic = decision_count + 1

        # Nesting depth
        max_nesting = self._calculate_max_nesting(code)

        # Function/method count
        function_count = len(re.findall(
            r'\b(def|function|void|int|char|float|double|public|private)\s+\w+\s*\(',
            code
        ))

        return {
            "cyclomatic_complexity": cyclomatic,
            "max_nesting_depth": max_nesting,
            "function_count": function_count,
            "decisions_per_line": decision_count / max(len(code.split("\n")), 1),
            "complexity_density": cyclomatic / max(len(code.split("\n")), 1),
        }

    def _calculate_max_nesting(self, code: str) -> int:
        """Calculate maximum nesting depth."""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char == '{':
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == '}':
                current_depth = max(0, current_depth - 1)

        # Also check for Python-style indentation
        for line in code.split("\n"):
            stripped = line.lstrip()
            if stripped:
                indent = len(line) - len(stripped)
                depth = indent // 4  # Assuming 4-space indentation
                max_depth = max(max_depth, depth)

        return max_depth

    def _extract_control_flow_metrics(self, code: str, language: str) -> Dict[str, float]:
        """Extract control flow metrics."""
        keywords = self.control_keywords.get(language, self.control_keywords["c"])

        keyword_counts = {}
        for kw in keywords:
            count = len(re.findall(rf'\b{kw}\b', code))
            keyword_counts[f"keyword_{kw}"] = count

        # Aggregate metrics
        total_control = sum(keyword_counts.values())
        loop_count = keyword_counts.get("keyword_for", 0) + keyword_counts.get("keyword_while", 0)
        branch_count = keyword_counts.get("keyword_if", 0) + keyword_counts.get("keyword_switch", 0)

        features = {
            "total_control_statements": total_control,
            "loop_count": loop_count,
            "branch_count": branch_count,
            "loop_to_branch_ratio": loop_count / max(branch_count, 1),
        }

        # Add individual keyword counts
        features.update(keyword_counts)

        return features

    def _extract_dangerous_patterns(self, code: str, language: str) -> Dict[str, float]:
        """Extract counts of dangerous function usage."""
        dangerous = self.dangerous_functions.get(language, [])

        pattern_counts = {}
        total_dangerous = 0

        for func in dangerous:
            # Match function calls
            pattern = rf'\b{re.escape(func)}\s*\('
            count = len(re.findall(pattern, code))
            pattern_counts[f"dangerous_{func.replace('.', '_')}"] = count
            total_dangerous += count

        return {
            "total_dangerous_calls": total_dangerous,
            "dangerous_call_density": total_dangerous / max(len(code.split("\n")), 1),
            **pattern_counts,
        }

    def _extract_memory_metrics(self, code: str) -> Dict[str, float]:
        """Extract memory-related metrics for C/C++."""
        malloc_count = len(re.findall(r'\bmalloc\s*\(', code))
        free_count = len(re.findall(r'\bfree\s*\(', code))
        realloc_count = len(re.findall(r'\brealloc\s*\(', code))
        new_count = len(re.findall(r'\bnew\s+', code))
        delete_count = len(re.findall(r'\bdelete\s+', code))

        total_alloc = malloc_count + new_count + realloc_count
        total_dealloc = free_count + delete_count

        return {
            "malloc_count": malloc_count,
            "free_count": free_count,
            "realloc_count": realloc_count,
            "new_count": new_count,
            "delete_count": delete_count,
            "total_allocations": total_alloc,
            "total_deallocations": total_dealloc,
            "alloc_dealloc_balance": total_alloc - total_dealloc,
            "pointer_arithmetic": len(re.findall(r'\*\s*\w+\s*[+\-]', code)),
            "array_access": len(re.findall(r'\w+\s*\[', code)),
        }

    def _extract_input_metrics(self, code: str, language: str) -> Dict[str, float]:
        """Extract input handling metrics."""
        features = {}

        if language in ("c", "cpp"):
            features["scanf_count"] = len(re.findall(r'\bscanf\s*\(', code))
            features["gets_count"] = len(re.findall(r'\bgets\s*\(', code))
            features["fgets_count"] = len(re.findall(r'\bfgets\s*\(', code))
            features["stdin_usage"] = len(re.findall(r'\bstdin\b', code))
            features["argv_usage"] = len(re.findall(r'\bargv\b', code))

        elif language == "python":
            features["input_count"] = len(re.findall(r'\binput\s*\(', code))
            features["argv_usage"] = len(re.findall(r'\bsys\.argv\b', code))
            features["request_data"] = len(re.findall(r'\brequest\.(form|args|data|json)\b', code))

        elif language == "javascript":
            features["prompt_count"] = len(re.findall(r'\bprompt\s*\(', code))
            features["query_params"] = len(re.findall(r'\b(req\.query|req\.params|req\.body)\b', code))
            features["url_params"] = len(re.findall(r'\bURLSearchParams\b', code))

        # Common patterns
        features["user_input_patterns"] = len(re.findall(
            r'\b(user_?input|userInput|user_data|userData|input_data)\b',
            code,
            re.IGNORECASE
        ))

        return features

    def get_feature_names(self, language: str = "c") -> List[str]:
        """
        Get the list of feature names that will be extracted.

        Args:
            language: Programming language

        Returns:
            List of feature names
        """
        # Extract features from sample code to get all feature names
        sample = "int main() { if (x) { for (;;) {} } }"
        features = self.extract_features(sample, language)
        return sorted(features.keys())

    def extract_batch(self, codes: List[str], language: Optional[str] = None) -> np.ndarray:
        """
        Extract features from multiple code samples.

        Args:
            codes: List of source code strings
            language: Programming language

        Returns:
            NumPy array of shape (n_samples, n_features)
        """
        all_features = []
        feature_names = None

        for code in codes:
            features = self.extract_features(code, language)
            if feature_names is None:
                feature_names = sorted(features.keys())
            all_features.append([features.get(name, 0) for name in feature_names])

        return np.array(all_features, dtype=np.float32)
