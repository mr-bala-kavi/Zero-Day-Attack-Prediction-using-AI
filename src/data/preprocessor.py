"""
Code preprocessing utilities for vulnerability detection.

Handles normalization, tokenization, and cleaning of source code.
"""

import re
from typing import List, Optional, Tuple

from ..utils.logger import get_logger


class CodePreprocessor:
    """
    Preprocessor for source code before feature extraction and model input.

    Handles various programming languages and normalizes code for
    consistent processing.
    """

    def __init__(self, language: str = "auto"):
        """
        Initialize the preprocessor.

        Args:
            language: Programming language (c, cpp, python, javascript, java, auto)
        """
        self.language = language
        self.logger = get_logger("preprocessor")

        # Language-specific comment patterns
        self.comment_patterns = {
            "c": [(r"//.*$", ""), (r"/\*[\s\S]*?\*/", "")],
            "cpp": [(r"//.*$", ""), (r"/\*[\s\S]*?\*/", "")],
            "java": [(r"//.*$", ""), (r"/\*[\s\S]*?\*/", "")],
            "javascript": [(r"//.*$", ""), (r"/\*[\s\S]*?\*/", "")],
            "python": [(r"#.*$", ""), (r'"""[\s\S]*?"""', ""), (r"'''[\s\S]*?'''", "")],
        }

        # String literal patterns
        self.string_patterns = [
            (r'"(?:[^"\\]|\\.)*"', '"STRING"'),
            (r"'(?:[^'\\]|\\.)*'", "'STRING'"),
        ]

    def detect_language(self, code: str) -> str:
        """
        Auto-detect the programming language of the code.

        Args:
            code: Source code string

        Returns:
            Detected language identifier
        """
        # Simple heuristic-based detection
        if "#include" in code or "int main(" in code:
            return "c" if ".h>" in code else "cpp"
        if "def " in code and ":" in code:
            return "python"
        if "function " in code or "const " in code or "=>" in code:
            return "javascript"
        if "public class" in code or "private void" in code:
            return "java"

        return "c"  # Default to C

    def remove_comments(self, code: str, language: Optional[str] = None) -> str:
        """
        Remove comments from source code.

        Args:
            code: Source code string
            language: Programming language (uses self.language if None)

        Returns:
            Code with comments removed
        """
        lang = language or self.language
        if lang == "auto":
            lang = self.detect_language(code)

        patterns = self.comment_patterns.get(lang, [])
        result = code

        for pattern, replacement in patterns:
            result = re.sub(pattern, replacement, result, flags=re.MULTILINE)

        return result

    def normalize_strings(self, code: str) -> str:
        """
        Replace string literals with placeholders.

        Args:
            code: Source code string

        Returns:
            Code with normalized string literals
        """
        result = code
        for pattern, replacement in self.string_patterns:
            result = re.sub(pattern, replacement, result)
        return result

    def normalize_whitespace(self, code: str) -> str:
        """
        Normalize whitespace in code.

        Args:
            code: Source code string

        Returns:
            Code with normalized whitespace
        """
        # Replace tabs with spaces
        code = code.replace("\t", "    ")

        # Remove trailing whitespace
        lines = [line.rstrip() for line in code.split("\n")]

        # Remove excessive blank lines
        result = []
        prev_blank = False
        for line in lines:
            is_blank = not line.strip()
            if is_blank and prev_blank:
                continue
            result.append(line)
            prev_blank = is_blank

        return "\n".join(result)

    def normalize_identifiers(self, code: str) -> str:
        """
        Normalize variable and function names to generic identifiers.

        This helps the model focus on patterns rather than specific names.

        Args:
            code: Source code string

        Returns:
            Code with normalized identifiers
        """
        # This is a simplified version - a full implementation would use AST
        # For now, we'll keep identifiers as-is to preserve semantic meaning
        return code

    def preprocess(
        self,
        code: str,
        remove_comments: bool = True,
        normalize_strings: bool = True,
        normalize_whitespace: bool = True,
    ) -> str:
        """
        Apply all preprocessing steps to code.

        Args:
            code: Source code string
            remove_comments: Whether to remove comments
            normalize_strings: Whether to normalize string literals
            normalize_whitespace: Whether to normalize whitespace

        Returns:
            Preprocessed code
        """
        result = code

        if remove_comments:
            result = self.remove_comments(result)
        if normalize_strings:
            result = self.normalize_strings(result)
        if normalize_whitespace:
            result = self.normalize_whitespace(result)

        return result

    def tokenize(self, code: str) -> List[str]:
        """
        Tokenize code into a list of tokens.

        Args:
            code: Source code string

        Returns:
            List of code tokens
        """
        # Simple tokenization - split on whitespace and punctuation
        # A more sophisticated version would use tree-sitter
        tokens = re.findall(r'\w+|[^\w\s]', code)
        return tokens

    def extract_functions(self, code: str, language: Optional[str] = None) -> List[Tuple[str, str]]:
        """
        Extract individual functions from code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            List of (function_name, function_code) tuples
        """
        lang = language or self.language
        if lang == "auto":
            lang = self.detect_language(code)

        functions = []

        if lang in ("c", "cpp"):
            # Match C/C++ function definitions
            pattern = r'(\w+)\s*\([^)]*\)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
            matches = re.finditer(pattern, code)
            for match in matches:
                func_name = match.group(1)
                func_body = match.group(0)
                functions.append((func_name, func_body))

        elif lang == "python":
            # Match Python function definitions
            pattern = r'def\s+(\w+)\s*\([^)]*\):[^\n]*\n((?:[ \t]+[^\n]*\n)*)'
            matches = re.finditer(pattern, code)
            for match in matches:
                func_name = match.group(1)
                func_body = match.group(0)
                functions.append((func_name, func_body))

        elif lang == "javascript":
            # Match JavaScript function definitions
            pattern = r'function\s+(\w+)\s*\([^)]*\)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
            matches = re.finditer(pattern, code)
            for match in matches:
                func_name = match.group(1)
                func_body = match.group(0)
                functions.append((func_name, func_body))

        return functions

    def get_code_stats(self, code: str) -> dict:
        """
        Get basic statistics about the code.

        Args:
            code: Source code string

        Returns:
            Dictionary with code statistics
        """
        lines = code.split("\n")
        non_empty_lines = [l for l in lines if l.strip()]
        tokens = self.tokenize(code)

        return {
            "total_lines": len(lines),
            "non_empty_lines": len(non_empty_lines),
            "total_tokens": len(tokens),
            "unique_tokens": len(set(tokens)),
            "avg_line_length": sum(len(l) for l in lines) / max(len(lines), 1),
            "max_line_length": max(len(l) for l in lines) if lines else 0,
        }
