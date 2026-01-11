"""
AST-based feature extraction for vulnerability detection.

Uses tree-sitter for parsing and extracts structural features
from Abstract Syntax Trees.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

from ..utils.logger import get_logger


class ASTFeatureExtractor:
    """
    Extract features from code using AST analysis.

    This extractor parses code into an Abstract Syntax Tree and
    extracts structural features that may indicate vulnerabilities.
    """

    def __init__(self):
        """Initialize the AST feature extractor."""
        self.logger = get_logger("ast_features")
        self._parsers = {}
        self._tree_sitter_available = False

        # Try to initialize tree-sitter parsers
        self._init_parsers()

    def _init_parsers(self) -> None:
        """Initialize tree-sitter parsers for supported languages."""
        try:
            import tree_sitter
            from tree_sitter import Language, Parser

            self._tree_sitter_available = True
            self.logger.info("Tree-sitter is available")

            # Note: In production, you would build and load language libraries
            # For now, we'll use regex-based fallback
        except ImportError:
            self.logger.warning(
                "Tree-sitter not available, using regex-based extraction"
            )
            self._tree_sitter_available = False

    def extract_features(self, code: str, language: str = "c") -> Dict[str, Any]:
        """
        Extract AST-based features from code.

        Args:
            code: Source code string
            language: Programming language

        Returns:
            Dictionary of AST features
        """
        if self._tree_sitter_available:
            return self._extract_with_tree_sitter(code, language)
        else:
            return self._extract_with_regex(code, language)

    def _extract_with_tree_sitter(self, code: str, language: str) -> Dict[str, Any]:
        """Extract features using tree-sitter parser."""
        # Placeholder for full tree-sitter implementation
        # Would parse AST and extract node types, depths, etc.
        return self._extract_with_regex(code, language)

    def _extract_with_regex(self, code: str, language: str) -> Dict[str, Any]:
        """Extract AST-like features using regex patterns."""
        features = {}

        # Function definitions
        func_defs = self._extract_function_definitions(code, language)
        features["function_count"] = len(func_defs)
        features["avg_function_length"] = np.mean([f["length"] for f in func_defs]) if func_defs else 0
        features["max_function_length"] = max([f["length"] for f in func_defs]) if func_defs else 0
        features["functions_with_params"] = sum(1 for f in func_defs if f["param_count"] > 0)

        # Variable declarations
        var_decls = self._extract_variable_declarations(code, language)
        features["variable_count"] = len(var_decls)
        features["pointer_variable_count"] = sum(1 for v in var_decls if v.get("is_pointer"))
        features["array_variable_count"] = sum(1 for v in var_decls if v.get("is_array"))

        # Control structures
        control_struct = self._extract_control_structures(code, language)
        features["if_count"] = control_struct.get("if", 0)
        features["for_count"] = control_struct.get("for", 0)
        features["while_count"] = control_struct.get("while", 0)
        features["switch_count"] = control_struct.get("switch", 0)
        features["try_count"] = control_struct.get("try", 0)

        # Call expressions
        calls = self._extract_function_calls(code, language)
        features["function_call_count"] = len(calls)
        features["unique_functions_called"] = len(set(c["name"] for c in calls))
        features["avg_call_args"] = np.mean([c["arg_count"] for c in calls]) if calls else 0

        # Operators
        operators = self._extract_operators(code)
        features["assignment_count"] = operators.get("assignment", 0)
        features["comparison_count"] = operators.get("comparison", 0)
        features["arithmetic_count"] = operators.get("arithmetic", 0)
        features["logical_count"] = operators.get("logical", 0)
        features["bitwise_count"] = operators.get("bitwise", 0)

        # Code structure
        features["max_nesting_depth"] = self._calculate_nesting_depth(code)
        features["statement_count"] = code.count(";")
        features["block_count"] = code.count("{")

        return features

    def _extract_function_definitions(self, code: str, language: str) -> List[Dict]:
        """Extract function definitions from code."""
        functions = []

        if language in ("c", "cpp", "java"):
            # Match C-style function definitions
            pattern = r'(\w+)\s+(\w+)\s*\(([^)]*)\)\s*\{'
            for match in re.finditer(pattern, code):
                return_type = match.group(1)
                name = match.group(2)
                params = match.group(3)
                param_count = len([p for p in params.split(",") if p.strip()])

                # Find function body length
                start = match.end()
                depth = 1
                end = start
                while depth > 0 and end < len(code):
                    if code[end] == "{":
                        depth += 1
                    elif code[end] == "}":
                        depth -= 1
                    end += 1

                body = code[start:end-1]
                functions.append({
                    "name": name,
                    "return_type": return_type,
                    "param_count": param_count,
                    "length": len(body.split("\n")),
                })

        elif language == "python":
            pattern = r'def\s+(\w+)\s*\(([^)]*)\):'
            for match in re.finditer(pattern, code):
                name = match.group(1)
                params = match.group(2)
                param_count = len([p for p in params.split(",") if p.strip()])

                # Estimate function length by indentation
                start = match.end()
                lines = code[start:].split("\n")
                length = 0
                for line in lines[1:]:
                    if line.strip() and not line.startswith((" ", "\t")):
                        break
                    length += 1

                functions.append({
                    "name": name,
                    "return_type": "unknown",
                    "param_count": param_count,
                    "length": max(length, 1),
                })

        elif language == "javascript":
            # Named functions
            pattern = r'function\s+(\w+)\s*\(([^)]*)\)\s*\{'
            for match in re.finditer(pattern, code):
                name = match.group(1)
                params = match.group(2)
                param_count = len([p for p in params.split(",") if p.strip()])

                functions.append({
                    "name": name,
                    "return_type": "unknown",
                    "param_count": param_count,
                    "length": 10,  # Simplified
                })

            # Arrow functions
            pattern = r'(\w+)\s*=\s*\(([^)]*)\)\s*=>'
            for match in re.finditer(pattern, code):
                name = match.group(1)
                params = match.group(2)
                param_count = len([p for p in params.split(",") if p.strip()])

                functions.append({
                    "name": name,
                    "return_type": "unknown",
                    "param_count": param_count,
                    "length": 5,
                })

        return functions

    def _extract_variable_declarations(self, code: str, language: str) -> List[Dict]:
        """Extract variable declarations from code."""
        variables = []

        if language in ("c", "cpp"):
            # Match variable declarations
            pattern = r'\b(int|char|float|double|long|short|unsigned|void)\s*(\*?)\s*(\w+)\s*(\[[^\]]*\])?\s*[;=]'
            for match in re.finditer(pattern, code):
                variables.append({
                    "type": match.group(1),
                    "name": match.group(3),
                    "is_pointer": bool(match.group(2)),
                    "is_array": bool(match.group(4)),
                })

        elif language == "python":
            # Python doesn't have explicit type declarations
            # Look for assignments
            pattern = r'^(\w+)\s*='
            for match in re.finditer(pattern, code, re.MULTILINE):
                variables.append({
                    "name": match.group(1),
                    "is_pointer": False,
                    "is_array": False,
                })

        elif language == "javascript":
            pattern = r'\b(var|let|const)\s+(\w+)'
            for match in re.finditer(pattern, code):
                variables.append({
                    "keyword": match.group(1),
                    "name": match.group(2),
                    "is_pointer": False,
                    "is_array": False,
                })

        return variables

    def _extract_control_structures(self, code: str, language: str) -> Dict[str, int]:
        """Extract control structure counts."""
        return {
            "if": len(re.findall(r'\bif\s*\(', code)),
            "for": len(re.findall(r'\bfor\s*\(', code)),
            "while": len(re.findall(r'\bwhile\s*\(', code)),
            "switch": len(re.findall(r'\bswitch\s*\(', code)),
            "try": len(re.findall(r'\btry\s*[{:]', code)),
            "catch": len(re.findall(r'\bcatch\s*[\(:]', code)),
        }

    def _extract_function_calls(self, code: str, language: str) -> List[Dict]:
        """Extract function call expressions."""
        calls = []

        # Match function calls: name(args)
        pattern = r'\b(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)'
        for match in re.finditer(pattern, code):
            name = match.group(1)
            args = match.group(2)

            # Skip keywords
            if name in ("if", "for", "while", "switch", "catch", "return"):
                continue

            arg_count = len([a for a in args.split(",") if a.strip()]) if args.strip() else 0

            calls.append({
                "name": name,
                "arg_count": arg_count,
            })

        return calls

    def _extract_operators(self, code: str) -> Dict[str, int]:
        """Extract operator counts."""
        return {
            "assignment": len(re.findall(r'(?<![=!<>])=(?!=)', code)),
            "comparison": len(re.findall(r'==|!=|<=|>=|<(?!=)|>(?!=)', code)),
            "arithmetic": len(re.findall(r'[+\-*/%](?!=)', code)),
            "logical": len(re.findall(r'&&|\|\||!(?!=)', code)),
            "bitwise": len(re.findall(r'&(?!&)|\|(?!\|)|\^|~|<<|>>', code)),
        }

    def _calculate_nesting_depth(self, code: str) -> int:
        """Calculate maximum nesting depth."""
        max_depth = 0
        current_depth = 0

        for char in code:
            if char == "{":
                current_depth += 1
                max_depth = max(max_depth, current_depth)
            elif char == "}":
                current_depth = max(0, current_depth - 1)

        return max_depth

    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return [
            "function_count", "avg_function_length", "max_function_length",
            "functions_with_params", "variable_count", "pointer_variable_count",
            "array_variable_count", "if_count", "for_count", "while_count",
            "switch_count", "try_count", "function_call_count",
            "unique_functions_called", "avg_call_args", "assignment_count",
            "comparison_count", "arithmetic_count", "logical_count",
            "bitwise_count", "max_nesting_depth", "statement_count", "block_count",
        ]

    def extract_batch(self, codes: List[str], language: str = "c") -> np.ndarray:
        """
        Extract features from multiple code samples.

        Args:
            codes: List of source code strings
            language: Programming language

        Returns:
            NumPy array of features
        """
        feature_names = self.get_feature_names()
        all_features = []

        for code in codes:
            features = self.extract_features(code, language)
            all_features.append([features.get(name, 0) for name in feature_names])

        return np.array(all_features, dtype=np.float32)
