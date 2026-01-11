#!/usr/bin/env python3
"""
Prediction CLI for vulnerability detection.

Usage:
    python scripts/predict.py --file vulnerable_code.c
    python scripts/predict.py --code "strcpy(dest, src);"
    python scripts/predict.py --dir ./source_files --output results.json
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Any

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.utils.logger import setup_logger
from src.features.pattern_detector import PatternDetector


def parse_args():
    parser = argparse.ArgumentParser(
        description="Predict vulnerabilities in source code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/predict.py --file vulnerable.c
    python scripts/predict.py --code "gets(buffer);"
    python scripts/predict.py --dir ./src --output results.json
        """
    )
    parser.add_argument(
        "--file",
        type=str,
        help="Path to source code file to analyze",
    )
    parser.add_argument(
        "--code",
        type=str,
        help="Inline code snippet to analyze",
    )
    parser.add_argument(
        "--dir",
        type=str,
        help="Directory to scan recursively",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Path to trained model (optional, uses pattern detection if not provided)",
    )
    parser.add_argument(
        "--language",
        type=str,
        default="auto",
        help="Programming language (c, cpp, python, javascript, java, auto)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output file for JSON results",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=0.5,
        help="Vulnerability threshold (0.0-1.0)",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output",
    )
    return parser.parse_args()


def load_model(model_path: str):
    """Load a trained model from disk."""
    if model_path is None:
        return None

    model_path = Path(model_path)

    if model_path.suffix == ".joblib":
        from src.models.baseline import BaselineModel
        model = BaselineModel()
        model.load(str(model_path))
        return model

    elif model_path.is_dir():
        if (model_path / "encoder").exists():
            from src.models.codebert_model import CodeBERTModel
            model = CodeBERTModel()
            model.load(str(model_path))
            return model
        elif (model_path / "ensemble_config.json").exists():
            from src.models.ensemble import EnsembleModel
            model = EnsembleModel()
            model.load(str(model_path))
            return model

    raise ValueError(f"Could not determine model type from path: {model_path}")


def analyze_code(
    code: str,
    language: str = "auto",
    model=None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """Analyze a single code sample."""
    detector = PatternDetector()

    result = {
        "vulnerable": False,
        "confidence": 0.0,
        "vulnerability_score": 0.0,
        "patterns": [],
        "recommendations": [],
    }

    # Pattern-based detection
    matches = detector.detect(code, language)
    result["vulnerability_score"] = detector.get_vulnerability_score(matches)
    result["patterns"] = [
        {
            "name": m.pattern_name,
            "type": m.vulnerability_type,
            "severity": m.severity,
            "line": m.line_number,
            "code": m.code_snippet[:100],
            "cwe": m.cwe_id,
            "description": m.description,
            "fix": m.fix_suggestion,
        }
        for m in matches
    ]

    # ML model prediction if available
    if model is not None:
        try:
            proba = model.predict_proba(code, language)
            if len(proba.shape) == 2:
                ml_score = float(proba[0, 1])
            else:
                ml_score = float(proba[0])
            result["ml_score"] = ml_score
            # Combine scores
            combined = 0.6 * ml_score + 0.4 * result["vulnerability_score"]
            result["vulnerability_score"] = combined
        except Exception as e:
            result["ml_error"] = str(e)

    # Final decision
    result["vulnerable"] = result["vulnerability_score"] > threshold
    result["confidence"] = abs(result["vulnerability_score"] - 0.5) * 2

    # Generate recommendations
    if result["vulnerable"]:
        result["recommendations"].append("Manual code review recommended")
        for pattern in result["patterns"]:
            if pattern["fix"]:
                result["recommendations"].append(
                    f"Line {pattern['line']}: {pattern['fix']}"
                )

    return result


def analyze_file(
    file_path: str,
    language: str = "auto",
    model=None,
    threshold: float = 0.5,
) -> Dict[str, Any]:
    """Analyze a source code file."""
    path = Path(file_path)

    if not path.exists():
        return {"error": f"File not found: {file_path}"}

    # Detect language from extension if auto
    if language == "auto":
        ext_map = {
            ".c": "c",
            ".h": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".cxx": "cpp",
            ".hpp": "cpp",
            ".py": "python",
            ".js": "javascript",
            ".ts": "javascript",
            ".java": "java",
        }
        language = ext_map.get(path.suffix.lower(), "c")

    try:
        code = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return {"error": f"Could not read file: {e}"}

    result = analyze_code(code, language, model, threshold)
    result["file"] = str(path)
    result["language"] = language
    result["lines"] = len(code.split("\n"))

    return result


def analyze_directory(
    dir_path: str,
    language: str = "auto",
    model=None,
    threshold: float = 0.5,
) -> List[Dict[str, Any]]:
    """Analyze all source files in a directory."""
    results = []
    path = Path(dir_path)

    # File extensions to scan
    extensions = {".c", ".h", ".cpp", ".cc", ".cxx", ".hpp", ".py", ".js", ".ts", ".java"}

    for file_path in path.rglob("*"):
        if file_path.is_file() and file_path.suffix.lower() in extensions:
            result = analyze_file(str(file_path), language, model, threshold)
            results.append(result)

    return results


def print_result(result: Dict[str, Any], verbose: bool = False):
    """Print analysis result to console."""
    if "error" in result:
        print(f"Error: {result['error']}")
        return

    # Header
    file_info = result.get("file", "inline code")
    status = "VULNERABLE" if result["vulnerable"] else "SAFE"
    status_color = "\033[91m" if result["vulnerable"] else "\033[92m"
    reset = "\033[0m"

    print(f"\n{'=' * 60}")
    print(f"File: {file_info}")
    print(f"Status: {status_color}{status}{reset}")
    print(f"Vulnerability Score: {result['vulnerability_score']:.2%}")
    print(f"Confidence: {result['confidence']:.2%}")

    if result.get("patterns"):
        print(f"\nDetected Patterns ({len(result['patterns'])}):")
        for p in result["patterns"]:
            severity_colors = {
                "CRITICAL": "\033[91m",
                "HIGH": "\033[93m",
                "MEDIUM": "\033[33m",
                "LOW": "\033[90m",
            }
            color = severity_colors.get(p["severity"], "")
            print(f"  [{color}{p['severity']}{reset}] Line {p['line']}: {p['name']}")
            if verbose:
                print(f"       Type: {p['type']}")
                print(f"       CWE: {p['cwe']}")
                print(f"       Code: {p['code'][:60]}...")
                print(f"       Description: {p['description']}")
                if p["fix"]:
                    print(f"       Fix: {p['fix']}")

    if result.get("recommendations"):
        print(f"\nRecommendations:")
        for rec in result["recommendations"][:5]:
            print(f"  - {rec}")

    print("=" * 60)


def print_summary(results: List[Dict[str, Any]]):
    """Print summary of multiple file analysis."""
    total = len(results)
    vulnerable = sum(1 for r in results if r.get("vulnerable", False))
    errors = sum(1 for r in results if "error" in r)

    print(f"\n{'=' * 60}")
    print("SCAN SUMMARY")
    print("=" * 60)
    print(f"Total files scanned: {total}")
    print(f"Vulnerable files: {vulnerable}")
    print(f"Safe files: {total - vulnerable - errors}")
    print(f"Errors: {errors}")

    if vulnerable > 0:
        print(f"\nVulnerable files:")
        for r in results:
            if r.get("vulnerable", False):
                print(f"  - {r.get('file', 'unknown')}: {r['vulnerability_score']:.2%}")

    # Count vulnerability types
    vuln_types = {}
    for r in results:
        for p in r.get("patterns", []):
            vuln_types[p["type"]] = vuln_types.get(p["type"], 0) + 1

    if vuln_types:
        print(f"\nVulnerability types found:")
        for vtype, count in sorted(vuln_types.items(), key=lambda x: -x[1]):
            print(f"  - {vtype}: {count}")

    print("=" * 60)


def main():
    args = parse_args()
    logger = setup_logger("predict", level="DEBUG" if args.verbose else "INFO")

    # Load model if specified
    model = None
    if args.model:
        try:
            model = load_model(args.model)
            logger.info(f"Loaded model from {args.model}")
        except Exception as e:
            logger.warning(f"Could not load model: {e}")
            logger.info("Proceeding with pattern-based detection only")

    results = []

    # Analyze based on input type
    if args.code:
        logger.info("Analyzing inline code...")
        result = analyze_code(args.code, args.language, model, args.threshold)
        results.append(result)
        print_result(result, args.verbose)

    elif args.file:
        logger.info(f"Analyzing file: {args.file}")
        result = analyze_file(args.file, args.language, model, args.threshold)
        results.append(result)
        print_result(result, args.verbose)

    elif args.dir:
        logger.info(f"Scanning directory: {args.dir}")
        results = analyze_directory(args.dir, args.language, model, args.threshold)
        for result in results:
            if result.get("vulnerable", False) or args.verbose:
                print_result(result, args.verbose)
        print_summary(results)

    else:
        print("Error: Must specify --file, --code, or --dir")
        sys.exit(1)

    # Save results if output specified
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        logger.info(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
