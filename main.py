#!/usr/bin/env python3
"""
Zero-Day Vulnerability Prediction System

Main entry point for the vulnerability prediction CLI.

Usage:
    python main.py scan --file code.c
    python main.py scan --dir ./src
    python main.py train --model baseline
    python main.py evaluate --model data/models/baseline_model.joblib
"""

import argparse
import sys
from pathlib import Path

from src.utils.logger import setup_logger


def create_parser():
    parser = argparse.ArgumentParser(
        description="Zero-Day Vulnerability Prediction System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Scan a file for vulnerabilities
    python main.py scan --file vulnerable.c

    # Scan a directory
    python main.py scan --dir ./source_code --output results.json

    # Train a model
    python main.py train --model baseline --samples 500

    # Evaluate a model
    python main.py evaluate --model data/models/baseline_model.joblib

    # Quick demo
    python main.py demo
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan code for vulnerabilities")
    scan_parser.add_argument("--file", type=str, help="File to scan")
    scan_parser.add_argument("--dir", type=str, help="Directory to scan")
    scan_parser.add_argument("--code", type=str, help="Inline code to scan")
    scan_parser.add_argument("--model", type=str, help="Path to trained model")
    scan_parser.add_argument("--language", type=str, default="auto", help="Programming language")
    scan_parser.add_argument("--output", type=str, help="Output JSON file")
    scan_parser.add_argument("--threshold", type=float, default=0.5, help="Detection threshold")
    scan_parser.add_argument("--verbose", action="store_true", help="Verbose output")

    # Train command
    train_parser = subparsers.add_parser("train", help="Train a vulnerability detection model")
    train_parser.add_argument(
        "--model",
        type=str,
        choices=["baseline", "codebert", "ensemble"],
        default="baseline",
        help="Model type",
    )
    train_parser.add_argument("--data", type=str, help="Training data CSV")
    train_parser.add_argument("--output", type=str, default="data/models", help="Output directory")
    train_parser.add_argument("--samples", type=int, default=500, help="Synthetic samples per type")
    train_parser.add_argument("--epochs", type=int, default=10, help="Training epochs")

    # Evaluate command
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate a trained model")
    eval_parser.add_argument("--model", type=str, required=True, help="Model path")
    eval_parser.add_argument("--data", type=str, help="Test data CSV")
    eval_parser.add_argument("--output", type=str, default="evaluation.json", help="Output file")
    eval_parser.add_argument("--threshold", type=float, default=0.5, help="Classification threshold")

    # Demo command
    demo_parser = subparsers.add_parser("demo", help="Run a quick demonstration")

    return parser


def run_scan(args):
    """Run vulnerability scanning."""
    from scripts.predict import analyze_code, analyze_file, analyze_directory, print_result, print_summary
    import json

    model = None
    if args.model:
        from scripts.predict import load_model
        model = load_model(args.model)

    results = []

    if args.code:
        result = analyze_code(args.code, args.language, model, args.threshold)
        results.append(result)
        print_result(result, args.verbose)

    elif args.file:
        result = analyze_file(args.file, args.language, model, args.threshold)
        results.append(result)
        print_result(result, args.verbose)

    elif args.dir:
        results = analyze_directory(args.dir, args.language, model, args.threshold)
        for result in results:
            if result.get("vulnerable", False) or args.verbose:
                print_result(result, args.verbose)
        print_summary(results)

    else:
        print("Error: Must specify --file, --code, or --dir")
        return 1

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to {args.output}")

    return 0


def run_train(args):
    """Run model training."""
    import subprocess
    cmd = [
        sys.executable, "scripts/train.py",
        "--model", args.model,
        "--output", args.output,
        "--samples", str(args.samples),
        "--epochs", str(args.epochs),
    ]
    if args.data:
        cmd.extend(["--data", args.data])

    return subprocess.call(cmd)


def run_evaluate(args):
    """Run model evaluation."""
    import subprocess
    cmd = [
        sys.executable, "scripts/evaluate.py",
        "--model", args.model,
        "--output", args.output,
        "--threshold", str(args.threshold),
    ]
    if args.data:
        cmd.extend(["--data", args.data])

    return subprocess.call(cmd)


def run_demo():
    """Run a quick demonstration."""
    print("\n" + "=" * 60)
    print("Zero-Day Vulnerability Prediction System - Demo")
    print("=" * 60)

    from src.features.pattern_detector import PatternDetector
    from src.features.code_features import CodeFeatureExtractor

    detector = PatternDetector()
    extractor = CodeFeatureExtractor()

    # Demo vulnerable code samples
    samples = [
        {
            "name": "Buffer Overflow (C)",
            "language": "c",
            "code": """
void process_input(char *user_input) {
    char buffer[64];
    strcpy(buffer, user_input);  // Vulnerable!
    printf(buffer);              // Format string vulnerability!
}
            """,
        },
        {
            "name": "SQL Injection (Python)",
            "language": "python",
            "code": """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)  # SQL Injection!
    return cursor.fetchone()
            """,
        },
        {
            "name": "XSS (JavaScript)",
            "language": "javascript",
            "code": """
function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;  // XSS!
    eval(userInput);  // Code injection!
}
            """,
        },
        {
            "name": "Safe Code (Python)",
            "language": "python",
            "code": """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = ?"
    cursor.execute(query, (user_id,))  # Safe parameterized query
    return cursor.fetchone()
            """,
        },
    ]

    for sample in samples:
        print(f"\n{'-' * 60}")
        print(f"Sample: {sample['name']}")
        print(f"Language: {sample['language']}")
        print(f"{'-' * 60}")
        print(f"Code:{sample['code']}")

        # Detect patterns
        matches = detector.detect(sample["code"], sample["language"])
        score = detector.get_vulnerability_score(matches)

        if matches:
            print(f"\n[!] VULNERABILITIES DETECTED (Score: {score:.2%})")
            for m in matches:
                print(f"  [{m.severity}] {m.pattern_name}")
                print(f"    Line {m.line_number}: {m.description}")
                if m.fix_suggestion:
                    print(f"    Fix: {m.fix_suggestion}")
        else:
            print(f"\n[OK] No vulnerabilities detected (Score: {score:.2%})")

    print("\n" + "=" * 60)
    print("Demo Complete!")
    print("=" * 60)
    print("\nNext steps:")
    print("  1. Train a model: python main.py train --model baseline")
    print("  2. Scan your code: python main.py scan --file your_code.c")
    print("  3. Scan a directory: python main.py scan --dir ./src")
    print()

    return 0


def main():
    parser = create_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return 1

    logger = setup_logger("main", level="INFO")

    if args.command == "scan":
        return run_scan(args)
    elif args.command == "train":
        return run_train(args)
    elif args.command == "evaluate":
        return run_evaluate(args)
    elif args.command == "demo":
        return run_demo()
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
