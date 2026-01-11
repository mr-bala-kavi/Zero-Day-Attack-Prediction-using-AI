"""Tests for feature extraction modules."""

import pytest
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.features.code_features import CodeFeatureExtractor
from src.features.ast_features import ASTFeatureExtractor
from src.features.pattern_detector import PatternDetector


class TestCodeFeatureExtractor:
    """Tests for CodeFeatureExtractor."""

    def setup_method(self):
        self.extractor = CodeFeatureExtractor()

    def test_extract_basic_metrics(self):
        code = """
int main() {
    int x = 5;
    return 0;
}
        """
        features = self.extractor.extract_features(code, "c")

        assert "total_lines" in features
        assert "cyclomatic_complexity" in features
        assert features["total_lines"] > 0

    def test_detect_language(self):
        c_code = "#include <stdio.h>\nint main() {}"
        py_code = "def hello():\n    print('hi')"
        js_code = "function hello() { console.log('hi'); }"

        assert self.extractor.detect_language(c_code) == "c"
        assert self.extractor.detect_language(py_code) == "python"
        assert self.extractor.detect_language(js_code) == "javascript"

    def test_dangerous_function_detection(self):
        vulnerable_code = """
void copy_data(char *input) {
    char buffer[100];
    strcpy(buffer, input);
    gets(buffer);
}
        """
        features = self.extractor.extract_features(vulnerable_code, "c")

        assert features.get("total_dangerous_calls", 0) > 0


class TestASTFeatureExtractor:
    """Tests for ASTFeatureExtractor."""

    def setup_method(self):
        self.extractor = ASTFeatureExtractor()

    def test_extract_function_definitions(self):
        code = """
int add(int a, int b) {
    return a + b;
}

void print_hello() {
    printf("Hello");
}
        """
        features = self.extractor.extract_features(code, "c")

        assert features["function_count"] == 2

    def test_extract_control_structures(self):
        code = """
void process(int x) {
    if (x > 0) {
        for (int i = 0; i < x; i++) {
            while (condition) {
                // do something
            }
        }
    }
}
        """
        features = self.extractor.extract_features(code, "c")

        assert features["if_count"] == 1
        assert features["for_count"] == 1
        assert features["while_count"] == 1


class TestPatternDetector:
    """Tests for PatternDetector."""

    def setup_method(self):
        self.detector = PatternDetector()

    def test_detect_buffer_overflow(self):
        code = """
void vulnerable(char *input) {
    char buf[64];
    strcpy(buf, input);
}
        """
        matches = self.detector.detect(code, "c")

        assert len(matches) > 0
        assert any(m.vulnerability_type == "buffer_overflow" for m in matches)

    def test_detect_sql_injection(self):
        code = """
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
        """
        matches = self.detector.detect(code, "python")

        assert len(matches) > 0
        assert any(m.vulnerability_type == "sql_injection" for m in matches)

    def test_detect_xss(self):
        code = """
function display(input) {
    document.getElementById('output').innerHTML = input;
}
        """
        matches = self.detector.detect(code, "javascript")

        assert len(matches) > 0
        assert any(m.vulnerability_type == "xss" for m in matches)

    def test_safe_code_no_matches(self):
        code = """
def get_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchone()
        """
        matches = self.detector.detect(code, "python")

        # Should have no SQL injection matches
        sql_matches = [m for m in matches if m.vulnerability_type == "sql_injection"]
        assert len(sql_matches) == 0

    def test_vulnerability_score(self):
        vulnerable_code = """
void func() {
    gets(buffer);
    strcpy(dest, src);
    system(user_input);
}
        """
        matches = self.detector.detect(vulnerable_code, "c")
        score = self.detector.get_vulnerability_score(matches)

        assert 0 <= score <= 1
        assert score > 0.5  # Should be high for this code

    def test_generate_report(self):
        code = "gets(buffer);"
        matches = self.detector.detect(code, "c")
        report = self.detector.generate_report(matches)

        assert "VULNERABILITY SCAN REPORT" in report
        assert "gets" in report.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
