"""
PII Detection Accuracy Benchmarks — EU AI Act Art. 15
=====================================================
Measure detection accuracy against a benchmark dataset with known labels.

Key metrics:
  - True Positive Rate (TPR / Recall): PII correctly detected
  - True Negative Rate (TNR / Specificity): Non-PII correctly passed
  - False Positive Rate (FPR): Non-PII incorrectly flagged
  - False Negative Rate (FNR): PII MISSED — the critical safety metric

Target: FNR < 5% for BLOCK categories (ID cards, bank accounts)
Target: FNR < 10% for MASK categories (names, phones, emails)
"""

from __future__ import annotations

from dataclasses import dataclass

import polars as pl
import pytest

from venus_pii import detect, sanitize
from venus_pii.guard import PIICategory, PIILevel


# ============================================================
#  Benchmark Dataset
# ============================================================

@dataclass
class BenchmarkColumn:
    """A column with known ground-truth PII classification."""
    name: str
    values: list
    expected_category: PIICategory
    expected_level: PIILevel
    description: str


BENCHMARK_COLUMNS = [
    # ---- TRUE PII: Names ----
    BenchmarkColumn("姓名", ["张三", "李四", "王五"], PIICategory.NAME, PIILevel.MASK, "Chinese name column"),
    BenchmarkColumn("name", ["Alice", "Bob", "Carol"], PIICategory.NAME, PIILevel.MASK, "English name column"),
    BenchmarkColumn("student_name", ["张小明", "李大伟"], PIICategory.NAME, PIILevel.MASK, "Student name variant"),
    BenchmarkColumn("员工姓名", ["赵六", "钱七"], PIICategory.NAME, PIILevel.MASK, "Employee name column"),
    BenchmarkColumn("fullname", ["John Doe", "Jane Smith"], PIICategory.NAME, PIILevel.MASK, "Full name variant"),
    BenchmarkColumn("教师姓名", ["孙老师", "周老师"], PIICategory.NAME, PIILevel.MASK, "Teacher name variant"),
    BenchmarkColumn("first_name", ["Alice", "Bob"], PIICategory.NAME, PIILevel.MASK, "First name column"),
    BenchmarkColumn("last_name", ["Chen", "Li"], PIICategory.NAME, PIILevel.MASK, "Last name column"),

    # ---- TRUE PII: Phone ----
    BenchmarkColumn("phone", ["13800138000", "13900139000"], PIICategory.PHONE, PIILevel.MASK, "Phone column"),
    BenchmarkColumn("电话", ["13800138001", "13900139001"], PIICategory.PHONE, PIILevel.MASK, "Chinese phone column"),
    BenchmarkColumn("mobile", ["13700137000", "13600136000"], PIICategory.PHONE, PIILevel.MASK, "Mobile variant"),
    BenchmarkColumn("联系方式", ["13500135000", "13400134000"], PIICategory.PHONE, PIILevel.MASK, "Contact method column"),
    BenchmarkColumn("手机", ["13300133000", "13200132000"], PIICategory.PHONE, PIILevel.MASK, "Cell phone column"),
    BenchmarkColumn("tel", ["13100131000", "13000130000"], PIICategory.PHONE, PIILevel.MASK, "Tel column"),

    # ---- TRUE PII: ID Card (BLOCK) ----
    BenchmarkColumn("身份证号", ["110101200001011234", "110101200002021234"], PIICategory.ID_CARD, PIILevel.BLOCK, "ID card column"),
    BenchmarkColumn("idcard", ["110101200003031234", "110101200004041234"], PIICategory.ID_CARD, PIILevel.BLOCK, "ID card English"),
    BenchmarkColumn("id_card", ["110101200005051234", "110101200006061234"], PIICategory.ID_CARD, PIILevel.BLOCK, "ID card underscore"),
    BenchmarkColumn("证件号", ["110101200007071234", "110101200008081234"], PIICategory.ID_CARD, PIILevel.BLOCK, "Certificate number"),
    BenchmarkColumn("ssn", ["110101200009091234", "11010120001010123X"], PIICategory.ID_CARD, PIILevel.BLOCK, "SSN column"),

    # ---- TRUE PII: Email ----
    BenchmarkColumn("邮箱", ["a@b.com", "c@d.com"], PIICategory.EMAIL, PIILevel.MASK, "Chinese email column"),
    BenchmarkColumn("email", ["x@y.com", "p@q.com"], PIICategory.EMAIL, PIILevel.MASK, "English email column"),
    BenchmarkColumn("e-mail", ["test@test.com", "foo@bar.com"], PIICategory.EMAIL, PIILevel.MASK, "E-mail variant"),

    # ---- TRUE PII: Address ----
    BenchmarkColumn("地址", ["北京市朝阳区", "上海市浦东新区"], PIICategory.ADDRESS, PIILevel.MASK, "Chinese address"),
    BenchmarkColumn("address", ["123 Main St", "456 Oak Ave"], PIICategory.ADDRESS, PIILevel.MASK, "English address"),
    BenchmarkColumn("住址", ["广州市天河区", "深圳市南山区"], PIICategory.ADDRESS, PIILevel.MASK, "Residence address"),

    # ---- TRUE PII: Salary ----
    BenchmarkColumn("salary", [8500, 25000, 45000], PIICategory.SALARY, PIILevel.MASK, "Salary column"),
    BenchmarkColumn("工资", [5000, 12000], PIICategory.SALARY, PIILevel.MASK, "Chinese salary"),
    BenchmarkColumn("income", [30000, 60000], PIICategory.SALARY, PIILevel.MASK, "Income column"),
    BenchmarkColumn("compensation", [8000, 15000], PIICategory.SALARY, PIILevel.MASK, "Compensation column"),

    # ---- TRUE PII: Bank Account (BLOCK) ----
    BenchmarkColumn("bank_account", ["6222021234567890", "6222029876543210"], PIICategory.BANK_ACCOUNT, PIILevel.BLOCK, "Bank account"),
    BenchmarkColumn("银行卡号", ["6217001234567890", "6217009876543210"], PIICategory.BANK_ACCOUNT, PIILevel.BLOCK, "Chinese bank card"),
    BenchmarkColumn("account", ["ACC001", "ACC002"], PIICategory.BANK_ACCOUNT, PIILevel.BLOCK, "Account column"),

    # ---- TRUE NEGATIVES: Non-PII ----
    BenchmarkColumn("score", [85, 92, 78], PIICategory.NONE, PIILevel.PASS, "Numeric score"),
    BenchmarkColumn("成绩", [90, 88, 95], PIICategory.NONE, PIILevel.PASS, "Chinese score"),
    BenchmarkColumn("department", ["Engineering", "Marketing"], PIICategory.NONE, PIILevel.PASS, "Department name"),
    BenchmarkColumn("class_id", ["A01", "B02", "C03"], PIICategory.NONE, PIILevel.PASS, "Class identifier"),
    BenchmarkColumn("date", ["2024-01-01", "2024-02-01"], PIICategory.NONE, PIILevel.PASS, "Date column"),
    BenchmarkColumn("status", ["active", "inactive"], PIICategory.NONE, PIILevel.PASS, "Status flag"),
    BenchmarkColumn("count", [1, 2, 3, 4, 5], PIICategory.NONE, PIILevel.PASS, "Count column"),
    BenchmarkColumn("ratio", [0.5, 0.8, 0.3], PIICategory.NONE, PIILevel.PASS, "Ratio column"),
    BenchmarkColumn("description", ["good", "average", "excellent"], PIICategory.NONE, PIILevel.PASS, "Text description"),
    BenchmarkColumn("product_code", ["SKU001", "SKU002"], PIICategory.NONE, PIILevel.PASS, "Product code"),
    BenchmarkColumn("quantity", [10, 20, 30], PIICategory.NONE, PIILevel.PASS, "Quantity"),
    BenchmarkColumn("is_valid", [True, False, True], PIICategory.NONE, PIILevel.PASS, "Boolean flag"),
]


# ============================================================
#  Accuracy Measurement
# ============================================================

@dataclass
class AccuracyResult:
    total: int = 0
    true_positives: int = 0   # PII correctly detected
    true_negatives: int = 0   # Non-PII correctly passed
    false_positives: int = 0  # Non-PII incorrectly flagged as PII
    false_negatives: int = 0  # PII MISSED (critical failure)

    @property
    def tpr(self) -> float:
        """True positive rate (recall/sensitivity)."""
        denom = self.true_positives + self.false_negatives
        return self.true_positives / denom if denom > 0 else 1.0

    @property
    def tnr(self) -> float:
        """True negative rate (specificity)."""
        denom = self.true_negatives + self.false_positives
        return self.true_negatives / denom if denom > 0 else 1.0

    @property
    def fpr(self) -> float:
        """False positive rate."""
        return 1 - self.tnr

    @property
    def fnr(self) -> float:
        """False negative rate — the CRITICAL safety metric."""
        return 1 - self.tpr

    @property
    def accuracy(self) -> float:
        return (self.true_positives + self.true_negatives) / self.total if self.total > 0 else 0.0


def measure_accuracy(columns: list[BenchmarkColumn]) -> AccuracyResult:
    """Run detection on each benchmark column and compare to ground truth."""
    result = AccuracyResult()

    for col in columns:
        # Build a single-column DataFrame
        df = pl.DataFrame({col.name: col.values})
        reports = detect(df)

        assert len(reports) == 1
        detected = reports[0]

        is_pii = col.expected_category != PIICategory.NONE
        detected_pii = detected.category != PIICategory.NONE

        result.total += 1

        if is_pii and detected_pii:
            result.true_positives += 1
        elif not is_pii and not detected_pii:
            result.true_negatives += 1
        elif not is_pii and detected_pii:
            result.false_positives += 1
        elif is_pii and not detected_pii:
            result.false_negatives += 1

    return result


# ============================================================
#  Tests
# ============================================================

class TestOverallAccuracy:
    """Overall accuracy across all benchmark columns."""

    def test_overall_accuracy_above_90_percent(self):
        result = measure_accuracy(BENCHMARK_COLUMNS)
        print(f"\nOverall Accuracy Report:")
        print(f"  Total columns: {result.total}")
        print(f"  True positives:  {result.true_positives}")
        print(f"  True negatives:  {result.true_negatives}")
        print(f"  False positives: {result.false_positives}")
        print(f"  False negatives: {result.false_negatives}")
        print(f"  Accuracy: {result.accuracy:.1%}")
        print(f"  TPR (recall): {result.tpr:.1%}")
        print(f"  TNR (specificity): {result.tnr:.1%}")
        print(f"  FPR: {result.fpr:.1%}")
        print(f"  FNR: {result.fnr:.1%}")

        assert result.accuracy >= 0.90, (
            f"Overall accuracy {result.accuracy:.1%} below 90%"
        )

    def test_false_negative_rate_below_10_percent(self):
        result = measure_accuracy(BENCHMARK_COLUMNS)
        assert result.fnr <= 0.10, (
            f"FNR {result.fnr:.1%} exceeds 10% — PII being missed"
        )


class TestBlockCategoryAccuracy:
    """BLOCK categories (ID card, bank account) must have near-zero FNR."""

    def test_id_card_detection_100_percent(self):
        """ID cards must ALWAYS be detected — zero tolerance for misses."""
        id_columns = [c for c in BENCHMARK_COLUMNS
                      if c.expected_category == PIICategory.ID_CARD]
        result = measure_accuracy(id_columns)
        print(f"\nID Card Detection: {result.true_positives}/{result.total} detected")
        assert result.fnr == 0.0, (
            f"ID card FNR = {result.fnr:.1%} — CRITICAL: ID cards must never be missed"
        )

    def test_bank_account_detection_100_percent(self):
        """Bank accounts must ALWAYS be detected — zero tolerance."""
        bank_columns = [c for c in BENCHMARK_COLUMNS
                        if c.expected_category == PIICategory.BANK_ACCOUNT]
        result = measure_accuracy(bank_columns)
        print(f"\nBank Account Detection: {result.true_positives}/{result.total} detected")
        assert result.fnr == 0.0, (
            f"Bank account FNR = {result.fnr:.1%} — CRITICAL: bank accounts must never be missed"
        )

    def test_block_level_always_applied(self):
        """Detected BLOCK categories must always get BLOCK level, never MASK."""
        block_columns = [c for c in BENCHMARK_COLUMNS
                         if c.expected_level == PIILevel.BLOCK]
        for col in block_columns:
            df = pl.DataFrame({col.name: col.values})
            reports = detect(df)
            for r in reports:
                if r.category in (PIICategory.ID_CARD, PIICategory.BANK_ACCOUNT):
                    assert r.level == PIILevel.BLOCK, (
                        f"Column '{col.name}' ({r.category}) got {r.level} instead of BLOCK"
                    )


class TestMaskCategoryAccuracy:
    """MASK categories should have FNR < 10%."""

    def test_name_detection(self):
        name_columns = [c for c in BENCHMARK_COLUMNS
                        if c.expected_category == PIICategory.NAME]
        result = measure_accuracy(name_columns)
        print(f"\nName Detection: {result.true_positives}/{result.total}")
        assert result.fnr < 0.10, f"Name FNR = {result.fnr:.1%}"

    def test_phone_detection(self):
        phone_columns = [c for c in BENCHMARK_COLUMNS
                         if c.expected_category == PIICategory.PHONE]
        result = measure_accuracy(phone_columns)
        print(f"\nPhone Detection: {result.true_positives}/{result.total}")
        assert result.fnr < 0.10, f"Phone FNR = {result.fnr:.1%}"

    def test_email_detection(self):
        email_columns = [c for c in BENCHMARK_COLUMNS
                         if c.expected_category == PIICategory.EMAIL]
        result = measure_accuracy(email_columns)
        print(f"\nEmail Detection: {result.true_positives}/{result.total}")
        assert result.fnr < 0.10, f"Email FNR = {result.fnr:.1%}"

    def test_address_detection(self):
        addr_columns = [c for c in BENCHMARK_COLUMNS
                        if c.expected_category == PIICategory.ADDRESS]
        result = measure_accuracy(addr_columns)
        print(f"\nAddress Detection: {result.true_positives}/{result.total}")
        assert result.fnr < 0.10, f"Address FNR = {result.fnr:.1%}"

    def test_salary_detection(self):
        salary_columns = [c for c in BENCHMARK_COLUMNS
                          if c.expected_category == PIICategory.SALARY]
        result = measure_accuracy(salary_columns)
        print(f"\nSalary Detection: {result.true_positives}/{result.total}")
        assert result.fnr < 0.10, f"Salary FNR = {result.fnr:.1%}"


class TestTrueNegatives:
    """Non-PII columns should NOT be flagged."""

    def test_non_pii_not_flagged(self):
        """Non-PII columns should be correctly passed through."""
        non_pii = [c for c in BENCHMARK_COLUMNS
                   if c.expected_category == PIICategory.NONE]
        result = measure_accuracy(non_pii)
        print(f"\nTrue Negative Rate: {result.true_negatives}/{result.total}")
        assert result.fpr < 0.10, (
            f"FPR = {result.fpr:.1%} — too many false positives"
        )

    def test_numeric_columns_always_pass(self):
        """Pure numeric columns should never be flagged as PII
        (unless the column name suggests salary/income)."""
        df = pl.DataFrame({
            "score": [85, 92, 78],
            "count": [1, 2, 3],
            "ratio": [0.5, 0.8, 0.3],
        })
        reports = detect(df)
        for r in reports:
            assert r.level == PIILevel.PASS, (
                f"Numeric column '{r.column_name}' incorrectly flagged as {r.level}"
            )


class TestConfidenceScores:
    """Confidence scores should reflect detection method reliability."""

    def test_column_name_match_high_confidence(self):
        """Column name pattern matches should have confidence >= 0.8."""
        df = pl.DataFrame({"姓名": ["张三"], "phone": ["13800138000"]})
        reports = detect(df)
        for r in reports:
            if r.category != PIICategory.NONE:
                assert r.confidence >= 0.8, (
                    f"Column '{r.column_name}' confidence {r.confidence} too low for name match"
                )

    def test_value_pattern_match_medium_confidence(self):
        """Value-based detection (no column name match) should have
        confidence >= 0.5 but potentially lower than name-based."""
        # Use a generic column name but PII values
        df = pl.DataFrame({"col_x": ["110101200001011234", "110101200002021234"]})
        reports = detect(df)
        for r in reports:
            if r.category != PIICategory.NONE:
                assert r.confidence >= 0.5, (
                    f"Value-detected PII confidence {r.confidence} too low"
                )

    def test_non_pii_zero_confidence(self):
        """Non-PII columns should have zero confidence."""
        df = pl.DataFrame({"score": [85, 92]})
        reports = detect(df)
        for r in reports:
            if r.category == PIICategory.NONE:
                assert r.confidence == 0.0
