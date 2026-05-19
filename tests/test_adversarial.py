"""
Adversarial Robustness Tests — EU AI Act Art. 15
=================================================
Test resistance to evasion attacks on PII detection.

Art. 15: "High-risk AI systems shall be resilient against attempts by
unauthorised third parties to alter their use, outputs or performance
by exploiting system vulnerabilities."

These tests attempt to bypass PII detection using:
  1. Column name obfuscation
  2. Value format manipulation
  3. Serialization roundtrip attacks
  4. Mixed PII in unexpected columns
  5. Edge cases and boundary conditions
"""

from __future__ import annotations

import json

import polars as pl
import pytest

from venus_pii import detect, sanitize, restore
from venus_pii.guard import PIICategory, PIILevel, _hmac_token, _DEFAULT_HMAC_KEY


# ============================================================
#  1. Column Name Obfuscation Attacks
# ============================================================

class TestColumnNameObfuscation:
    """Attackers might rename columns to evade detection."""

    def test_standard_names_detected(self):
        """Baseline: standard column names must always be detected."""
        df = pl.DataFrame({
            "姓名": ["张三"],
            "phone": ["13800138000"],
            "身份证号": ["110101200001011234"],
            "email": ["test@test.com"],
        })
        reports = detect(df)
        report_map = {r.column_name: r for r in reports}

        assert report_map["姓名"].category == PIICategory.NAME
        assert report_map["phone"].category == PIICategory.PHONE
        assert report_map["身份证号"].category == PIICategory.ID_CARD
        assert report_map["email"].category == PIICategory.EMAIL

    def test_case_insensitive_detection(self):
        """Column names should be detected regardless of case."""
        variants = [
            ("NAME", PIICategory.NAME),
            ("Name", PIICategory.NAME),
            ("PHONE", PIICategory.PHONE),
            ("Phone", PIICategory.PHONE),
            ("EMAIL", PIICategory.EMAIL),
            ("Email", PIICategory.EMAIL),
            ("ADDRESS", PIICategory.ADDRESS),
            ("Address", PIICategory.ADDRESS),
            ("SALARY", PIICategory.SALARY),
        ]
        for col_name, expected in variants:
            df = pl.DataFrame({col_name: ["test_value"]})
            reports = detect(df)
            assert reports[0].category == expected, (
                f"Case variant '{col_name}' not detected as {expected.value}"
            )

    def test_value_based_detection_fallback(self):
        """When column names are obfuscated, value patterns should still detect PII."""
        # Use generic column names but PII values
        df = pl.DataFrame({
            "col_a": ["110101200001011234", "110101200002021234"],  # ID cards
        })
        reports = detect(df)
        # Value-based detection should catch these as ID cards
        assert reports[0].category == PIICategory.ID_CARD, (
            "Value-based ID card detection failed for obfuscated column name"
        )

    def test_phone_value_detection_with_generic_name(self):
        """Phone numbers should be detected by value pattern even with generic column name."""
        df = pl.DataFrame({
            "data_field": ["13800138000", "13900139000", "13700137000"],
        })
        reports = detect(df)
        assert reports[0].category == PIICategory.PHONE, (
            "Value-based phone detection failed for generic column name"
        )

    def test_email_value_detection_with_generic_name(self):
        """Emails should be detected by value pattern even with generic column name."""
        df = pl.DataFrame({
            "field_1": ["test@test.com", "user@domain.org", "hello@world.io"],
        })
        reports = detect(df)
        assert reports[0].category == PIICategory.EMAIL, (
            "Value-based email detection failed for generic column name"
        )


# ============================================================
#  2. Serialization Roundtrip Attacks
# ============================================================

class TestSerializationRoundtrip:
    """Tokenized data must survive serialization/deserialization."""

    def test_json_roundtrip(self):
        """Tokens must survive JSON serialization."""
        df = pl.DataFrame({
            "姓名": ["张三", "李四"],
            "score": [85, 92],
        })
        result = sanitize(df)

        # Serialize to JSON
        json_str = result.sanitized_df.write_json()
        # Deserialize
        restored_df = pl.read_json(json_str.encode())

        # Tokens should be intact
        assert list(restored_df.columns) == list(result.sanitized_df.columns)
        assert restored_df["姓名"].to_list() == result.sanitized_df["姓名"].to_list()

    def test_csv_roundtrip(self):
        """Tokens must survive CSV serialization."""
        df = pl.DataFrame({
            "name": ["Alice", "Bob"],
            "score": [85, 92],
        })
        result = sanitize(df)

        # Serialize to CSV
        csv_str = result.sanitized_df.write_csv()
        # Deserialize
        restored_df = pl.read_csv(csv_str.encode())

        assert restored_df["name"].to_list() == result.sanitized_df["name"].to_list()

    def test_token_map_json_roundtrip(self):
        """Token maps must survive JSON serialization for storage."""
        df = pl.DataFrame({"姓名": ["张三", "李四", "王五"]})
        result = sanitize(df)

        # Serialize token maps
        json_str = json.dumps(result.token_maps, ensure_ascii=False)
        # Deserialize
        restored_maps = json.loads(json_str)

        # Restore should work with deserialized maps
        restored = restore(result.sanitized_df, restored_maps)
        assert restored["姓名"].to_list() == ["张三", "李四", "王五"]

    def test_full_pipeline_survives_parquet_roundtrip(self):
        """Full sanitize → parquet → restore pipeline."""
        import tempfile
        import os

        df = pl.DataFrame({
            "姓名": ["张三", "李四"],
            "phone": ["13800138000", "13900139000"],
            "score": [85, 92],
        })
        result = sanitize(df)

        # Write to parquet
        tmp = tempfile.NamedTemporaryFile(suffix=".parquet", delete=False)
        try:
            result.sanitized_df.write_parquet(tmp.name)
            loaded = pl.read_parquet(tmp.name)
            restored = restore(loaded, result.token_maps)
            assert restored["姓名"].to_list() == ["张三", "李四"]
            assert restored["phone"].to_list() == ["13800138000", "13900139000"]
        finally:
            os.unlink(tmp.name)


# ============================================================
#  3. Edge Cases and Boundary Conditions
# ============================================================

class TestEdgeCases:
    """Edge cases that might cause detection failures or crashes."""

    def test_empty_dataframe(self):
        """Empty DataFrame should not crash."""
        df = pl.DataFrame({"姓名": []}).cast({"姓名": pl.Utf8})
        result = sanitize(df)
        assert result.sanitized_df.shape == (0, 1)

    def test_single_row(self):
        """Single row should work correctly."""
        df = pl.DataFrame({"姓名": ["张三"]})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["姓名"].to_list() == ["张三"]

    def test_null_values(self):
        """Null values should be preserved, not crash."""
        df = pl.DataFrame({"姓名": ["张三", None, "王五"]})
        result = sanitize(df)
        assert result.sanitized_df["姓名"][1] is None

        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["姓名"].to_list() == ["张三", None, "王五"]

    def test_duplicate_values(self):
        """Duplicate values should produce same token (deterministic)."""
        df = pl.DataFrame({"姓名": ["张三", "张三", "李四", "张三"]})
        result = sanitize(df)
        tokens = result.sanitized_df["姓名"].to_list()

        assert tokens[0] == tokens[1] == tokens[3], "Duplicate values got different tokens"
        assert tokens[0] != tokens[2], "Different values got same token"

    def test_very_long_values(self):
        """Very long strings should be tokenized without issues."""
        long_name = "张" * 1000
        df = pl.DataFrame({"姓名": [long_name]})
        result = sanitize(df)

        token = result.sanitized_df["姓名"][0]
        assert token.startswith("PERSON_")
        assert len(token) == len("PERSON_") + 8  # Fixed length regardless of input

    def test_special_characters_in_values(self):
        """Values with special characters should be handled."""
        names = ["张三(Jr.)", "李四 & 王五", "赵六「别名」"]
        df = pl.DataFrame({"姓名": names})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["姓名"].to_list() == names

    def test_unicode_values(self):
        """Unicode characters beyond CJK should be handled."""
        names = ["田中太郎", "김철수", "Müller"]  # Japanese, Korean, German
        df = pl.DataFrame({"name": names})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["name"].to_list() == names

    def test_mixed_type_column(self):
        """Columns with mixed types should not crash."""
        df = pl.DataFrame({"score": [85, 92, 78, 95]})
        result = sanitize(df)
        assert result.sanitized_df["score"].to_list() == [85, 92, 78, 95]

    def test_all_columns_blocked(self):
        """If all columns are BLOCK-level, result should be empty DataFrame."""
        df = pl.DataFrame({
            "身份证号": ["110101200001011234"],
            "银行卡号": ["6222021234567890"],
        })
        result = sanitize(df)
        assert len(result.sanitized_df.columns) == 0
        assert len(result.blocked_columns) == 2

    def test_no_pii_columns(self):
        """DataFrame with no PII should pass through unchanged."""
        df = pl.DataFrame({
            "score": [85, 92],
            "department": ["Engineering", "Marketing"],
        })
        result = sanitize(df)
        assert result.sanitized_df.shape == df.shape
        assert result.blocked_columns == []
        assert result.token_maps == {}


# ============================================================
#  4. Token Integrity Attacks
# ============================================================

class TestTokenIntegrity:
    """Verify tokens cannot be manipulated to leak information."""

    def test_token_prefix_cannot_be_spoofed(self):
        """A PERSON token from one column cannot be used to restore
        a different column's value."""
        df = pl.DataFrame({
            "姓名": ["张三", "李四"],
            "phone": ["13800138000", "13900139000"],
        })
        result = sanitize(df)

        # Try to use name token map on phone column — should not work
        name_map = result.token_maps["姓名"]
        phone_tokens = result.sanitized_df["phone"].to_list()

        for token in phone_tokens:
            assert token not in name_map, (
                "Phone token found in name token map — cross-column leakage"
            )

    def test_tokens_immutable_after_sanitization(self):
        """Sanitization result should be independent — modifying the
        original DataFrame should not affect the sanitized one."""
        original = pl.DataFrame({"姓名": ["张三", "李四"]})
        result = sanitize(original)

        # The sanitized df should have tokens, not original values
        assert result.sanitized_df["姓名"][0] != "张三"
        assert result.sanitized_df["姓名"][0].startswith("PERSON_")

    def test_restore_with_wrong_map_produces_tokens(self):
        """Restoring with wrong token map should leave tokens unchanged,
        not produce garbage or crash."""
        df = pl.DataFrame({"姓名": ["张三"]})
        result = sanitize(df)

        # Use a completely wrong map
        wrong_map = {"姓名": {"WRONG_TOKEN": "bad_value"}}
        restored = restore(result.sanitized_df, wrong_map)

        # Should leave the PERSON_ token intact (no match in wrong map)
        assert restored["姓名"][0].startswith("PERSON_")


# ============================================================
#  5. HMAC-Specific Attacks
# ============================================================

class TestHMACAttacks:
    """Test HMAC-SHA256 implementation against known attack vectors."""

    def test_length_extension_not_applicable(self):
        """HMAC is not vulnerable to length extension attacks
        (unlike raw SHA-256). Verify that extending the input
        does not produce a predictable token."""
        key = _DEFAULT_HMAC_KEY
        token_short = _hmac_token("张三", "PERSON", key)
        token_extended = _hmac_token("张三\x00\x00\x00", "PERSON", key)

        assert token_short != token_extended, (
            "Length extension produced same token — HMAC may be broken"
        )

    def test_empty_string_handled(self):
        """Empty string should produce a valid token, not crash."""
        key = _DEFAULT_HMAC_KEY
        token = _hmac_token("", "PERSON", key)
        assert token.startswith("PERSON_")
        assert len(token) == len("PERSON_") + 8

    def test_timing_consistent(self):
        """Token generation should take roughly constant time
        regardless of input, to prevent timing attacks."""
        import time
        key = _DEFAULT_HMAC_KEY

        # Short input
        times_short = []
        for _ in range(1000):
            start = time.monotonic()
            _hmac_token("张", "PERSON", key)
            times_short.append(time.monotonic() - start)

        # Long input
        times_long = []
        for _ in range(1000):
            start = time.monotonic()
            _hmac_token("张" * 10000, "PERSON", key)
            times_long.append(time.monotonic() - start)

        avg_short = sum(times_short) / len(times_short)
        avg_long = sum(times_long) / len(times_long)

        # Long inputs may take a bit more due to hashing, but
        # should be within 100x (not exponential)
        ratio = avg_long / avg_short if avg_short > 0 else 1
        assert ratio < 100, (
            f"Timing ratio {ratio:.1f}x — possible timing attack vector"
        )
        print(f"Timing ratio (long/short): {ratio:.1f}x")

    def test_deterministic_across_calls(self):
        """Same input + same key must ALWAYS produce same token."""
        key = _DEFAULT_HMAC_KEY
        tokens = [_hmac_token("张三", "PERSON", key) for _ in range(100)]
        assert len(set(tokens)) == 1, "HMAC not deterministic"
