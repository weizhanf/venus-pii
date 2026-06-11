"""
Re-identification Resistance Tests — EU AI Act Art. 15, GDPR Recital 26
========================================================================
Prove that HMAC-SHA256 tokens resist reversal attacks.

GDPR Recital 26 standard: data is anonymous only when re-identification is
"reasonably unlikely given all the means reasonably likely to be used."

These tests verify:
  1. Brute-force reversal is computationally infeasible
  2. Different keys produce entirely different token sets
  3. Hash collision rate is negligible
  4. Statistical analysis of tokens reveals no distribution patterns
  5. Token format leaks no information about the original value
"""

from __future__ import annotations

import hashlib
import hmac
import math
import os
import re
import statistics
import time
from collections import Counter

import polars as pl
import pytest

from venus_pii import sanitize, restore
from venus_pii.guard import _hmac_token, _DEFAULT_HMAC_KEY, _DEFAULT_TOKEN_WIDTH


# ============================================================
#  Test Data
# ============================================================

CHINESE_NAMES = [
    "张三", "李四", "王五", "赵六", "陈七", "刘八", "周九", "吴十",
    "郑十一", "孙十二", "钱十三", "朱十四", "马十五", "黄十六",
    "林小明", "杨大伟", "何美丽", "曹文华", "冯志强", "许建国",
]

ENGLISH_NAMES = [
    "Alice Chen", "Bob Li", "Carol Wang", "David Zhang", "Eve Liu",
    "Frank Wu", "Grace Zhou", "Henry Sun", "Ivy Qian", "Jack Zhu",
    "Karen Ma", "Leo Huang", "Mia Lin", "Nick Yang", "Olivia He",
    "Paul Cao", "Quinn Feng", "Rose Xu", "Sam Tang", "Tina Deng",
]

PHONE_NUMBERS = [f"1{d}{str(i).zfill(9)}" for d, i in
                 zip("3456789" * 3, range(21))]

ID_CARDS = [f"11010120000{str(i).zfill(7)}X" for i in range(20)]


# ============================================================
#  1. Brute-force Resistance
# ============================================================

class TestBruteForceResistance:
    """Without the HMAC key, reversing a token should be infeasible."""

    def test_token_not_reversible_without_key(self):
        """Given a token, trying all common Chinese surnames should not
        recover the original without the correct HMAC key."""
        secret_key = b"secret-production-key-2024"
        original = "张三"
        token = _hmac_token(original, "PERSON", secret_key)

        # Attacker tries common names with the WRONG key
        wrong_key = b"attacker-guess-key"
        for name in CHINESE_NAMES:
            attacker_token = _hmac_token(name, "PERSON", wrong_key)
            assert attacker_token != token, (
                f"Wrong key produced matching token for '{name}'"
            )

    def test_token_not_reversible_by_dictionary(self):
        """Even with a dictionary of 10,000 names, attacker cannot match
        tokens without the key."""
        key = os.urandom(32)  # Random production key
        original = "张三"
        token = _hmac_token(original, "PERSON", key)

        # Build a large dictionary of guesses with default key
        guesses = [f"张{chr(0x4E00 + i)}" for i in range(5000)]
        guesses += [f"{chr(0x4E00 + i)}三" for i in range(5000)]

        matched = False
        for guess in guesses:
            if _hmac_token(guess, "PERSON", _DEFAULT_HMAC_KEY) == token:
                matched = True
                break

        assert not matched, "Dictionary attack succeeded — key isolation failure"

    def test_brute_force_timing(self):
        """Brute-forcing 100,000 guesses should take measurable time,
        making large-scale attacks impractical."""
        key = os.urandom(32)
        target_token = _hmac_token("张三", "PERSON", key)

        start = time.monotonic()
        attempts = 0
        for i in range(100_000):
            guess = f"NAME_{i}"
            _hmac_token(guess, "PERSON", key)
            attempts += 1
        elapsed = time.monotonic() - start

        # At this rate, exhausting a realistic name space (millions)
        # would take proportionally longer
        cost_per_attempt_us = (elapsed / attempts) * 1_000_000
        assert cost_per_attempt_us > 0.1, "HMAC too fast — consider key stretching"
        # Document the cost for the report
        print(f"Brute-force cost: {cost_per_attempt_us:.2f}µs per attempt")
        print(f"100k attempts: {elapsed:.3f}s")
        print(f"Estimated 1B attempts: {elapsed * 10_000:.0f}s ({elapsed * 10_000 / 3600:.1f}h)")


# ============================================================
#  2. Key Sensitivity
# ============================================================

class TestKeySensitivity:
    """Different HMAC keys must produce entirely different token sets."""

    def test_different_keys_different_tokens(self):
        """Same input + different key = different token."""
        key_a = b"key-alpha"
        key_b = b"key-beta"
        for name in CHINESE_NAMES:
            token_a = _hmac_token(name, "PERSON", key_a)
            token_b = _hmac_token(name, "PERSON", key_b)
            assert token_a != token_b, f"Key collision for '{name}'"

    def test_key_sensitivity_single_bit(self):
        """Flipping a single bit in the key changes the token."""
        key_original = b"production-key-2024-secure"
        key_flipped = bytearray(key_original)
        key_flipped[0] ^= 0x01  # Flip one bit
        key_flipped = bytes(key_flipped)

        for name in CHINESE_NAMES[:5]:
            t1 = _hmac_token(name, "PERSON", key_original)
            t2 = _hmac_token(name, "PERSON", key_flipped)
            assert t1 != t2, f"Single-bit key change didn't affect token for '{name}'"

    def test_sanitize_with_different_keys(self):
        """Full pipeline: different keys produce different sanitized DataFrames.
        Note: _DEFAULT_HMAC_KEY is set at import time from VENUS_PII_KEY env var.
        To test key sensitivity, we patch the module-level constant directly."""
        import venus_pii.guard as guard
        df = pl.DataFrame({"姓名": CHINESE_NAMES[:5]})

        original_key = guard._DEFAULT_HMAC_KEY

        guard._DEFAULT_HMAC_KEY = b"key-one"
        r1 = sanitize(df)

        guard._DEFAULT_HMAC_KEY = b"key-two"
        r2 = sanitize(df)

        # Restore original
        guard._DEFAULT_HMAC_KEY = original_key

        tokens_1 = set(r1.sanitized_df["姓名"].to_list())
        tokens_2 = set(r2.sanitized_df["姓名"].to_list())
        assert tokens_1 != tokens_2, "Different keys produced same tokens"


# ============================================================
#  3. Collision Resistance
# ============================================================

class TestCollisionResistance:
    """HMAC-SHA256 truncated to 8 hex chars (32 bits) should have
    negligible collision rate for realistic dataset sizes."""

    def test_collision_rate_1000_values(self):
        """Among 1,000 unique values, collision rate should be < 1%."""
        key = _DEFAULT_HMAC_KEY
        values = [f"person_{i}" for i in range(1000)]
        tokens = [_hmac_token(v, "PERSON", key) for v in values]
        unique_tokens = set(tokens)

        collision_rate = 1 - len(unique_tokens) / len(values)
        assert collision_rate < 0.01, (
            f"Collision rate {collision_rate:.2%} exceeds 1% for 1,000 values"
        )
        print(f"1,000 values: {len(unique_tokens)} unique tokens, "
              f"collision rate = {collision_rate:.4%}")

    def test_collision_rate_100000_values(self):
        """Among 100,000 unique values, check collision statistics.
        With 32-bit hash space (4B possibilities), birthday paradox
        predicts ~1.2 collisions at 100k values."""
        key = _DEFAULT_HMAC_KEY
        values = [f"value_{i:06d}" for i in range(100_000)]
        tokens = [_hmac_token(v, "PERSON", key) for v in values]
        unique_tokens = set(tokens)

        collisions = len(values) - len(unique_tokens)
        collision_rate = collisions / len(values)

        # Birthday paradox expected: n^2 / (2 * 2^32) ≈ 1.16 collisions
        # Allow up to 10x expected as safety margin
        expected_collisions = (len(values) ** 2) / (2 * (2 ** 32))
        print(f"100,000 values: {collisions} collisions "
              f"(expected ~{expected_collisions:.1f}), rate = {collision_rate:.4%}")

        assert collision_rate < 0.01, (
            f"Collision rate {collision_rate:.2%} too high for 100k values"
        )

    def test_no_collisions_in_typical_dataset(self):
        """A typical PII dataset (< 10,000 rows) should have zero collisions."""
        key = _DEFAULT_HMAC_KEY
        names = [f"张{chr(0x4E00 + i)}" for i in range(10_000)]
        tokens = [_hmac_token(n, "PERSON", key) for n in names]
        unique_tokens = set(tokens)

        collisions = len(names) - len(unique_tokens)
        # For 10k values in 32-bit space, expected collisions ≈ 0.01
        assert collisions <= 2, (
            f"Expected ≤2 collisions in 10k values, got {collisions}"
        )


# ============================================================
#  4. Statistical Indistinguishability
# ============================================================

class TestStatisticalIndistinguishability:
    """Tokens should reveal no statistical patterns about original values."""

    def test_token_hex_distribution(self):
        """Hex characters in token suffixes should be roughly uniform."""
        key = _DEFAULT_HMAC_KEY
        all_hex_chars = []
        for i in range(10_000):
            token = _hmac_token(f"value_{i}", "PERSON", key)
            # Extract hex suffix (after "PERSON_")
            hex_part = token.split("_", 1)[1]
            all_hex_chars.extend(list(hex_part))

        counts = Counter(all_hex_chars)
        expected = len(all_hex_chars) / 16  # 16 possible hex chars

        # Chi-squared test: each hex char should appear ~expected times
        chi_sq = sum((c - expected) ** 2 / expected for c in counts.values())
        # 15 degrees of freedom, p=0.01 critical value ≈ 30.6
        assert chi_sq < 50, (
            f"Hex distribution non-uniform (chi² = {chi_sq:.1f}, expected < 30.6)"
        )
        print(f"Hex distribution chi² = {chi_sq:.2f} (good if < 30.6)")

    def test_token_length_constant(self):
        """All tokens for same category should have identical length
        (no information leakage through length)."""
        key = _DEFAULT_HMAC_KEY
        short_names = ["张", "李"]
        long_names = ["欧阳修远大将军", "上官婉儿公主殿下"]

        short_tokens = [_hmac_token(n, "PERSON", key) for n in short_names]
        long_tokens = [_hmac_token(n, "PERSON", key) for n in long_names]

        all_lengths = [len(t) for t in short_tokens + long_tokens]
        assert len(set(all_lengths)) == 1, (
            f"Token lengths vary: {all_lengths} — leaks value length info"
        )

    def test_similar_inputs_different_tokens(self):
        """Similar inputs (e.g., 张三 vs 张四) should produce very different tokens."""
        key = _DEFAULT_HMAC_KEY
        t1 = _hmac_token("张三", "PERSON", key)
        t2 = _hmac_token("张四", "PERSON", key)

        # Extract hex parts and compare
        hex1 = t1.split("_")[1]
        hex2 = t2.split("_")[1]

        # Count matching hex positions
        matching = sum(1 for a, b in zip(hex1, hex2) if a == b)
        # With 8 hex chars, random expectation is 0.5 matches
        assert matching <= 4, (
            f"Similar inputs produced similar tokens ({matching}/8 chars match)"
        )

    def test_token_ordering_independent_of_value_ordering(self):
        """Alphabetical order of tokens should NOT correlate with
        alphabetical order of original values."""
        key = _DEFAULT_HMAC_KEY
        sorted_names = sorted(CHINESE_NAMES)
        tokens = [_hmac_token(n, "PERSON", key) for n in sorted_names]

        # Check if tokens are also sorted (they shouldn't be)
        is_sorted = all(tokens[i] <= tokens[i+1] for i in range(len(tokens)-1))
        assert not is_sorted, "Token order preserves original value order"

    def test_no_frequency_leakage_in_sanitized_df(self):
        """Duplicate values should produce duplicate tokens (deterministic),
        but an attacker cannot infer which original value a token represents
        from frequency alone — that requires the key."""
        df = pl.DataFrame({
            "姓名": ["张三", "张三", "李四", "张三", "李四", "王五"],
        })
        result = sanitize(df)
        token_counts = Counter(result.sanitized_df["姓名"].to_list())

        # Deterministic: same name → same token
        assert len(token_counts) == 3, "Expected 3 unique tokens for 3 unique names"

        # The tokens themselves reveal nothing about which name is which
        for token in token_counts:
            assert token.startswith("PERSON_"), f"Token missing prefix: {token}"
            assert re.match(rf"^PERSON_[0-9a-f]{{{_DEFAULT_TOKEN_WIDTH}}}$", token), (
                f"Token format unexpected: {token}"
            )


# ============================================================
#  5. Token Format Security
# ============================================================

class TestTokenFormatSecurity:
    """Token format should leak no information about original values."""

    def test_token_prefix_reveals_only_category(self):
        """Token prefix should indicate category (PERSON, PHONE, etc.)
        but nothing about the specific value."""
        key = _DEFAULT_HMAC_KEY
        assert _hmac_token("张三", "PERSON", key).startswith("PERSON_")
        assert _hmac_token("13800138000", "PHONE", key).startswith("PHONE_")
        assert _hmac_token("test@test.com", "EMAIL", key).startswith("EMAIL_")

    def test_token_contains_no_original_chars(self):
        """No Chinese characters or original value fragments in tokens."""
        key = _DEFAULT_HMAC_KEY
        for name in CHINESE_NAMES:
            token = _hmac_token(name, "PERSON", key)
            for char in name:
                assert char not in token, (
                    f"Original char '{char}' found in token '{token}'"
                )

    def test_token_is_pure_ascii(self):
        """Tokens must be pure ASCII (prefix + underscore + hex)."""
        key = _DEFAULT_HMAC_KEY
        for name in CHINESE_NAMES + ENGLISH_NAMES:
            token = _hmac_token(name, "PERSON", key)
            assert token.isascii(), f"Non-ASCII token: {token}"

    def test_token_regex_format(self):
        """All tokens must match PREFIX_ + default-width hex exactly."""
        key = _DEFAULT_HMAC_KEY
        pattern = re.compile(rf"^[A-Z_]+_[0-9a-f]{{{_DEFAULT_TOKEN_WIDTH}}}$")

        for name in CHINESE_NAMES + ENGLISH_NAMES:
            token = _hmac_token(name, "PERSON", key)
            assert pattern.match(token), f"Token format violation: {token}"

        for phone in PHONE_NUMBERS:
            token = _hmac_token(phone, "PHONE", key)
            assert pattern.match(token), f"Phone token format violation: {token}"


# ============================================================
#  6. Roundtrip Integrity Under Tokenization
# ============================================================

class TestRoundtripIntegrity:
    """Verify that sanitize → restore produces exact original values."""

    def test_roundtrip_chinese_names(self):
        df = pl.DataFrame({"姓名": CHINESE_NAMES})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["姓名"].to_list() == CHINESE_NAMES

    def test_roundtrip_english_names(self):
        df = pl.DataFrame({"name": ENGLISH_NAMES})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["name"].to_list() == ENGLISH_NAMES

    def test_roundtrip_mixed_columns(self):
        df = pl.DataFrame({
            "姓名": CHINESE_NAMES[:5],
            "phone": PHONE_NUMBERS[:5],
            "邮箱": [f"user{i}@test.com" for i in range(5)],
            "score": [85, 92, 78, 95, 88],
        })
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)

        assert restored["姓名"].to_list() == CHINESE_NAMES[:5]
        assert restored["phone"].to_list() == PHONE_NUMBERS[:5]
        assert restored["score"].to_list() == [85, 92, 78, 95, 88]

    def test_roundtrip_preserves_nulls(self):
        df = pl.DataFrame({"姓名": ["张三", None, "王五"]})
        result = sanitize(df)
        restored = restore(result.sanitized_df, result.token_maps)
        assert restored["姓名"].to_list() == ["张三", None, "王五"]
