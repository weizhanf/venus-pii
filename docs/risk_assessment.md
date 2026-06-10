# Risk Assessment — venus-pii

**Document ID**: VENUS-PII-RA-001
**Version**: 1.0
**Date**: 2026-05-19
**EU AI Act Reference**: Article 9 — Risk Management System
**Status**: Active

---

## 1. System Description

**venus-pii** is a client-side Python library for detecting, tokenizing, and restoring Personally Identifiable Information (PII) in Polars DataFrames. It acts as a data protection layer between raw user data and AI/LLM systems.

**Intended purpose**: Prevent PII exposure to AI models during data analysis, while preserving data utility and enabling reversible restoration.

**Protection levels**:
- **BLOCK**: Column removed entirely (ID cards, bank accounts)
- **MASK**: Values replaced with deterministic HMAC-SHA256 tokens (names, phones, emails, addresses)
- **PASS**: Non-PII data passes through unchanged (scores, dates, counts)

---

## 2. Risk Identification

### RISK-001: Incomplete PII Detection (False Negatives)

| Field | Value |
|-------|-------|
| **Category** | Data Protection |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Level** | HIGH |
| **EU AI Act** | Art. 10 (data governance), Art. 15 (accuracy) |

**Description**: PII columns may not be detected if column names don't match known patterns AND cell values don't match value-based regex patterns. This would cause real PII to be sent to AI models unprotected.

**Affected PII types**:
- Names in languages not covered by current regex (Arabic, Hindi, etc.)
- Phone numbers in non-Chinese formats (US, EU, etc.)
- National IDs from non-Chinese jurisdictions
- Custom/proprietary PII categories

**Mitigations**:
- Column name pattern matching covers Chinese and English variants (tested in `test_bias.py`)
- Value-based fallback detection for ID cards, phones, and emails (tested in `test_adversarial.py`)
- Benchmark testing shows FNR < 5% for BLOCK categories (tested in `test_accuracy.py`)
- Extensible architecture: new categories can be added via `COLUMN_NAME_PATTERNS`, `VALUE_PATTERNS`, `CATEGORY_LEVEL`

**Residual risk**: PII types not in the detection ruleset will pass through undetected. Users must review column reports before sending data to AI systems.

---

### RISK-002: HMAC Token Reversal (Re-identification)

| Field | Value |
|-------|-------|
| **Category** | Cryptographic Security |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk Level** | MEDIUM |
| **EU AI Act** | Art. 15 (robustness), GDPR Recital 26 |

**Description**: An attacker with access to HMAC tokens could attempt to reverse them to recover original PII values.

**Attack vectors**:
- Brute-force dictionary attack: Try common names/values with guessed keys
- Statistical analysis: Infer value distribution from token patterns
- Key compromise: If the HMAC key is leaked, all tokens become reversible

**Mitigations**:
- HMAC-SHA256 is computationally one-way without the key (tested in `test_reidentification.py`)
- 100,000 brute-force attempts per second — impractical for large value spaces
- Token format reveals only category (PERSON_, PHONE_) not value characteristics
- Token length is constant regardless of input length (no length leakage)
- Hex character distribution is statistically uniform (no distribution leakage)
- Key isolation: different keys produce entirely different token sets

**Residual risk**: If the HMAC key is compromised, all tokens for that key can be reversed. Key management is the user's responsibility.

---

### RISK-003: Hash Collisions

| Field | Value |
|-------|-------|
| **Category** | Data Integrity |
| **Likelihood** | Very Low |
| **Impact** | Medium |
| **Risk Level** | LOW |
| **EU AI Act** | Art. 15 (accuracy) |

**Description**: HMAC-SHA256 is truncated to 8 hex characters (32 bits). Two different values could produce the same token, causing data loss during restoration.

**Analysis**:
- 32-bit hash space = 4,294,967,296 possible tokens
- Birthday paradox: 50% collision probability at ~65,536 unique values per column
- For typical datasets (< 10,000 rows): expected collisions ≈ 0.01
- For 100,000 unique values: expected ~1.2 collisions

**Mitigations**:
- Collision rate tested at < 0.01% for 100,000 values (`test_reidentification.py`)
- Typical PII columns have far fewer unique values (thousands, not millions)
- Collisions are detectable: forward map creation would show two values mapping to the same token

**Residual risk**: Extremely rare collisions in columns with > 50,000 unique values. Could be mitigated by increasing hash truncation length (breaking change).

---

### RISK-004: Detection Bias Across Languages

| Field | Value |
|-------|-------|
| **Category** | Fairness / Discrimination |
| **Likelihood** | Medium |
| **Impact** | Medium |
| **Risk Level** | MEDIUM |
| **EU AI Act** | Art. 10(2)(f)(g) |

**Description**: PII detection may work better for some languages/regions than others, creating unequal protection. Chinese and English are well-supported; other languages may have gaps.

**Current coverage**:
- Chinese: Full coverage for names (姓名, 名字, etc.), phone (电话, 手机, etc.), ID (身份证号, 证件号, etc.), email (邮箱, 电子邮件), address (地址, 住址, etc.), salary (工资, 薪资, 月薪, etc.)
- English: Full coverage for names, phone, email, address, salary, bank accounts
- Other languages: Column name detection only if English/Chinese aliases are used

**Mitigations**:
- Bias test suite (`test_bias.py`) verifies equal detection across Chinese and English
- Value-based detection works for any language (ID card format, phone format, email format are language-independent)
- Extensible pattern system allows adding new language patterns

**Residual risk**: Users with PII in languages other than Chinese/English must add custom column name patterns for name-based detection.

---

### RISK-005: Adversarial Evasion

| Field | Value |
|-------|-------|
| **Category** | Security |
| **Likelihood** | Low |
| **Impact** | High |
| **Risk Level** | MEDIUM |
| **EU AI Act** | Art. 15 (robustness, cybersecurity) |

**Description**: A malicious actor could craft column names or values to bypass PII detection.

**Attack vectors**:
- Column name obfuscation: Using non-standard column names to avoid pattern matching
- Unicode homoglyph substitution: Using look-alike characters to bypass regex
- Zero-width character injection: Inserting invisible characters to break patterns
- PII embedded in non-PII columns: Storing names in "notes" or "description" fields

**Mitigations**:
- Value-based fallback detection catches PII regardless of column names (tested in `test_adversarial.py`)
- Case-insensitive detection for column names
- Serialization roundtrip tests verify token integrity through JSON, CSV, and Parquet

**Residual risk**: Free-text columns containing PII (e.g., "notes: 张三 called about...") are NOT detected. This requires NLP-based detection, which is out of scope for rule-based pattern matching.

---

### RISK-006: Token Map Exposure

| Field | Value |
|-------|-------|
| **Category** | Data Protection |
| **Likelihood** | Medium |
| **Impact** | High |
| **Risk Level** | HIGH |
| **EU AI Act** | GDPR Art. 5(1)(f) (integrity and confidentiality) |

**Description**: Token maps (reverse mapping from tokens to original values) are stored in memory and may be serialized. If token maps are exposed, all masked data can be reversed.

**Mitigations**:
- Token maps are returned to the caller and never stored on disk by the library
- Client-side only: token maps never leave the user's machine unless explicitly sent
- Users control token map lifecycle and storage

**Residual risk**: If users serialize and store token maps insecurely (e.g., plain text file, unencrypted database), the maps could be accessed by unauthorized parties.

---

### RISK-007: Default HMAC Key Usage

| Field | Value |
|-------|-------|
| **Category** | Configuration Security |
| **Likelihood** | High |
| **Impact** | Medium |
| **Risk Level** | HIGH |
| **EU AI Act** | Art. 15 (cybersecurity) |

**Description**: If users do not set the `VENUS_PII_KEY` environment variable, a default key (`venus-pii-default-key`) is used. This default is publicly known (in source code), making all tokens reversible by anyone who reads the source.

**Mitigations**:
- Documentation warns about setting custom keys in production
- Default key exists to enable quick prototyping and testing

**Recommended actions**:
- Add runtime warning when default key is used
- Add `require_custom_key=True` option to enforce key configuration
- Document key rotation procedures

---

## 3. Risk Register Summary

| ID | Risk | Likelihood | Impact | Level | Status |
|----|------|-----------|--------|-------|--------|
| RISK-001 | Incomplete PII detection | Medium | High | HIGH | Mitigated (benchmarks) |
| RISK-002 | HMAC token reversal | Low | High | MEDIUM | Mitigated (crypto tests) |
| RISK-003 | Hash collisions | Very Low | Medium | LOW | Accepted |
| RISK-004 | Language detection bias | Medium | Medium | MEDIUM | Mitigated (bias tests) |
| RISK-005 | Adversarial evasion | Low | High | MEDIUM | Partially mitigated |
| RISK-006 | Token map exposure | Medium | High | HIGH | User responsibility |
| RISK-007 | Default HMAC key | High | Medium | HIGH | Pending mitigation |

---

## 4. Testing Evidence

| Risk | Test Suite | Tests | Status |
|------|-----------|-------|--------|
| RISK-001 | `tests/test_accuracy.py` | 15 tests, 45 benchmark columns | All passing |
| RISK-002 | `tests/test_reidentification.py` | 22 tests, brute-force + statistical | All passing |
| RISK-003 | `tests/test_reidentification.py` | Collision tests up to 100k values | All passing |
| RISK-004 | `tests/test_bias.py` | 17 tests across Chinese/English | All passing |
| RISK-005 | `tests/test_adversarial.py` | 26 tests including serialization | All passing |
| RISK-006 | N/A | Architecture review | Client-side only |
| RISK-007 | N/A | Pending implementation | Warning not yet added |

---

## 5. Review Schedule

| Review | Trigger | Responsible |
|--------|---------|-------------|
| Quarterly review | Calendar | Project maintainer |
| Post-incident review | Any PII exposure event | Project maintainer |
| New PII category addition | Feature change | Contributor |
| Dependency update | Security advisory | Project maintainer |

---

*This document fulfills the risk management system requirement per EU AI Act Article 9. It shall be updated whenever risks change or new mitigations are implemented.*
