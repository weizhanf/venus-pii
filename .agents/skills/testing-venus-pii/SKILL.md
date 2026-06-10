---
name: testing-venus-pii
description: Test the venus-pii PII protection library end-to-end. Use when verifying guard.py (sanitize/restore/detect), trace.py (TraceRecorder), or EU AI Act compliance test suites.
---

# Testing venus-pii

## Environment Setup

```bash
cd /home/ubuntu/venus-pii
pip install -e . && pip install pytest
```

No external services, databases, or API keys required. All testing is shell-based — no browser/GUI recording needed.

## Devin Secrets Needed

None. The library uses a default HMAC key for testing. No external credentials required.

## Quick Smoke Test

```bash
python -m pytest tests/ -v --tb=short
```

Expected: 123 tests collected, all passing, ~1s runtime. If test count changes, check which files are in `tests/`.

## Test Suites

| File | Tests | What It Covers |
|------|-------|---------|
| `tests/test_guard.py` | 12 | Core sanitize/restore/detect logic |
| `tests/test_trace.py` | 31 | TraceRecorder, @trace decorator, JSONL/Markdown/Timeline export |
| `tests/test_reidentification.py` | 22 | HMAC brute-force resistance, key sensitivity, collision rates, statistical indistinguishability |
| `tests/test_accuracy.py` | 15 | 45-column benchmark, FNR/FPR metrics, confidence scores |
| `tests/test_bias.py` | 17 | Chinese/English detection parity across all PII types |
| `tests/test_adversarial.py` | 26 | Column obfuscation, serialization roundtrip, edge cases, HMAC attacks |

## Adversarial Integration Testing

Beyond pytest, run targeted integration scenarios that exercise the full pipeline:

### 1. Re-identification Resistance
Tokenize names with a secret key, then attempt brute-force with a wrong key. Expect 0 matches from 10,000+ guesses.

### 2. BLOCK Category FNR
Test ALL column name variants for ID cards (`身份证号`, `idcard`, `id_card`, `证件号`, `ssn`) and bank accounts (`bank_account`, `银行卡号`, `account`). Every variant must detect as BLOCK level. FNR must be exactly 0%.

### 3. Bias Parity
Create equivalent DataFrames in Chinese and English. Both must produce identical token map sizes, both must roundtrip correctly, and salary banding must produce identical bands for identical values.

### 4. Serialization Roundtrip
Sanitize a DataFrame, serialize to JSON/CSV/Parquet, deserialize, restore. Restored values must match originals exactly. Token maps must survive JSON serialization.

### 5. Trace Pipeline
Run `traced_sanitize()` + `traced_restore()`, export JSONL. Verify: event count > 10, valid JSON on every line, sequential seq numbers, data_flow events present, BLOCK/MASK decision notes captured.

### 6. All Columns Blocked
Create a DataFrame with only BLOCK-level columns (身份证号, 银行卡号). Sanitized result must have 0 columns, 2 blocked entries, 0 token maps.

## Key Gotchas

- **HMAC key is a module-level constant**: `guard._DEFAULT_HMAC_KEY` is set at import time from `VENUS_PII_KEY` env var. To test with different keys, patch the module constant directly (`guard._DEFAULT_HMAC_KEY = b"new-key"`), don't set `os.environ` after import — it won't take effect.
- **Polars not Pandas**: This library uses Polars DataFrames, not Pandas. Use `pl.DataFrame()`, not `pd.DataFrame()`.
- **No CI configured**: This repo has no GitHub Actions or other CI. Tests must be run locally.
- **Token format**: Tokens are `PREFIX_` + 8 hex chars (e.g., `PERSON_a4f92e42`). The prefix reveals the PII category but nothing about the original value.
- **BLOCK vs MASK**: BLOCK columns are completely removed from the sanitized DataFrame (not tokenized). MASK columns are tokenized and can be restored. Don't expect token maps for BLOCK columns.
- **Salary banding**: Salaries are replaced with band labels (SALARY_BAND_A through SALARY_BAND_E), not tokenized. Banding is deterministic based on value ranges.
