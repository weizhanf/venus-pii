---
name: testing-venus-pii
description: Test the venus-pii library end-to-end. Use when verifying PII sanitization, trace module, or any venus-pii changes.
---

# Testing venus-pii

## Setup

```bash
cd /home/ubuntu/venus-pii
pip install -e . && pip install pytest
```

## Run Tests

### Unit tests (pytest)
```bash
python -m pytest tests/ -v
```
Expect 41+ tests across `test_guard.py` (PII detection/sanitization) and `test_trace.py` (data flow tracing).

### Demo script
```bash
python examples/trace_demo.py
```
Runs a full traced sanitize → restore pipeline. Verify output contains:
- ASCII TIMELINE, MARKDOWN, JSONL sections
- PERSON_ tokens in sanitized output
- Blocked columns include ID card columns
- Trace file saved to `/tmp/venus_trace_demo.jsonl`

## Adversarial E2E Validation

For thorough testing beyond unit tests, write a Python script that:
1. Runs both `sanitize(df)` and `traced_sanitize(df)` on identical data
2. Asserts output columns, blocked columns, token map keys, and token values are identical
3. Validates JSONL export: every line is valid JSON, header has required fields, seq numbers are sequential
4. Tests error tracing: decorate a function that raises, verify error message + traceback captured
5. Tests shell tracing: run commands with known stdout/returncode, verify captured correctly

## Key Assertions

- `traced_sanitize()` must produce identical results to `sanitize()` — it's observability-only
- JSONL export: every line must parse as valid JSON
- Error events must contain both `error` (message) and `traceback` (full Python traceback)
- Shell events must capture `stdout`, `stderr`, `returncode`, and `duration_ms`

## No CI

This repo has no CI checks configured. Testing is done locally via pytest.

## Architecture Notes

- `venus_pii/guard.py` — Core PII detection and sanitization (BLOCK/MASK/PASS)
- `venus_pii/trace.py` — Data flow tracer module
- `tests/test_guard.py` — Tests for guard module
- `tests/test_trace.py` — Tests for trace module
- `examples/trace_demo.py` — Runnable demo script
- All testing is shell-based (Python library, no GUI) — do NOT record screen

## Devin Secrets Needed

None required for testing.
