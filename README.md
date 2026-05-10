# venus-pii

**Give AI a blindfold before it sees your data.**

Every developer calling an LLM API is sending user data to someone else's server. This library lets you blindfold the AI with one line of code — before the data ever leaves your machine.

```python
from venus_pii import sanitize

safe_df = sanitize(df)
# "张三" → "PERSON_a3f8c21e"    (HMAC, irreversible without your key)
# "110101200001011234" → [REMOVED]  (ID card, blocked entirely)
# "85" → "85"                      (score, passed through)
```

Your data. Your key. Your rules.

---

## Why

| What happens today | What venus-pii does |
|---|---|
| You send raw names, phone numbers, IDs to ChatGPT/Claude/Gemini | HMAC-SHA256 tokenization — AI sees `PERSON_a3f8c21e`, never "张三" |
| You trust the provider's privacy policy | You trust **your own code** — data is masked before it leaves your machine |
| No way to prove what AI saw | Every masking operation is logged with SHA-256 hash chain |

## Install

```bash
pip install venus-pii
```

## Three Protection Levels

| Level | What happens | Example |
|-------|-------------|---------|
| **BLOCK** | Column removed entirely. AI never sees it. | ID cards, bank accounts |
| **MASK** | Values replaced with HMAC tokens. Reversible only with your key. | Names, phones, emails |
| **PASS** | No change. Non-sensitive data passes through. | Scores, dates, categories |

## Usage

### Basic — One line

```python
import polars as pl
from venus_pii import sanitize

df = pl.DataFrame({
    "name": ["Alice", "Bob"],
    "ssn": ["123-45-6789", "987-65-4321"],
    "score": [95, 88],
})

result = sanitize(df)
print(result.sanitized_df)
# name: PERSON_7a3f..., PERSON_b2e9...
# ssn: [column removed]
# score: 95, 88

print(result.blocked_columns)   # ["ssn"]
print(result.token_maps.keys()) # ["name"]
```

### Restore after processing

```python
from venus_pii import sanitize, restore

result = sanitize(df)
safe_df = result.sanitized_df

# ... send safe_df to LLM, get results back ...

original_df = restore(safe_df, result.token_maps)
# "PERSON_7a3f..." → "Alice"
```

### Custom HMAC key

```bash
export VENUS_PII_KEY="my-secret-enterprise-key"
```

Same name + same key = same token (deterministic across sessions).
Different key = different token (multi-tenant isolation).

### Detect without masking

```python
from venus_pii import detect

reports = detect(df)
for r in reports:
    print(f"{r.column_name}: {r.category} ({r.level})")
# name: name (mask)
# ssn: id_card (block)
# score: none (pass)
```

## Supported PII Categories

| Category | Detection | Level | Contribute? |
|----------|-----------|-------|-------------|
| Names (Chinese/English) | Column name pattern | MASK | [#1](../../issues) |
| Phone numbers | Regex `1[3-9]\d{9}` | MASK | [#2](../../issues) |
| ID cards (China) | Regex 18-digit | BLOCK | [#3](../../issues) |
| Email | Regex `*@*.*` | MASK | |
| Addresses | Column name pattern | MASK | |
| Salary/Income | Column name + band mapping | MASK | |
| Bank accounts | Column name pattern | BLOCK | |
| **Japanese names** | — | — | **Wanted!** [#10](../../issues) |
| **Korean names** | — | — | **Wanted!** [#11](../../issues) |
| **Medical records** | — | — | **Wanted!** [#12](../../issues) |
| **GDPR categories** | — | — | **Wanted!** [#13](../../issues) |
| **US SSN** | — | — | **Wanted!** [#14](../../issues) |

**Every new PII detector is one function + one PR.** See [CONTRIBUTING.md](CONTRIBUTING.md).

## How HMAC tokenization works

```
"张三" + secret_key
    → HMAC-SHA256 → a3f8c21e78b4...
    → "PERSON_a3f8c21e"
```

- **Deterministic**: same input + same key = same token (join tables still work)
- **Irreversible**: can't recover "张三" from "PERSON_a3f8c21e" without the reverse map
- **Isolated**: different key = completely different tokens (multi-tenant safe)

The reverse map (`token_maps`) stays on your machine. The LLM never sees it.

## Part of the Venus Protocol

venus-pii is the privacy layer of [Venus](https://github.com/weizhanf/venus-agent-site) — a white-box AI data processing engine.

The Venus philosophy: **AI is a beautiful goddess, but she must have severed arms.** Humans control what AI can touch, what it can see, and what it can do — through auditable, reversible, white-box constraints.

## License

MIT
