# Contributing to venus-pii

Every new PII detector is one function + one PR. Here's how.

## Adding a new PII category

### 1. Add the category to the enum

```python
# venus_pii/guard.py

class PIICategory(str, Enum):
    ...
    MEDICAL_RECORD = "medical_record"  # your new category
```

### 2. Add column name patterns

```python
COLUMN_NAME_PATTERNS[PIICategory.MEDICAL_RECORD] = [
    re.compile(r"病历|诊断|diagnosis|medical.?record|patient.?id", re.I),
]
```

### 3. (Optional) Add value patterns

```python
VALUE_PATTERNS[PIICategory.MEDICAL_RECORD] = re.compile(r"^MRN-\d{8}$")
```

### 4. Set the protection level

```python
CATEGORY_LEVEL[PIICategory.MEDICAL_RECORD] = PIILevel.BLOCK  # or MASK
```

### 5. Set the token prefix (if MASK)

```python
TOKEN_PREFIX[PIICategory.MEDICAL_RECORD] = "MRN"
```

### 6. Add a test

```python
def test_detect_medical_record():
    df = pl.DataFrame({"病历号": ["MRN-00012345", "MRN-00067890"]})
    reports = detect(df)
    assert reports[0].category == PIICategory.MEDICAL_RECORD
```

### 7. Submit PR

That's it. No need to touch any other file.

## Wanted detectors

- Japanese names (kanji/katakana patterns)
- Korean names (hangul patterns)
- US Social Security Numbers (XXX-XX-XXXX)
- European IBAN bank accounts
- Medical record numbers (HL7/FHIR)
- GDPR special categories (religion, ethnicity, biometrics)
- Indian Aadhaar numbers (12-digit)
- Brazilian CPF numbers (XXX.XXX.XXX-XX)

Pick one and open a PR!
