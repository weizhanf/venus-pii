"""
venus-pii — Give AI a blindfold before it sees your data.
==========================================================
HMAC-SHA256 PII sanitization for DataFrames.

Three protection levels:
  BLOCK: Column removed entirely (ID cards, bank accounts)
  MASK:  Values replaced with HMAC tokens (names, phones, emails)
  PASS:  No change (scores, dates, non-sensitive data)

Usage:
  from venus_pii import sanitize, restore
  result = sanitize(df)          # mask before sending to LLM
  restored = restore(safe_df, result.token_maps)  # restore after
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import warnings
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import polars as pl


# ============================================================
#  Enums & Data Classes
# ============================================================

class PIILevel(str, Enum):
    BLOCK = "block"
    MASK = "mask"
    PASS = "pass"


class PIICategory(str, Enum):
    NAME = "name"
    PHONE = "phone"
    ID_CARD = "id_card"
    EMAIL = "email"
    ADDRESS = "address"
    SALARY = "salary"
    BANK_ACCOUNT = "bank_account"
    NONE = "none"


@dataclass
class PIIColumnReport:
    column_name: str
    category: PIICategory = PIICategory.NONE
    level: PIILevel = PIILevel.PASS
    confidence: float = 0.0
    sample_tokens: list[str] = field(default_factory=list)


@dataclass
class PIIGuardResult:
    sanitized_df: pl.DataFrame
    column_reports: list[PIIColumnReport] = field(default_factory=list)
    blocked_columns: list[str] = field(default_factory=list)
    token_maps: dict[str, dict[str, str]] = field(default_factory=dict)


# ============================================================
#  Detection Rules — EXTEND HERE
# ============================================================
# To add a new PII category:
#   1. Add to PIICategory enum
#   2. Add column name pattern to COLUMN_NAME_PATTERNS
#   3. Optionally add value pattern to VALUE_PATTERNS
#   4. Set default level in CATEGORY_LEVEL
#   5. Set token prefix in TOKEN_PREFIX

COLUMN_NAME_PATTERNS: dict[PIICategory, list[re.Pattern]] = {
    PIICategory.NAME: [
        re.compile(r"姓名|名字|name|fullname|full_name|student_name|员工姓名|教师姓名|first.?name|last.?name", re.I),
    ],
    PIICategory.PHONE: [
        # \b on tel/cell stops "hotel"/"excellent" false positives; "telephone"
        # is still caught by the "phone" alternative.
        re.compile(r"电话|手机|phone|mobile|\btel\b|联系方式|\bcell\b", re.I),
    ],
    PIICategory.ID_CARD: [
        re.compile(r"身份证|idcard|id_card|证件号|sfz|\bssn\b|social.?security", re.I),
    ],
    PIICategory.EMAIL: [
        re.compile(r"邮箱|email|e-mail|电子邮件", re.I),
    ],
    PIICategory.ADDRESS: [
        # \bcity\b / \bzip\b stop "velocity"/"zipper"; zip.?code keeps the real
        # postal-code variants, and postal is added recall.
        re.compile(r"地址|住址|address|addr|家庭住址|street|\bcity\b|\bzip\b|zip.?code|postal", re.I),
    ],
    PIICategory.SALARY: [
        re.compile(r"工资|薪资|salary|wage|薪酬|月薪|年薪|收入|income|compensation", re.I),
    ],
    PIICategory.BANK_ACCOUNT: [
        # \bbank\b stops "embankment"; "bank_account" still matched via "account".
        re.compile(r"银行|卡号|\bbank\b|account|账号|routing", re.I),
    ],
}

# Multiple value patterns per category — a value is a match if ANY pattern hits.
# Value patterns must be specific enough not to fire on plain integers (scores,
# counts): bare digit runs are deliberately NOT treated as phones.
VALUE_PATTERNS: dict[PIICategory, list[re.Pattern]] = {
    PIICategory.ID_CARD: [
        re.compile(r"^\d{17}[\dXx]$"),       # China resident ID (18 digits)
        re.compile(r"^\d{3}-\d{2}-\d{4}$"),  # US SSN
    ],
    PIICategory.PHONE: [
        re.compile(r"^1[3-9]\d{9}$"),                       # China mobile
        re.compile(r"^\+\d{8,15}$"),                        # E.164 (requires +)
        re.compile(r"^\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}$"),  # US/NANP w/ separators
    ],
    PIICategory.EMAIL: [
        re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    ],
}

CATEGORY_LEVEL: dict[PIICategory, PIILevel] = {
    PIICategory.ID_CARD: PIILevel.BLOCK,
    PIICategory.BANK_ACCOUNT: PIILevel.BLOCK,
    PIICategory.NAME: PIILevel.MASK,
    PIICategory.PHONE: PIILevel.MASK,
    PIICategory.EMAIL: PIILevel.MASK,
    PIICategory.ADDRESS: PIILevel.MASK,
    PIICategory.SALARY: PIILevel.MASK,
    PIICategory.NONE: PIILevel.PASS,
}

TOKEN_PREFIX: dict[PIICategory, str] = {
    PIICategory.NAME: "PERSON",
    PIICategory.PHONE: "PHONE",
    PIICategory.EMAIL: "EMAIL",
    PIICategory.ADDRESS: "ADDR",
    PIICategory.SALARY: "SALARY_BAND",
}

_PUBLIC_DEFAULT_KEY = b"venus-pii-default-key"
# Default truncation: 16 hex chars = 64 bits. At 64 bits the birthday bound for a
# 50% collision is ~5 billion unique values, vs. ~77k for the old 32-bit (8-char)
# tokens — collisions there silently corrupted restore() and broke joins.
_DEFAULT_TOKEN_WIDTH = 16

# Kept for backwards compatibility (tests/tools patch this module constant).
_DEFAULT_HMAC_KEY = os.environ.get("VENUS_PII_KEY", "venus-pii-default-key").encode("utf-8")


def _resolve_key(key: Optional[str | bytes] = None) -> bytes:
    """Resolve the HMAC key to use, warning loudly if the public default is in play.

    Precedence: explicit ``key`` arg > ``VENUS_PII_KEY`` env var > public default.
    The public default is a constant shipped in the source, so any token produced
    with it is reversible by anyone — we never want that to happen silently.
    """
    if key is not None:
        return key.encode("utf-8") if isinstance(key, str) else key
    env = os.environ.get("VENUS_PII_KEY")
    if env:
        return env.encode("utf-8")
    # Honour a test/tool override of the module constant before warning.
    if _DEFAULT_HMAC_KEY != _PUBLIC_DEFAULT_KEY:
        return _DEFAULT_HMAC_KEY
    warnings.warn(
        "venus-pii: VENUS_PII_KEY is not set, using the public default key. "
        "Tokens produced this way are reversible by ANYONE who has this library. "
        "Set the VENUS_PII_KEY env var or pass key=... to sanitize() for real protection.",
        stacklevel=3,
    )
    return _PUBLIC_DEFAULT_KEY


# ============================================================
#  Detection
# ============================================================

def _detect_by_name(col_name: str) -> PIICategory:
    for category, patterns in COLUMN_NAME_PATTERNS.items():
        for p in patterns:
            if p.search(col_name):
                return category
    return PIICategory.NONE


def _detect_by_values(series: pl.Series) -> PIICategory:
    non_null = series.drop_nulls().cast(pl.Utf8, strict=False)
    if len(non_null) == 0:
        return PIICategory.NONE
    sample = non_null.head(min(20, len(non_null))).to_list()
    for category, patterns in VALUE_PATTERNS.items():
        matches = sum(1 for v in sample if any(p.match(str(v)) for p in patterns))
        if matches / len(sample) > 0.5:
            return category
    return PIICategory.NONE


def detect_pii_columns(df: pl.DataFrame) -> list[PIIColumnReport]:
    """Detect PII columns in a DataFrame. Returns a report for each column."""
    reports = []
    for col_name in df.columns:
        cat = _detect_by_name(col_name)
        confidence = 0.9 if cat != PIICategory.NONE else 0.0
        if cat == PIICategory.NONE:
            cat = _detect_by_values(df[col_name])
            confidence = 0.7 if cat != PIICategory.NONE else 0.0
        level = CATEGORY_LEVEL.get(cat, PIILevel.PASS)
        reports.append(PIIColumnReport(
            column_name=col_name, category=cat, level=level, confidence=confidence,
        ))
    return reports


# ============================================================
#  Tokenization
# ============================================================

def _hmac_token(value: str, prefix: str, key: bytes, width: int = _DEFAULT_TOKEN_WIDTH) -> str:
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:width]
    return f"{prefix}_{digest}"


def _tokenize_column(
    series: pl.Series,
    prefix: str,
    hmac_key: Optional[bytes] = None,
    width: int = _DEFAULT_TOKEN_WIDTH,
) -> tuple[pl.Series, dict[str, str]]:
    key = hmac_key or _DEFAULT_HMAC_KEY
    unique_vals = series.drop_nulls().unique().sort().to_list()
    forward_map = {str(v): _hmac_token(str(v), prefix, key, width) for v in unique_vals}
    # A truncated-digest collision would make restore() return the wrong original
    # and silently break joins. Fail loudly instead of corrupting data.
    if len(set(forward_map.values())) != len(forward_map):
        raise ValueError(
            f"venus-pii: HMAC token collision in column tokenization at width={width}. "
            f"Increase token_width to disambiguate {len(forward_map)} unique values."
        )
    reverse_map = {token: original for original, token in forward_map.items()}
    tokenized = series.cast(pl.Utf8, strict=False).map_elements(
        lambda v: forward_map.get(str(v), v) if v is not None else None,
        return_dtype=pl.Utf8,
    )
    return tokenized, reverse_map


# (band label, lower_inclusive, upper_exclusive). None means unbounded.
_SALARY_BANDS = [
    ("SALARY_BAND_A", None, 5000),
    ("SALARY_BAND_B", 5000, 10000),
    ("SALARY_BAND_C", 10000, 20000),
    ("SALARY_BAND_D", 20000, 50000),
    ("SALARY_BAND_E", 50000, None),
]


def _salary_band(series: pl.Series) -> tuple[pl.Series, dict[str, str]]:
    """Bucket salaries into bands. Banding is lossy by design: restore() recovers
    the band's numeric range string (e.g. "[5000, 10000)"), not the exact value.
    """
    numeric = series.cast(pl.Float64, strict=False)
    reverse_map: dict[str, str] = {}
    def to_band(v):
        if v is None:
            return None
        val = float(v)
        for band, lo, hi in _SALARY_BANDS:
            if (lo is None or val >= lo) and (hi is None or val < hi):
                lo_s = "-inf" if lo is None else str(int(lo))
                hi_s = "+inf" if hi is None else str(int(hi))
                reverse_map[band] = f"[{lo_s}, {hi_s})"
                return band
        return None
    banded = numeric.map_elements(to_band, return_dtype=pl.Utf8)
    return banded, reverse_map


# ============================================================
#  Public API
# ============================================================

def sanitize(
    df: pl.DataFrame,
    reports: Optional[list[PIIColumnReport]] = None,
    *,
    key: Optional[str | bytes] = None,
    token_width: int = _DEFAULT_TOKEN_WIDTH,
) -> PIIGuardResult:
    """Sanitize a DataFrame: detect PII and apply BLOCK/MASK/PASS rules.

    Args:
        df: The DataFrame to sanitize.
        reports: Pre-computed column reports; auto-detected if omitted.
        key: HMAC key for this call. Overrides the VENUS_PII_KEY env var. Pass a
            distinct key per tenant for multi-tenant isolation. If omitted and no
            env var is set, a public default key is used (with a warning) — those
            tokens are reversible by anyone.
        token_width: Hex chars of HMAC digest to keep (default 16 = 64 bits).
    """
    if reports is None:
        reports = detect_pii_columns(df)
    resolved_key = _resolve_key(key)
    sanitized = df.clone()
    blocked_columns: list[str] = []
    token_maps: dict[str, dict[str, str]] = {}
    for report in reports:
        col = report.column_name
        if col not in sanitized.columns:
            continue
        if report.level == PIILevel.BLOCK:
            sanitized = sanitized.drop(col)
            blocked_columns.append(col)
        elif report.level == PIILevel.MASK:
            prefix = TOKEN_PREFIX.get(report.category, "TOKEN")
            if report.category == PIICategory.SALARY:
                tokenized, rmap = _salary_band(sanitized[col])
            else:
                tokenized, rmap = _tokenize_column(
                    sanitized[col], prefix, hmac_key=resolved_key, width=token_width,
                )
            sanitized = sanitized.with_columns(tokenized.alias(col))
            token_maps[col] = rmap
            report.sample_tokens = list(rmap.values())[:5]
    return PIIGuardResult(
        sanitized_df=sanitized, column_reports=reports,
        blocked_columns=blocked_columns, token_maps=token_maps,
    )


def restore(
    df: pl.DataFrame,
    token_maps: dict[str, dict[str, str]],
) -> pl.DataFrame:
    """Restore masked columns using the token map from sanitize()."""
    result = df.clone()
    for col, rmap in token_maps.items():
        if col not in result.columns:
            continue
        result = result.with_columns(
            result[col].cast(pl.Utf8, strict=False).map_elements(
                lambda v, m=rmap: m.get(str(v), v) if v is not None else None,
                return_dtype=pl.Utf8,
            ).alias(col)
        )
    return result
