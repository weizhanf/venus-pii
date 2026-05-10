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
        re.compile(r"电话|手机|phone|mobile|tel|联系方式|cell", re.I),
    ],
    PIICategory.ID_CARD: [
        re.compile(r"身份证|idcard|id_card|证件号|sfz|ssn|social.?security", re.I),
    ],
    PIICategory.EMAIL: [
        re.compile(r"邮箱|email|e-mail|电子邮件", re.I),
    ],
    PIICategory.ADDRESS: [
        re.compile(r"地址|住址|address|addr|家庭住址|street|city|zip", re.I),
    ],
    PIICategory.SALARY: [
        re.compile(r"工资|薪资|salary|wage|薪酬|月薪|年薪|收入|income|compensation", re.I),
    ],
    PIICategory.BANK_ACCOUNT: [
        re.compile(r"银行|卡号|bank|account|账号|routing", re.I),
    ],
}

VALUE_PATTERNS: dict[PIICategory, re.Pattern] = {
    PIICategory.ID_CARD: re.compile(r"^\d{17}[\dXx]$"),
    PIICategory.PHONE: re.compile(r"^1[3-9]\d{9}$"),
    PIICategory.EMAIL: re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
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

_DEFAULT_HMAC_KEY = os.environ.get("VENUS_PII_KEY", "venus-pii-default-key").encode("utf-8")


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
    for category, pattern in VALUE_PATTERNS.items():
        matches = sum(1 for v in sample if pattern.match(str(v)))
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

def _hmac_token(value: str, prefix: str, key: bytes) -> str:
    digest = hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:8]
    return f"{prefix}_{digest}"


def _tokenize_column(
    series: pl.Series, prefix: str, hmac_key: Optional[bytes] = None,
) -> tuple[pl.Series, dict[str, str]]:
    key = hmac_key or _DEFAULT_HMAC_KEY
    unique_vals = series.drop_nulls().unique().sort().to_list()
    forward_map = {str(v): _hmac_token(str(v), prefix, key) for v in unique_vals}
    reverse_map = {token: original for original, token in forward_map.items()}
    tokenized = series.cast(pl.Utf8, strict=False).map_elements(
        lambda v: forward_map.get(str(v), v) if v is not None else None,
        return_dtype=pl.Utf8,
    )
    return tokenized, reverse_map


def _salary_band(series: pl.Series) -> tuple[pl.Series, dict[str, str]]:
    numeric = series.cast(pl.Float64, strict=False)
    reverse_map: dict[str, str] = {}
    def to_band(v):
        if v is None:
            return None
        val = float(v)
        if val < 5000:
            band = "SALARY_BAND_A"
        elif val < 10000:
            band = "SALARY_BAND_B"
        elif val < 20000:
            band = "SALARY_BAND_C"
        elif val < 50000:
            band = "SALARY_BAND_D"
        else:
            band = "SALARY_BAND_E"
        reverse_map[band] = f"{band}(range)"
        return band
    banded = numeric.map_elements(to_band, return_dtype=pl.Utf8)
    return banded, reverse_map


# ============================================================
#  Public API
# ============================================================

def sanitize(
    df: pl.DataFrame,
    reports: Optional[list[PIIColumnReport]] = None,
) -> PIIGuardResult:
    """Sanitize a DataFrame: detect PII and apply BLOCK/MASK/PASS rules."""
    if reports is None:
        reports = detect_pii_columns(df)
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
                tokenized, rmap = _tokenize_column(sanitized[col], prefix)
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
