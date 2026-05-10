"""venus-pii test suite"""

import pytest
import polars as pl
from venus_pii import detect, sanitize, restore, PIICategory, PIILevel


def test_detect_name():
    df = pl.DataFrame({"姓名": ["张三", "李四"]})
    reports = detect(df)
    assert reports[0].category == PIICategory.NAME
    assert reports[0].level == PIILevel.MASK


def test_detect_id_card():
    df = pl.DataFrame({"身份证号": ["110101200001011234", "110101200002021234"]})
    reports = detect(df)
    assert reports[0].category == PIICategory.ID_CARD
    assert reports[0].level == PIILevel.BLOCK


def test_detect_phone():
    df = pl.DataFrame({"phone": ["13800138001", "13900139001"]})
    reports = detect(df)
    assert reports[0].category == PIICategory.PHONE


def test_detect_email():
    df = pl.DataFrame({"邮箱": ["a@b.com", "c@d.com"]})
    reports = detect(df)
    assert reports[0].category == PIICategory.EMAIL


def test_detect_score_passes():
    df = pl.DataFrame({"成绩": [85, 92, 78]})
    reports = detect(df)
    assert reports[0].level == PIILevel.PASS


def test_sanitize_blocks_id():
    df = pl.DataFrame({"id_card": ["110101200001011234"], "score": [85]})
    result = sanitize(df)
    assert "id_card" not in result.sanitized_df.columns
    assert "id_card" in result.blocked_columns


def test_sanitize_masks_name():
    df = pl.DataFrame({"姓名": ["张三", "李四"]})
    result = sanitize(df)
    names = result.sanitized_df["姓名"].to_list()
    assert all(n.startswith("PERSON_") for n in names)


def test_sanitize_preserves_score():
    df = pl.DataFrame({"score": [85, 92]})
    result = sanitize(df)
    assert result.sanitized_df["score"].to_list() == [85, 92]


def test_restore_roundtrip():
    df = pl.DataFrame({"姓名": ["张三", "李四"], "score": [85, 92]})
    result = sanitize(df)
    restored = restore(result.sanitized_df, result.token_maps)
    assert restored["姓名"].to_list() == ["张三", "李四"]


def test_hmac_deterministic():
    df = pl.DataFrame({"姓名": ["张三"]})
    r1 = sanitize(df)
    r2 = sanitize(df)
    assert r1.sanitized_df["姓名"][0] == r2.sanitized_df["姓名"][0]


def test_hmac_not_sequential():
    df = pl.DataFrame({"姓名": ["张三"]})
    result = sanitize(df)
    token = result.sanitized_df["姓名"][0]
    assert "001" not in token  # not sequential numbering


def test_null_preserved():
    df = pl.DataFrame({"姓名": ["张三", None, "王五"]})
    result = sanitize(df)
    assert result.sanitized_df["姓名"].null_count() == 1
