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


def test_default_key_warns():
    """Using the public default key must warn — it is reversible by anyone."""
    df = pl.DataFrame({"姓名": ["张三"]})
    with pytest.warns(UserWarning, match="VENUS_PII_KEY"):
        sanitize(df)


def test_explicit_key_no_warning():
    df = pl.DataFrame({"姓名": ["张三"]})
    import warnings as _w
    with _w.catch_warnings():
        _w.simplefilter("error")  # any warning becomes an error
        sanitize(df, key="my-secret-key")  # must not warn


def test_key_isolation():
    """Different keys must produce different tokens (multi-tenant isolation)."""
    df = pl.DataFrame({"姓名": ["张三", "李四"]})
    t1 = sanitize(df, key="tenant-A").sanitized_df["姓名"].to_list()
    t2 = sanitize(df, key="tenant-B").sanitized_df["姓名"].to_list()
    assert t1 != t2
    # Same key is still deterministic.
    t1b = sanitize(df, key="tenant-A").sanitized_df["姓名"].to_list()
    assert t1 == t1b


def test_token_width_default_64bit():
    """Default token is PREFIX_ + 16 hex chars (64 bits)."""
    df = pl.DataFrame({"姓名": ["张三"]})
    token = sanitize(df, key="k").sanitized_df["姓名"][0]
    assert token.startswith("PERSON_")
    assert len(token.split("_", 1)[1]) == 16


def test_salary_band_restores_to_range():
    df = pl.DataFrame({"月薪": [3000, 8000, 60000]})
    result = sanitize(df, key="k")
    restored = restore(result.sanitized_df, result.token_maps)["月薪"].to_list()
    assert restored == ["[-inf, 5000)", "[5000, 10000)", "[50000, +inf)"]
