"""
Bias Detection Tests — EU AI Act Art. 10(2)(f)(g)
==================================================
Test for discriminatory detection failures across languages, regions,
and demographic patterns.

Art. 10(2)(f): "examination in view of possible biases that are likely to
affect the health and safety of persons, have a negative impact on
fundamental rights or lead to discrimination"

Art. 10(2)(g): "appropriate measures to detect, prevent and mitigate
possible biases identified"
"""

from __future__ import annotations

import polars as pl
import pytest

from venus_pii import detect, sanitize, restore
from venus_pii.guard import PIICategory, PIILevel


# ============================================================
#  Language Bias: Name Detection
# ============================================================

class TestNameDetectionBias:
    """Name detection should work equally across languages."""

    def test_chinese_names_detected(self):
        df = pl.DataFrame({"姓名": ["张三", "李四", "王五"]})
        reports = detect(df)
        assert reports[0].category == PIICategory.NAME

    def test_english_names_detected(self):
        df = pl.DataFrame({"name": ["Alice Chen", "Bob Li"]})
        reports = detect(df)
        assert reports[0].category == PIICategory.NAME

    def test_chinese_column_name_variants(self):
        """All Chinese name column variants should be detected."""
        variants = {
            "姓名": ["张三", "李四"],
            "名字": ["王五", "赵六"],
            "员工姓名": ["陈七", "刘八"],
            "教师姓名": ["周老师", "吴老师"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.NAME, (
                f"Chinese name variant '{col_name}' not detected"
            )

    def test_english_column_name_variants(self):
        """All English name column variants should be detected."""
        variants = {
            "name": ["Alice", "Bob"],
            "fullname": ["John Doe", "Jane Smith"],
            "full_name": ["Alice Chen", "Bob Li"],
            "student_name": ["Carol Wang", "David Zhang"],
            "first_name": ["Eve", "Frank"],
            "last_name": ["Liu", "Wu"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.NAME, (
                f"English name variant '{col_name}' not detected"
            )

    def test_equal_masking_quality_chinese_vs_english(self):
        """Chinese and English names should be masked with equal quality."""
        df_cn = pl.DataFrame({"姓名": ["张三", "李四", "王五"]})
        df_en = pl.DataFrame({"name": ["Alice", "Bob", "Carol"]})

        r_cn = sanitize(df_cn)
        r_en = sanitize(df_en)

        # Both should be masked (not blocked, not passed)
        assert "姓名" in r_cn.token_maps, "Chinese names not masked"
        assert "name" in r_en.token_maps, "English names not masked"

        # Both should have same number of tokens
        assert len(r_cn.token_maps["姓名"]) == 3
        assert len(r_en.token_maps["name"]) == 3

        # Both should be restorable
        restored_cn = restore(r_cn.sanitized_df, r_cn.token_maps)
        restored_en = restore(r_en.sanitized_df, r_en.token_maps)

        assert restored_cn["姓名"].to_list() == ["张三", "李四", "王五"]
        assert restored_en["name"].to_list() == ["Alice", "Bob", "Carol"]


# ============================================================
#  Phone Number Format Bias
# ============================================================

class TestPhoneFormatBias:
    """Phone detection should handle Chinese mobile formats consistently."""

    def test_chinese_mobile_formats(self):
        """Standard Chinese mobile numbers (1[3-9]XXXXXXXXX) should be detected."""
        numbers = [
            "13800138000",  # 138 prefix
            "13900139000",  # 139 prefix
            "15012345678",  # 150 prefix
            "16612345678",  # 166 prefix
            "17712345678",  # 177 prefix
            "18812345678",  # 188 prefix
            "19912345678",  # 199 prefix
        ]
        df = pl.DataFrame({"phone": numbers})
        reports = detect(df)
        assert reports[0].category == PIICategory.PHONE, "Chinese mobile numbers not detected"

    def test_phone_column_name_bias(self):
        """Both Chinese and English phone column names should be detected."""
        column_variants = {
            "phone": ["13800138000"],
            "电话": ["13800138001"],
            "手机": ["13800138002"],
            "mobile": ["13800138003"],
            "联系方式": ["13800138004"],
            "tel": ["13800138005"],
            "cell": ["13800138006"],
        }
        for col_name, values in column_variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.PHONE, (
                f"Phone column variant '{col_name}' not detected"
            )


# ============================================================
#  ID Card Format Bias
# ============================================================

class TestIDCardBias:
    """ID card detection should handle all valid Chinese ID formats."""

    def test_standard_18_digit_id(self):
        """Standard 18-digit Chinese ID cards."""
        ids = ["110101200001011234", "440301199901012345"]
        df = pl.DataFrame({"身份证号": ids})
        reports = detect(df)
        assert reports[0].category == PIICategory.ID_CARD
        assert reports[0].level == PIILevel.BLOCK

    def test_id_with_x_checksum(self):
        """ID cards ending with X should also be detected."""
        ids = ["11010120000101123X", "44030119990101234x"]
        df = pl.DataFrame({"身份证号": ids})
        reports = detect(df)
        assert reports[0].category == PIICategory.ID_CARD

    def test_id_column_name_variants(self):
        """All ID card column name variants should be detected."""
        variants = {
            "身份证号": ["110101200001011234"],
            "idcard": ["110101200002021234"],
            "id_card": ["110101200003031234"],
            "证件号": ["110101200004041234"],
            "sfz": ["110101200005051234"],
            "ssn": ["110101200006061234"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.ID_CARD, (
                f"ID card variant '{col_name}' not detected"
            )
            assert reports[0].level == PIILevel.BLOCK, (
                f"ID card variant '{col_name}' not set to BLOCK"
            )


# ============================================================
#  Email Format Bias
# ============================================================

class TestEmailBias:
    """Email detection should handle various email formats equally."""

    def test_email_column_variants(self):
        variants = {
            "邮箱": ["test@test.com", "user@domain.com"],
            "email": ["a@b.com", "c@d.org"],
            "e-mail": ["x@y.io", "p@q.net"],
            "电子邮件": ["hello@world.com", "foo@bar.co"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.EMAIL, (
                f"Email variant '{col_name}' not detected"
            )

    def test_various_email_domains_detected(self):
        """Emails from different providers should all be detected."""
        emails = [
            "user@gmail.com",
            "user@outlook.com",
            "user@qq.com",
            "user@163.com",
            "user@company.co.jp",
            "user@university.edu.cn",
        ]
        df = pl.DataFrame({"email": emails})
        reports = detect(df)
        assert reports[0].category == PIICategory.EMAIL


# ============================================================
#  Address Bias
# ============================================================

class TestAddressBias:
    """Address detection should work for Chinese and English addresses."""

    def test_chinese_address_column_variants(self):
        variants = {
            "地址": ["北京市朝阳区", "上海市浦东新区"],
            "住址": ["广州市天河区", "深圳市南山区"],
            "家庭住址": ["杭州市西湖区", "成都市武侯区"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.ADDRESS, (
                f"Address variant '{col_name}' not detected"
            )

    def test_english_address_column_variants(self):
        variants = {
            "address": ["123 Main St", "456 Oak Ave"],
            "addr": ["789 Pine Rd", "321 Elm Blvd"],
            "street": ["100 Broadway", "200 5th Ave"],
            "city": ["New York", "Los Angeles"],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.ADDRESS, (
                f"Address variant '{col_name}' not detected"
            )


# ============================================================
#  Salary / Income Bias
# ============================================================

class TestSalaryBias:
    """Salary detection should work for all income-related columns."""

    def test_salary_column_variants(self):
        variants = {
            "salary": [8500, 25000],
            "工资": [5000, 12000],
            "薪资": [8000, 15000],
            "月薪": [6000, 20000],
            "年薪": [100000, 200000],
            "收入": [7000, 18000],
            "income": [30000, 60000],
            "wage": [4500, 9000],
            "compensation": [10000, 35000],
        }
        for col_name, values in variants.items():
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].category == PIICategory.SALARY, (
                f"Salary variant '{col_name}' not detected"
            )

    def test_salary_banding_consistency(self):
        """All salary values should be banded consistently regardless
        of column name language."""
        df_cn = pl.DataFrame({"工资": [8500, 25000, 45000]})
        df_en = pl.DataFrame({"salary": [8500, 25000, 45000]})

        r_cn = sanitize(df_cn)
        r_en = sanitize(df_en)

        # Both should produce same bands for same values
        bands_cn = r_cn.sanitized_df["工资"].to_list()
        bands_en = r_en.sanitized_df["salary"].to_list()
        assert bands_cn == bands_en, (
            f"Salary banding inconsistent: CN={bands_cn} vs EN={bands_en}"
        )


# ============================================================
#  Cross-Category Consistency
# ============================================================

class TestCrossCategoryConsistency:
    """All PII categories should have consistent protection levels."""

    def test_block_categories_always_block(self):
        """BLOCK-level categories should NEVER be downgraded to MASK or PASS."""
        block_tests = [
            ("身份证号", ["110101200001011234"], PIICategory.ID_CARD),
            ("bank_account", ["6222021234567890"], PIICategory.BANK_ACCOUNT),
        ]
        for col_name, values, expected_cat in block_tests:
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            for r in reports:
                if r.category == expected_cat:
                    assert r.level == PIILevel.BLOCK, (
                        f"{expected_cat.value} downgraded from BLOCK to {r.level}"
                    )

    def test_mask_categories_never_pass(self):
        """MASK-level categories should not be incorrectly passed through."""
        mask_tests = [
            ("姓名", ["张三", "李四"]),
            ("phone", ["13800138000", "13900139000"]),
            ("email", ["a@b.com", "c@d.com"]),
        ]
        for col_name, values in mask_tests:
            df = pl.DataFrame({col_name: values})
            reports = detect(df)
            assert reports[0].level != PIILevel.PASS, (
                f"Column '{col_name}' incorrectly passed through"
            )

    def test_multi_column_no_cross_contamination(self):
        """Detection of one PII column should not affect others."""
        df = pl.DataFrame({
            "姓名": ["张三", "李四"],
            "score": [85, 92],
            "phone": ["13800138000", "13900139000"],
            "department": ["Engineering", "Marketing"],
        })
        reports = detect(df)
        report_map = {r.column_name: r for r in reports}

        assert report_map["姓名"].category == PIICategory.NAME
        assert report_map["score"].category == PIICategory.NONE
        assert report_map["phone"].category == PIICategory.PHONE
        assert report_map["department"].category == PIICategory.NONE
