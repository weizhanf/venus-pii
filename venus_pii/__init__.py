"""
venus-pii — Give AI a blindfold before it sees your data.
"""

from venus_pii.guard import (
    detect_pii_columns as detect,
    sanitize,
    restore,
    PIICategory,
    PIILevel,
    PIIColumnReport,
    PIIGuardResult,
)

__version__ = "0.1.0"
__all__ = [
    "detect",
    "sanitize",
    "restore",
    "PIICategory",
    "PIILevel",
    "PIIColumnReport",
    "PIIGuardResult",
]
