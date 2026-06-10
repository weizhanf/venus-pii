"""
venus-pii — Give AI a blindfold before it sees your data.

The core (detect / sanitize / restore) is imported eagerly and stays lightweight.
The optional trace module (venus_pii.trace) is imported lazily via PEP 562: it is
only loaded when you actually access TraceRecorder / traced_sanitize / traced_restore
(or `import venus_pii.trace` directly), so `import venus_pii` never pulls in
subprocess/inspect/etc. just to mask a DataFrame.
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

# Names served lazily from venus_pii.trace on first access.
_LAZY_TRACE_EXPORTS = {
    "TraceRecorder",
    "traced_sanitize",
    "traced_restore",
}

__all__ = [
    "detect",
    "sanitize",
    "restore",
    "PIICategory",
    "PIILevel",
    "PIIColumnReport",
    "PIIGuardResult",
    *sorted(_LAZY_TRACE_EXPORTS),
]


def __getattr__(name: str):
    # PEP 562: resolve trace exports on demand so the heavy module isn't imported
    # unless it's actually used.
    if name in _LAZY_TRACE_EXPORTS:
        from venus_pii import trace

        return getattr(trace, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__():
    return sorted(set(globals()) | _LAZY_TRACE_EXPORTS)
