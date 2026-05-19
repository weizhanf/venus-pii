"""
venus_pii.trace — AI Agent Data Flow Tracer
=============================================
White-box observability for AI data pipelines.

Captures the complete, controlled data flow that's normally hidden:
- Function inputs/outputs with timing
- Tool calls (MCP-style structured events)
- Shell command execution with stdout/stderr/tracebacks
- DataFrame transformations (before/after snapshots)
- Exception tracebacks with full context

Every event is timestamped and sequenced. Export as JSONL (machine),
Markdown (human), or ASCII timeline (terminal).

Usage:
    from venus_pii.trace import TraceRecorder

    rec = TraceRecorder("my-experiment")

    @rec.trace
    def my_function(x):
        return x * 2

    my_function(21)
    print(rec.to_markdown())
"""

from __future__ import annotations

import functools
import inspect
import json
import subprocess
import sys
import time
import traceback as tb_mod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

import polars as pl


# ============================================================
#  Event Types
# ============================================================

class EventType(str, Enum):
    CALL = "call"
    RETURN = "return"
    ERROR = "error"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    SHELL_CMD = "shell_cmd"
    DATA_FLOW = "data_flow"
    NOTE = "note"


@dataclass
class TraceEvent:
    """A single event in the recorded trace."""

    seq: int
    event_type: EventType
    timestamp: str
    elapsed_ms: float
    function_name: str = ""
    args: dict = field(default_factory=dict)
    result: Any = None
    error: Optional[str] = None
    traceback: Optional[str] = None
    duration_ms: Optional[float] = None
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["event_type"] = self.event_type.value
        if d["result"] is not None:
            d["result"] = _safe_repr(d["result"])
        return {k: v for k, v in d.items() if v is not None and v != {} and v != ""}


# ============================================================
#  Safe serialization helpers
# ============================================================

def _safe_repr(obj: Any, max_len: int = 500) -> str:
    """Safe string representation, truncated for large objects."""
    if isinstance(obj, pl.DataFrame):
        return f"DataFrame({obj.shape[0]}×{obj.shape[1]} cols={obj.columns})"
    if isinstance(obj, pl.Series):
        return f"Series(name={obj.name!r}, len={len(obj)})"
    try:
        s = repr(obj)
    except Exception:
        s = f"<{type(obj).__name__}>"
    if len(s) > max_len:
        return s[:max_len] + f"…({len(s)} chars)"
    return s


def _safe_args(func: Callable, args: tuple, kwargs: dict) -> dict:
    """Extract function arguments as a serializable dict."""
    sig = inspect.signature(func)
    bound = sig.bind(*args, **kwargs)
    bound.apply_defaults()
    return {k: _safe_repr(v) for k, v in bound.arguments.items()}


def _df_snapshot(df: pl.DataFrame, sample_rows: int = 3) -> dict:
    """Capture a DataFrame snapshot for tracing."""
    snap: dict[str, Any] = {
        "shape": list(df.shape),
        "columns": df.columns,
        "dtypes": [str(d) for d in df.dtypes],
    }
    if df.height > 0:
        sample = df.head(min(sample_rows, df.height))
        snap["sample"] = sample.to_dicts()
    return snap


# ============================================================
#  TraceRecorder
# ============================================================

class TraceRecorder:
    """Records a complete data flow trace with structured events.

    Args:
        name: Human-readable name for this trace session.
        capture_args: Whether to capture function arguments (default True).
        capture_results: Whether to capture return values (default True).
    """

    def __init__(
        self,
        name: str = "unnamed",
        capture_args: bool = True,
        capture_results: bool = True,
    ):
        self.name = name
        self.capture_args = capture_args
        self.capture_results = capture_results
        self.events: list[TraceEvent] = []
        self._seq = 0
        self._start_time = time.monotonic()
        self._start_wall = datetime.now(timezone.utc)

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    def _elapsed_ms(self) -> float:
        return round((time.monotonic() - self._start_time) * 1000, 2)

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat(timespec="milliseconds")

    # ── Core recording methods ──────────────────────────────

    def _record(self, event_type: EventType, **kwargs: Any) -> TraceEvent:
        event = TraceEvent(
            seq=self._next_seq(),
            event_type=event_type,
            timestamp=self._now_iso(),
            elapsed_ms=self._elapsed_ms(),
            **kwargs,
        )
        self.events.append(event)
        return event

    # ── Function tracing decorator ──────────────────────────

    def trace(self, func: Callable) -> Callable:
        """Decorator that records function calls, returns, and errors."""

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            call_args = {}
            if self.capture_args:
                try:
                    call_args = _safe_args(func, args, kwargs)
                except Exception:
                    call_args = {"_raw_args": _safe_repr(args), "_raw_kwargs": _safe_repr(kwargs)}

            self._record(
                EventType.CALL,
                function_name=func.__qualname__,
                args=call_args,
            )

            t0 = time.monotonic()
            try:
                result = func(*args, **kwargs)
                duration = round((time.monotonic() - t0) * 1000, 2)

                result_repr = _safe_repr(result) if self.capture_results else "<captured>"
                self._record(
                    EventType.RETURN,
                    function_name=func.__qualname__,
                    result=result_repr,
                    duration_ms=duration,
                )
                return result
            except Exception as exc:
                duration = round((time.monotonic() - t0) * 1000, 2)
                self._record(
                    EventType.ERROR,
                    function_name=func.__qualname__,
                    error=f"{type(exc).__name__}: {exc}",
                    traceback=tb_mod.format_exc(),
                    duration_ms=duration,
                )
                raise

        return wrapper

    # ── Tool use recording ──────────────────────────────────

    def record_tool_use(
        self,
        tool_name: str,
        tool_input: dict,
        tool_output: Any = None,
        error: Optional[str] = None,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Record a tool call (MCP-style tool_use event)."""
        self._record(
            EventType.TOOL_USE,
            function_name=tool_name,
            args=tool_input,
            result=_safe_repr(tool_output) if tool_output is not None else None,
            error=error,
            duration_ms=duration_ms,
        )

    def record_tool_result(
        self,
        tool_name: str,
        result: Any,
        is_error: bool = False,
    ) -> None:
        """Record a tool result (response from tool execution)."""
        self._record(
            EventType.TOOL_RESULT,
            function_name=tool_name,
            result=_safe_repr(result),
            error="tool returned error" if is_error else None,
        )

    # ── Shell command recording ─────────────────────────────

    def record_shell(
        self,
        command: str,
        stdout: str = "",
        stderr: str = "",
        returncode: int = 0,
        duration_ms: Optional[float] = None,
    ) -> None:
        """Record a shell command execution."""
        self._record(
            EventType.SHELL_CMD,
            function_name="shell",
            args={"command": command},
            result=stdout[:2000] if stdout else None,
            error=stderr[:2000] if stderr else None,
            duration_ms=duration_ms,
            metadata={
                "returncode": returncode,
                "stdout_len": len(stdout),
                "stderr_len": len(stderr),
            },
        )

    def run_shell(self, command: str, timeout: int = 30) -> dict:
        """Execute a shell command and record the trace. Returns result dict."""
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=timeout,
            )
            duration = round((time.monotonic() - t0) * 1000, 2)
            self.record_shell(
                command=command,
                stdout=proc.stdout,
                stderr=proc.stderr,
                returncode=proc.returncode,
                duration_ms=duration,
            )
            return {
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "returncode": proc.returncode,
                "duration_ms": duration,
            }
        except subprocess.TimeoutExpired:
            duration = round((time.monotonic() - t0) * 1000, 2)
            self._record(
                EventType.ERROR,
                function_name="shell",
                args={"command": command},
                error=f"TimeoutExpired after {timeout}s",
                duration_ms=duration,
            )
            return {"stdout": "", "stderr": f"timeout after {timeout}s", "returncode": -1, "duration_ms": duration}

    # ── Data flow recording ─────────────────────────────────

    def record_data_flow(
        self,
        stage: str,
        df_before: Optional[pl.DataFrame] = None,
        df_after: Optional[pl.DataFrame] = None,
        changes: Optional[dict] = None,
    ) -> None:
        """Record a data transformation step."""
        meta: dict[str, Any] = {}
        if df_before is not None:
            meta["before"] = _df_snapshot(df_before)
        if df_after is not None:
            meta["after"] = _df_snapshot(df_after)
        if changes:
            meta["changes"] = changes
        self._record(
            EventType.DATA_FLOW,
            function_name=stage,
            metadata=meta,
        )

    # ── Note recording ──────────────────────────────────────

    def note(self, message: str, metadata: Optional[dict] = None) -> None:
        """Add a freeform note to the trace."""
        self._record(
            EventType.NOTE,
            function_name="note",
            result=message,
            metadata=metadata or {},
        )

    # ── Export: JSONL ────────────────────────────────────────

    def to_jsonl(self) -> str:
        """Export trace as JSONL (one JSON object per line)."""
        header = json.dumps({
            "trace_name": self.name,
            "started_at": self._start_wall.isoformat(timespec="milliseconds"),
            "total_events": len(self.events),
            "version": "venus-pii-trace/0.1",
        }, ensure_ascii=False)
        lines = [header]
        for event in self.events:
            lines.append(json.dumps(event.to_dict(), ensure_ascii=False, default=str))
        return "\n".join(lines) + "\n"

    def save_jsonl(self, filepath: str) -> None:
        """Write trace to a JSONL file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_jsonl())

    # ── Export: Markdown ────────────────────────────────────

    def to_markdown(self) -> str:
        """Export trace as a human-readable Markdown document."""
        lines = [
            f"# Trace: {self.name}",
            "",
            f"- **Started**: {self._start_wall.isoformat(timespec='seconds')}",
            f"- **Events**: {len(self.events)}",
            f"- **Duration**: {self._elapsed_ms():.0f}ms",
            "",
            "---",
            "",
        ]

        for event in self.events:
            icon = _event_icon(event.event_type)
            ts = f"+{event.elapsed_ms:.0f}ms"
            lines.append(f"### {icon} #{event.seq} `{event.event_type.value}` [{ts}]")
            lines.append("")

            if event.function_name and event.function_name != "note":
                lines.append(f"**{event.function_name}**")
                lines.append("")

            if event.args:
                lines.append("```json")
                lines.append(json.dumps(event.args, ensure_ascii=False, indent=2, default=str))
                lines.append("```")
                lines.append("")

            if event.result is not None:
                lines.append(f"> Result: `{event.result}`")
                lines.append("")

            if event.error:
                lines.append(f"> ⚠ Error: `{event.error}`")
                lines.append("")

            if event.traceback:
                lines.append("<details><summary>Traceback</summary>")
                lines.append("")
                lines.append("```")
                lines.append(event.traceback)
                lines.append("```")
                lines.append("</details>")
                lines.append("")

            if event.duration_ms is not None:
                lines.append(f"*Duration: {event.duration_ms:.2f}ms*")
                lines.append("")

            if event.metadata:
                if event.event_type == EventType.DATA_FLOW:
                    lines.extend(_format_data_flow_md(event.metadata))
                elif event.event_type == EventType.SHELL_CMD:
                    rc = event.metadata.get("returncode", "?")
                    lines.append(f"*Exit code: {rc}*")
                    lines.append("")

            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    # ── Export: ASCII Timeline ──────────────────────────────

    def to_timeline(self) -> str:
        """Export trace as an ASCII timeline for terminal display."""
        lines = [
            f"{'='*60}",
            f"  TRACE: {self.name}",
            f"  Started: {self._start_wall.isoformat(timespec='seconds')}",
            f"  Events: {len(self.events)}",
            f"{'='*60}",
            "",
        ]

        for event in self.events:
            icon = _event_icon(event.event_type)
            ts = f"+{event.elapsed_ms:>8.1f}ms"
            tag = event.event_type.value.upper().ljust(12)

            header = f"  {ts} {icon} {tag}"
            if event.function_name and event.function_name != "note":
                header += f" {event.function_name}"
            lines.append(header)

            indent = "                          "
            if event.args:
                for k, v in event.args.items():
                    val = str(v)[:80]
                    lines.append(f"{indent}  {k}: {val}")

            if event.result is not None:
                r = str(event.result)[:120]
                lines.append(f"{indent}  -> {r}")

            if event.error:
                lines.append(f"{indent}  !! {event.error}")

            if event.duration_ms is not None:
                lines.append(f"{indent}  ({event.duration_ms:.2f}ms)")

            if event.metadata and event.event_type == EventType.DATA_FLOW:
                before = event.metadata.get("before", {})
                after = event.metadata.get("after", {})
                if before:
                    lines.append(f"{indent}  before: {before.get('shape', '?')} {before.get('columns', '?')}")
                if after:
                    lines.append(f"{indent}  after:  {after.get('shape', '?')} {after.get('columns', '?')}")

            lines.append("")

        lines.append(f"{'='*60}")
        return "\n".join(lines)

    # ── Context manager ─────────────────────────────────────

    def __enter__(self) -> TraceRecorder:
        self.note(f"Trace session '{self.name}' started")
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        if exc_type is not None:
            self._record(
                EventType.ERROR,
                function_name="session",
                error=f"{exc_type.__name__}: {exc_val}",
                traceback=tb_mod.format_exc(),
            )
        self.note(f"Trace session '{self.name}' ended ({len(self.events)} events)")

    def __repr__(self) -> str:
        return f"TraceRecorder(name={self.name!r}, events={len(self.events)})"


# ============================================================
#  Traced wrappers for venus-pii functions
# ============================================================

def traced_sanitize(
    df: pl.DataFrame,
    recorder: Optional[TraceRecorder] = None,
    reports: Optional[list] = None,
) -> Any:
    """Sanitize with full data flow tracing.

    Wraps venus_pii.sanitize() and records:
    - Input DataFrame snapshot
    - PII detection results
    - Each column's treatment (BLOCK/MASK/PASS)
    - Output DataFrame snapshot
    - Token maps generated
    """
    from venus_pii.guard import detect_pii_columns, sanitize, PIILevel

    if recorder is None:
        recorder = TraceRecorder("sanitize")

    recorder.note("Starting traced sanitize pipeline")
    recorder.record_data_flow("input", df_before=df)

    # Detection phase
    if reports is None:
        detect_start = time.monotonic()
        reports = detect_pii_columns(df)
        detect_duration = round((time.monotonic() - detect_start) * 1000, 2)
        recorder.record_tool_use(
            tool_name="detect_pii_columns",
            tool_input={"columns": df.columns, "row_count": df.height},
            tool_output={
                "reports": [
                    {"column": r.column_name, "category": r.category.value, "level": r.level.value, "confidence": r.confidence}
                    for r in reports
                ],
            },
            duration_ms=detect_duration,
        )

    # Log per-column decisions
    for report in reports:
        action = report.level.value.upper()
        recorder.note(
            f"Column '{report.column_name}': {report.category.value} -> {action}",
            metadata={"column": report.column_name, "category": report.category.value, "level": action, "confidence": report.confidence},
        )

    # Sanitize phase
    sanitize_start = time.monotonic()
    result = sanitize(df, reports=reports)
    sanitize_duration = round((time.monotonic() - sanitize_start) * 1000, 2)

    changes: dict[str, Any] = {
        "blocked_columns": result.blocked_columns,
        "masked_columns": list(result.token_maps.keys()),
        "token_map_sizes": {col: len(tmap) for col, tmap in result.token_maps.items()},
    }

    recorder.record_data_flow(
        stage="sanitize",
        df_before=df,
        df_after=result.sanitized_df,
        changes=changes,
    )

    recorder.record_tool_use(
        tool_name="sanitize",
        tool_input={"input_shape": list(df.shape)},
        tool_output={
            "output_shape": list(result.sanitized_df.shape),
            "blocked": result.blocked_columns,
            "masked": list(result.token_maps.keys()),
        },
        duration_ms=sanitize_duration,
    )

    return result, recorder


def traced_restore(
    df: pl.DataFrame,
    token_maps: dict[str, dict[str, str]],
    recorder: Optional[TraceRecorder] = None,
) -> tuple[pl.DataFrame, TraceRecorder]:
    """Restore with full data flow tracing."""
    from venus_pii.guard import restore

    if recorder is None:
        recorder = TraceRecorder("restore")

    recorder.note("Starting traced restore pipeline")
    recorder.record_data_flow("restore_input", df_before=df)

    restore_start = time.monotonic()
    restored = restore(df, token_maps)
    restore_duration = round((time.monotonic() - restore_start) * 1000, 2)

    recorder.record_data_flow(
        stage="restore",
        df_before=df,
        df_after=restored,
        changes={"restored_columns": list(token_maps.keys())},
    )

    recorder.record_tool_use(
        tool_name="restore",
        tool_input={"columns_to_restore": list(token_maps.keys())},
        tool_output={"output_shape": list(restored.shape)},
        duration_ms=restore_duration,
    )

    return restored, recorder


# ============================================================
#  Helpers
# ============================================================

def _event_icon(event_type: EventType) -> str:
    return {
        EventType.CALL: ">>",
        EventType.RETURN: "<<",
        EventType.ERROR: "!!",
        EventType.TOOL_USE: "=>",
        EventType.TOOL_RESULT: "<=",
        EventType.SHELL_CMD: "$>",
        EventType.DATA_FLOW: "<>",
        EventType.NOTE: "--",
    }.get(event_type, "??")


def _format_data_flow_md(metadata: dict) -> list[str]:
    """Format data flow metadata as Markdown."""
    lines: list[str] = []
    before = metadata.get("before", {})
    after = metadata.get("after", {})
    changes = metadata.get("changes", {})

    if before:
        lines.append(f"**Before**: {before.get('shape', '?')} columns={before.get('columns', '?')}")
    if after:
        lines.append(f"**After**: {after.get('shape', '?')} columns={after.get('columns', '?')}")
    if changes:
        if changes.get("blocked_columns"):
            lines.append(f"**Blocked**: {changes['blocked_columns']}")
        if changes.get("masked_columns"):
            lines.append(f"**Masked**: {changes['masked_columns']}")
        if changes.get("restored_columns"):
            lines.append(f"**Restored**: {changes['restored_columns']}")
    lines.append("")
    return lines
