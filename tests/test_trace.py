"""Tests for venus_pii.trace — AI Agent Data Flow Tracer"""

import json
import polars as pl
import pytest

from venus_pii.trace import (
    TraceRecorder,
    EventType,
    traced_sanitize,
    traced_restore,
    _safe_repr,
    _df_snapshot,
)


# ── TraceRecorder basics ────────────────────────────────────


def test_recorder_init():
    rec = TraceRecorder("test-session")
    assert rec.name == "test-session"
    assert len(rec.events) == 0


def test_recorder_repr():
    rec = TraceRecorder("demo")
    assert "demo" in repr(rec)
    assert "events=0" in repr(rec)


def test_note_recording():
    rec = TraceRecorder("notes")
    rec.note("hello world")
    assert len(rec.events) == 1
    assert rec.events[0].event_type == EventType.NOTE
    assert rec.events[0].result == "hello world"


def test_sequential_numbering():
    rec = TraceRecorder()
    rec.note("a")
    rec.note("b")
    rec.note("c")
    assert [e.seq for e in rec.events] == [1, 2, 3]


# ── Function tracing ───────────────────────────────────────


def test_trace_decorator_captures_call_and_return():
    rec = TraceRecorder("func-trace")

    @rec.trace
    def add(a, b):
        return a + b

    result = add(3, 4)
    assert result == 7
    assert len(rec.events) == 2
    assert rec.events[0].event_type == EventType.CALL
    assert rec.events[0].function_name == "test_trace_decorator_captures_call_and_return.<locals>.add"
    assert rec.events[1].event_type == EventType.RETURN
    assert rec.events[1].duration_ms is not None


def test_trace_decorator_captures_error():
    rec = TraceRecorder("error-trace")

    @rec.trace
    def fail():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        fail()

    assert len(rec.events) == 2
    assert rec.events[1].event_type == EventType.ERROR
    assert "ValueError: boom" in rec.events[1].error
    assert rec.events[1].traceback is not None


def test_trace_captures_args():
    rec = TraceRecorder()

    @rec.trace
    def greet(name, greeting="hello"):
        return f"{greeting} {name}"

    greet("world")
    call_event = rec.events[0]
    assert "name" in call_event.args
    assert "'world'" in call_event.args["name"]


# ── Tool use recording ─────────────────────────────────────


def test_record_tool_use():
    rec = TraceRecorder()
    rec.record_tool_use(
        tool_name="advisor_inbox",
        tool_input={"content": "test idea"},
        tool_output={"status": "saved", "id": "123"},
        duration_ms=5.0,
    )
    assert len(rec.events) == 1
    assert rec.events[0].event_type == EventType.TOOL_USE
    assert rec.events[0].function_name == "advisor_inbox"
    assert rec.events[0].args == {"content": "test idea"}


def test_record_tool_result():
    rec = TraceRecorder()
    rec.record_tool_result("search", result={"count": 3}, is_error=False)
    assert rec.events[0].event_type == EventType.TOOL_RESULT
    assert rec.events[0].error is None


def test_record_tool_result_error():
    rec = TraceRecorder()
    rec.record_tool_result("search", result="not found", is_error=True)
    assert rec.events[0].error == "tool returned error"


# ── Shell command recording ─────────────────────────────────


def test_record_shell():
    rec = TraceRecorder()
    rec.record_shell(
        command="echo hello",
        stdout="hello\n",
        stderr="",
        returncode=0,
        duration_ms=10.0,
    )
    assert len(rec.events) == 1
    assert rec.events[0].event_type == EventType.SHELL_CMD
    assert rec.events[0].args == {"command": "echo hello"}
    assert rec.events[0].metadata["returncode"] == 0


def test_run_shell():
    rec = TraceRecorder()
    result = rec.run_shell("echo hi")
    assert result["returncode"] == 0
    assert "hi" in result["stdout"]
    assert len(rec.events) == 1
    assert rec.events[0].event_type == EventType.SHELL_CMD


def test_run_shell_error():
    rec = TraceRecorder()
    result = rec.run_shell("exit 1")
    assert result["returncode"] == 1


# ── Data flow recording ────────────────────────────────────


def test_record_data_flow():
    rec = TraceRecorder()
    df = pl.DataFrame({"name": ["Alice", "Bob"], "score": [90, 85]})
    rec.record_data_flow("input", df_before=df)
    assert len(rec.events) == 1
    assert rec.events[0].event_type == EventType.DATA_FLOW
    assert rec.events[0].metadata["before"]["shape"] == [2, 2]
    assert rec.events[0].metadata["before"]["columns"] == ["name", "score"]


# ── Context manager ────────────────────────────────────────


def test_context_manager():
    with TraceRecorder("ctx-test") as rec:
        rec.note("inside context")
    assert len(rec.events) == 3  # start note, user note, end note


def test_context_manager_with_error():
    try:
        with TraceRecorder("ctx-err") as rec:
            raise RuntimeError("test error")
    except RuntimeError:
        pass
    error_events = [e for e in rec.events if e.event_type == EventType.ERROR]
    assert len(error_events) == 1
    assert "RuntimeError" in error_events[0].error


# ── Export: JSONL ──────────────────────────────────────────


def test_to_jsonl():
    rec = TraceRecorder("jsonl-test")
    rec.note("test event")
    jsonl = rec.to_jsonl()
    lines = jsonl.strip().split("\n")
    assert len(lines) == 2  # header + 1 event
    header = json.loads(lines[0])
    assert header["trace_name"] == "jsonl-test"
    assert header["total_events"] == 1
    event = json.loads(lines[1])
    assert event["event_type"] == "note"


def test_save_jsonl(tmp_path):
    rec = TraceRecorder("save-test")
    rec.note("persist me")
    filepath = str(tmp_path / "trace.jsonl")
    rec.save_jsonl(filepath)
    with open(filepath, "r") as f:
        content = f.read()
    assert "persist me" in content


# ── Export: Markdown ────────────────────────────────────────


def test_to_markdown():
    rec = TraceRecorder("md-test")
    rec.note("hello markdown")
    rec.record_tool_use("test_tool", {"key": "val"})
    md = rec.to_markdown()
    assert "# Trace: md-test" in md
    assert "hello markdown" in md
    assert "test_tool" in md


def test_to_markdown_with_error():
    rec = TraceRecorder()

    @rec.trace
    def bad():
        raise ValueError("nope")

    try:
        bad()
    except ValueError:
        pass

    md = rec.to_markdown()
    assert "ValueError: nope" in md
    assert "Traceback" in md


# ── Export: Timeline ────────────────────────────────────────


def test_to_timeline():
    rec = TraceRecorder("timeline-test")
    rec.note("step 1")
    rec.record_shell("ls", stdout="file.txt", returncode=0)
    tl = rec.to_timeline()
    assert "TRACE: timeline-test" in tl
    assert "NOTE" in tl
    assert "SHELL_CMD" in tl


# ── Traced sanitize pipeline ──────────────────────────────


def test_traced_sanitize():
    df = pl.DataFrame({
        "姓名": ["张三", "李四"],
        "身份证号": ["110101200001011234", "110101200002021234"],
        "score": [85, 92],
    })
    result, rec = traced_sanitize(df)

    # Verify sanitization worked
    assert "身份证号" not in result.sanitized_df.columns
    assert "身份证号" in result.blocked_columns
    names = result.sanitized_df["姓名"].to_list()
    assert all(n.startswith("PERSON_") for n in names)
    assert result.sanitized_df["score"].to_list() == [85, 92]

    # Verify trace captured everything
    assert len(rec.events) > 0
    event_types = {e.event_type for e in rec.events}
    assert EventType.NOTE in event_types
    assert EventType.TOOL_USE in event_types
    assert EventType.DATA_FLOW in event_types


def test_traced_sanitize_with_existing_recorder():
    df = pl.DataFrame({"name": ["Alice"]})
    rec = TraceRecorder("shared")
    rec.note("pre-existing event")
    result, same_rec = traced_sanitize(df, recorder=rec)
    assert same_rec is rec
    assert len(rec.events) > 1  # pre-existing + traced events


def test_traced_sanitize_exports():
    """Verify traced sanitize produces valid JSONL and Markdown."""
    df = pl.DataFrame({"姓名": ["张三"], "score": [85]})
    result, rec = traced_sanitize(df)

    jsonl = rec.to_jsonl()
    for line in jsonl.strip().split("\n"):
        json.loads(line)  # all lines must be valid JSON

    md = rec.to_markdown()
    assert "# Trace:" in md

    tl = rec.to_timeline()
    assert "TRACE:" in tl


# ── Traced restore pipeline ────────────────────────────────


def test_traced_restore():
    df = pl.DataFrame({"姓名": ["张三", "李四"], "score": [85, 92]})
    result, _ = traced_sanitize(df)

    restored, rec = traced_restore(result.sanitized_df, result.token_maps)
    assert restored["姓名"].to_list() == ["张三", "李四"]
    assert len(rec.events) > 0
    event_types = {e.event_type for e in rec.events}
    assert EventType.DATA_FLOW in event_types


# ── Helper functions ────────────────────────────────────────


def test_safe_repr_dataframe():
    df = pl.DataFrame({"a": [1, 2]})
    r = _safe_repr(df)
    assert "DataFrame" in r
    assert "2" in r


def test_safe_repr_truncation():
    long_str = "x" * 1000
    r = _safe_repr(long_str)
    assert len(r) < 600
    assert "chars" in r


def test_df_snapshot():
    df = pl.DataFrame({"x": [1, 2, 3], "y": ["a", "b", "c"]})
    snap = _df_snapshot(df)
    assert snap["shape"] == [3, 2]
    assert snap["columns"] == ["x", "y"]
    assert len(snap["sample"]) == 3


def test_df_snapshot_empty():
    df = pl.DataFrame({"x": pl.Series([], dtype=pl.Int64)})
    snap = _df_snapshot(df)
    assert snap["shape"] == [0, 1]
    assert "sample" not in snap
