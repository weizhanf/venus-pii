#!/usr/bin/env python3
"""
venus-pii trace demo — See everything the AI pipeline does to your data.

Run:
    python examples/trace_demo.py

This script demonstrates the full data flow trace:
1. Input DataFrame with PII (names, ID cards, scores)
2. Traced sanitize: detection → BLOCK/MASK/PASS decisions → tokenization
3. Traced restore: token → original value
4. Shell command tracing
5. Custom function tracing with @trace decorator
6. Export as JSONL, Markdown, and ASCII timeline
"""

import polars as pl
from venus_pii.trace import TraceRecorder, traced_sanitize, traced_restore


def main():
    print("=" * 60)
    print("  venus-pii trace demo")
    print("  Your data. Your key. Your rules. Your trace.")
    print("=" * 60)
    print()

    # ── 1. Create a DataFrame with PII ──────────────────────

    df = pl.DataFrame({
        "姓名": ["张三", "李四", "王五"],
        "身份证号": ["110101200001011234", "110101200002021234", "110101200003031234"],
        "phone": ["13800138001", "13900139001", "13700137001"],
        "邮箱": ["zhang@example.com", "li@example.com", "wang@example.com"],
        "score": [85, 92, 78],
    })

    print("Input DataFrame:")
    print(df)
    print()

    # ── 2. Traced sanitize ──────────────────────────────────

    rec = TraceRecorder("full-pipeline-demo")

    # Trace a custom function
    @rec.trace
    def validate_input(dataframe: pl.DataFrame) -> bool:
        """Validate that DataFrame has required columns."""
        has_data = dataframe.height > 0
        has_columns = len(dataframe.columns) > 0
        return has_data and has_columns

    validate_input(df)

    # Run traced sanitize
    result, rec = traced_sanitize(df, recorder=rec)

    print("Sanitized DataFrame:")
    print(result.sanitized_df)
    print(f"\nBlocked columns: {result.blocked_columns}")
    print(f"Token maps: {list(result.token_maps.keys())}")
    print()

    # ── 3. Traced restore ───────────────────────────────────

    restored, rec = traced_restore(result.sanitized_df, result.token_maps, recorder=rec)

    print("Restored DataFrame:")
    print(restored)
    print()

    # ── 4. Shell command tracing ────────────────────────────

    rec.run_shell("echo 'venus-pii trace is working'")
    rec.run_shell("python --version")

    # ── 5. Simulate a tool call ─────────────────────────────

    rec.record_tool_use(
        tool_name="llm_api_call",
        tool_input={"model": "claude-sonnet", "prompt": "Analyze this data..."},
        tool_output={"response": "Analysis complete", "tokens_used": 150},
        duration_ms=1234.5,
    )

    # ── 6. Export all formats ───────────────────────────────

    print("\n" + "=" * 60)
    print("  ASCII TIMELINE")
    print("=" * 60)
    print(rec.to_timeline())

    print("\n" + "=" * 60)
    print("  MARKDOWN (first 80 lines)")
    print("=" * 60)
    md = rec.to_markdown()
    for line in md.split("\n")[:80]:
        print(line)

    print("\n" + "=" * 60)
    print("  JSONL (first 5 events)")
    print("=" * 60)
    jsonl = rec.to_jsonl()
    for i, line in enumerate(jsonl.split("\n")[:6]):
        print(line)

    # Save full trace
    rec.save_jsonl("/tmp/venus_trace_demo.jsonl")
    print(f"\nFull trace saved to /tmp/venus_trace_demo.jsonl")
    print(f"Total events recorded: {len(rec.events)}")
    print()


if __name__ == "__main__":
    main()
