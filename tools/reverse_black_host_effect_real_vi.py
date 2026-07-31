#!/usr/bin/env python3
"""Experimental reverse host-effect real-VI selector for black FISH traces.

This is intentionally separate from the current LightFISH endpoint-slice path.
It reuses black frame/vSP/vBP/arg-taint inference, but treats host/guest boundary
effects as sinks and adds a small reverse dependency model for implicit x86
operands such as ``cdq`` -> ``idiv``.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
TOOLS = ROOT / "tools"
if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))

from extract_fish_vi_slices import MASK32, OperandAccess, OperandType, parse_trace, root_reg, run_lightfish  # noqa: E402


@dataclass
class Access:
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)


@dataclass
class ReverseSelection:
    trace_name: str
    rows: set[int]
    buckets: dict[str, set[int]]
    sinks: dict[str, set[int]]
    reverse_candidates: set[int]
    frame: dict[str, Any]


def reg_storage(reg_name: str | None) -> str:
    return f"reg:{root_reg(reg_name)}"


def addr_storage(light: Any, addr: int) -> str:
    addr &= MASK32
    label = getattr(light, "vb_addr_map", {}).get(addr)
    if label:
        return f"vm:{label}"
    return f"mem:{addr:08x}"


def row_mnemonic(light: Any, row: dict) -> str:
    return light._trace_mnemonic(row)


def mem_operand_addr(light: Any, op: Any, row: dict) -> int | None:
    return light._trace_mem_operand_addr(op, row)


def row_access(light: Any, row: dict) -> Access:
    access = Access()

    for addr, _value in light._raw_reads(row):
        access.reads.add(addr_storage(light, addr))
    for addr, _value in light._raw_writes(row):
        access.writes.add(addr_storage(light, addr))

    for op in row.get("parsed_operands") or []:
        if op.type == OperandType.REG:
            key = reg_storage(op.reg_name)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                access.reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                access.writes.add(key)
            continue

        if op.type != OperandType.MEM:
            continue

        addr = mem_operand_addr(light, op, row)
        if addr is None:
            continue
        label = getattr(light, "vb_addr_map", {}).get(addr & MASK32)

        # Address dependencies are important for host/guest boundary memory,
        # but pulling VBR-relative VM-slot address registers into every slice
        # makes dispatch internals dominate the result.
        if label is None:
            mem = op.mem_info or {}
            for reg_key in ("base", "index"):
                reg_name = mem.get(reg_key)
                if reg_name:
                    access.reads.add(reg_storage(reg_name))

        key = addr_storage(light, addr)
        if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
            access.reads.add(key)
        if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
            access.writes.add(key)

    mnemonic = row_mnemonic(light, row)
    if mnemonic in {"CDQ", "CWD"}:
        access.reads.add("reg:EAX")
        access.writes.add("reg:EDX")
    elif mnemonic in {"DIV", "IDIV"}:
        access.reads.update({"reg:EAX", "reg:EDX"})
        access.writes.update({"reg:EAX", "reg:EDX"})
    elif mnemonic == "MUL":
        access.reads.add("reg:EAX")
        access.writes.update({"reg:EAX", "reg:EDX"})
    elif mnemonic == "IMUL":
        explicit = [op for op in (row.get("parsed_operands") or []) if not op.is_implicit]
        if len(explicit) == 1:
            access.reads.add("reg:EAX")
            access.writes.update({"reg:EAX", "reg:EDX"})

    return access


def reverse_slice(accesses: list[Access], start: int, sink_row: int) -> set[int]:
    needed = set(accesses[sink_row].reads)
    selected = {sink_row}

    for row_id in range(sink_row - 1, max(start, 0) - 1, -1):
        hit = needed & accesses[row_id].writes
        if not hit:
            continue
        selected.add(row_id)
        needed -= hit
        needed |= accesses[row_id].reads

    return selected


def add_forward_tainted_materialization(
    light: Any,
    rows: list[dict],
    records: list[dict],
    buckets: dict[str, set[int]],
    seed_row: int,
    labels: set[str],
    bucket: str,
) -> None:
    light._add_tainted_forward_materialization(rows, records, buckets, seed_row, labels, bucket)


def infer_frame_and_records(light: Any, rows: list[dict]) -> tuple[dict[str, Any], list[dict]] | None:
    base_frame = light._black_base_frame(rows)
    if base_frame is None:
        return None
    stack_roles = light._infer_black_stack_roles(rows, base_frame)
    if stack_roles is None or stack_roles.get("semantic_start") is None:
        return None

    semantic_end = stack_roles.get("semantic_end")
    if semantic_end is None:
        semantic_end = len(rows) - 1

    frame = {
        **base_frame,
        "vbp_label": stack_roles["vbp_label"],
        "vsp_label": stack_roles["vsp_label"],
        "vbp_addr": stack_roles["vbp_addr"],
        "vsp_addr": stack_roles["vsp_addr"],
        "semantic_start": stack_roles["semantic_start"],
        "bp_set_row": stack_roles.get("bp_set_row"),
        "semantic_end": min(semantic_end, len(rows) - 1),
        "semantic_end_inferred": stack_roles.get("semantic_end"),
    }
    records = light._black_taint_replay(rows, frame, replay_end=len(rows) - 1)
    return frame, records


def add_previous_stack_store(light: Any, rows: list[dict], buckets: dict[str, set[int]], frame: dict, row_id: int, value: int) -> None:
    light._add_previous_stack_store(rows, buckets, frame, row_id, value, "context")


def add_previous_tainted_stack_store(
    light: Any,
    rows: list[dict],
    records: list[dict],
    buckets: dict[str, set[int]],
    frame: dict,
    row_id: int,
    labels: set[str],
) -> None:
    light._add_previous_tainted_stack_store(rows, records, buckets, frame, row_id, labels, "result")


def select_reverse_host_effect_rows(rows: list[dict], light: Any, trace_name: str) -> ReverseSelection | None:
    inferred = infer_frame_and_records(light, rows)
    if inferred is None:
        return None
    frame, records = inferred

    start = frame["semantic_start"]
    end = frame["semantic_end"]
    result_labels = {"arg_1", "arg_2"}

    buckets: dict[str, set[int]] = defaultdict(set)
    sinks: dict[str, set[int]] = defaultdict(set)
    first_arg1_row = None
    first_arg2_row = None
    local_save_row = None
    zero_row = None
    result_store_row = None
    result_store_value = None
    result_read_row = None
    result_arith_candidates: list[int] = []

    if isinstance(start, int):
        buckets["context"].add(start)
        sinks["context"].add(start)
    if isinstance(frame.get("bp_set_row"), int):
        buckets["context"].add(frame["bp_set_row"])
        sinks["context"].add(frame["bp_set_row"])
    if isinstance(frame.get("semantic_end_inferred"), int):
        buckets["context"].add(frame["semantic_end_inferred"])
        sinks["context"].add(frame["semantic_end_inferred"])

    for row_id in range(start, end + 1):
        row = rows[row_id]
        record = records[row_id]
        mnemonic = row_mnemonic(light, row)

        if light._writes_label(row, frame["vbp_label"]):
            if light._has_write(row, frame["vbp_addr"], frame["frame_base"]):
                buckets["context"].add(row_id)
                sinks["context"].add(row_id)
            elif (
                light._has_write(row, frame["vbp_addr"], frame["caller_ebp"])
                and light._has_read(row, frame["saved_ebp_addr"], frame["caller_ebp"])
            ):
                buckets["context"].add(row_id)
                sinks["context"].add(row_id)

        if light._writes_label(row, frame["vsp_label"]):
            if light._has_write(row, frame["vsp_addr"], frame["local_addr"]):
                buckets["context"].add(row_id)
                sinks["boundary"].add(row_id)
            elif light._has_write(row, frame["vsp_addr"], frame["post_pop_sp"]):
                buckets["context"].add(row_id)
                sinks["context"].add(row_id)
            elif light._has_write(row, frame["vsp_addr"], frame["frame_base"]):
                # vSP can transiently hold frame-base during setup/helper
                # traffic.  Treat it as ``mov esp, ebp`` only after result
                # readback confirms we are in teardown.
                pass

        if light._has_write(row, frame["local_addr"], 0) and light._has_non_esp_explicit_write(row, frame["local_addr"]):
            buckets["boundary"].add(row_id)
            sinks["boundary"].add(row_id)
            if zero_row is None:
                zero_row = row_id

        local_write_value = light._black_first_write_value(row, frame["local_addr"])
        if (
            local_save_row is None
            and local_write_value is not None
            and local_write_value != 0
            and local_write_value == frame.get("caller_ecx")
            and frame.get("bp_set_row") is not None
            and row_id > frame["bp_set_row"]
            and (zero_row is None or row_id < zero_row)
            and light._black_reads_plain_vb_operand(row, exclude={frame["vbp_label"], frame["vsp_label"]})
        ):
            buckets["context"].add(row_id)
            sinks["boundary"].add(row_id)
            local_save_row = row_id

        if light._black_record_reads_addr_label(record, frame["arg1_addr"], "arg_1"):
            buckets["boundary"].add(row_id)
            sinks["boundary"].add(row_id)
            if first_arg1_row is None:
                first_arg1_row = row_id
            add_forward_tainted_materialization(light, rows, records, buckets, row_id, {"arg_1"}, "boundary")

        if light._black_record_reads_addr_label(record, frame["arg2_addr"], "arg_2"):
            buckets["boundary"].add(row_id)
            sinks["boundary"].add(row_id)
            if first_arg2_row is None:
                first_arg2_row = row_id
            add_forward_tainted_materialization(light, rows, records, buckets, row_id, {"arg_2"}, "boundary")

        if (
            mnemonic in {"ADD", "SUB", "IMUL", "MUL", "DIV", "IDIV"}
            and not light._black_reads_vm_slot_operand(row)
            and (
                light._black_record_writes_labels(record, result_labels, reg_only=True)
                or (
                    mnemonic in {"DIV", "IDIV"}
                    and any(read_addr == frame["arg2_addr"] for read_addr, _value in light._raw_reads(row))
                )
            )
        ):
            result_arith_candidates.append(row_id)

        if light._black_record_writes_addr_labels(record, frame["local_addr"], result_labels):
            if result_store_row is None and light._has_non_esp_explicit_write(row, frame["local_addr"]):
                buckets["result"].add(row_id)
                sinks["boundary"].add(row_id)
                result_store_row = row_id
                result_store_value = light._black_first_write_value(row, frame["local_addr"])
                add_previous_tainted_stack_store(light, rows, records, buckets, frame, row_id, result_labels)

        local_result_read = (
            light._black_record_reads_addr_label(record, frame["local_addr"], "arg_1")
            and light._black_record_reads_addr_label(record, frame["local_addr"], "arg_2")
        )
        if not local_result_read and result_store_value is not None:
            local_result_read = light._has_read(row, frame["local_addr"], result_store_value)
        if local_result_read and result_store_row is not None and result_read_row is None and row_id > result_store_row:
            buckets["result"].add(row_id)
            sinks["boundary"].add(row_id)
            result_read_row = row_id
            if result_store_value is not None:
                light._add_forward_materialization(rows, buckets, frame, row_id, result_store_value, "result")
            else:
                add_forward_tainted_materialization(light, rows, records, buckets, row_id, result_labels, "result")

    arithmetic_row = None
    if first_arg1_row is not None and first_arg2_row is not None:
        arg_ready_row = max(first_arg1_row, first_arg2_row)
        arithmetic_limit = min(
            value
            for value in (result_store_row, result_read_row, end)
            if value is not None and value >= arg_ready_row
        )
        matching = [
            row_id
            for row_id in result_arith_candidates
            if arg_ready_row <= row_id <= arithmetic_limit
            and (
                result_store_value is None
                or light._black_arithmetic_output_value(rows, row_id) == result_store_value
            )
        ]
        if not matching:
            matching = [
                row_id
                for row_id in result_arith_candidates
                if arg_ready_row <= row_id <= arithmetic_limit
            ]
        arithmetic_row = matching[0] if matching else None

    accesses = [row_access(light, row) for row in rows]
    reverse_candidates: set[int] = set()
    for row_ids in sinks.values():
        for sink_row in sorted(row_ids):
            reverse_candidates |= reverse_slice(accesses, start, sink_row)

    if arithmetic_row is not None:
        buckets["arithmetic"].add(arithmetic_row)
        sinks["arithmetic"].add(arithmetic_row)
        arithmetic_slice = reverse_slice(accesses, start, arithmetic_row)
        reverse_candidates |= arithmetic_slice
        light._add_black_arithmetic_materialization(rows, records, buckets, frame, arithmetic_row)

        if row_mnemonic(light, rows[arithmetic_row]) in {"DIV", "IDIV"}:
            cdq_rows = [
                row_id
                for row_id in arithmetic_slice
                if start <= row_id < arithmetic_row and row_mnemonic(light, rows[row_id]) in {"CDQ", "CWD"}
            ]
            if not cdq_rows:
                lower = first_arg1_row if first_arg1_row is not None else start
                cdq_rows = [
                    row_id
                    for row_id in range(lower, arithmetic_row)
                    if row_mnemonic(light, rows[row_id]) in {"CDQ", "CWD"}
                ]
            if cdq_rows:
                buckets["arithmetic"].add(cdq_rows[-1])

    if result_read_row is not None:
        restore_vsp_row = None
        for row_id in range(result_read_row + 1, end + 1):
            row = rows[row_id]
            if not (
                light._writes_label(row, frame["vsp_label"])
                and light._has_write(row, frame["vsp_addr"], frame["frame_base"])
            ):
                continue
            buckets["context"].add(row_id)
            sinks["context"].add(row_id)
            add_previous_stack_store(light, rows, buckets, frame, row_id, frame["frame_base"])
            restore_vsp_row = row_id
            break

        for row_id in range(result_read_row + 1, end + 1):
            row = rows[row_id]
            if not (
                row_mnemonic(light, row) == "PUSH"
                and light._reads_label(row, frame["vbp_label"])
                and light._has_read(row, frame["vbp_addr"], frame["frame_base"])
            ):
                continue
            buckets["context"].add(row_id)
            sinks["context"].add(row_id)
            if restore_vsp_row is not None and row_id < restore_vsp_row:
                light._add_forward_materialization(rows, buckets, frame, row_id, frame["frame_base"], "context")

    # Host/native sinks are trusted only after a concrete result store has been
    # observed.  This avoids truncated-tail helper rows in div v3.0.3.0.
    if result_store_value is not None:
        result_search_start = max(
            value
            for value in (end + 1, result_read_row or 0, result_store_row or 0)
            if value is not None
        )
        for row_id in range(result_search_start, len(rows)):
            row = rows[row_id]
            if row_mnemonic(light, row) != "PUSH":
                continue
            if not any(read_value == result_store_value for _addr, read_value in light._raw_reads(row)):
                continue
            buckets["native"].add(row_id)
            sinks["native"].add(row_id)
            light._add_forward_materialization(rows, buckets, frame, row_id, result_store_value, "native", lookahead=8)
            break

        native_exit = None
        for wanted in ("MOV", "POP"):
            for row_id in range(result_search_start, len(rows)):
                row = rows[row_id]
                if row_mnemonic(light, row) != wanted:
                    continue
                ops = [op for op in (row.get("parsed_operands") or []) if not op.is_implicit]
                if not ops or ops[0].type != OperandType.REG or root_reg(ops[0].reg_name) != "EAX":
                    continue
                if wanted == "MOV" and len(ops) < 2:
                    continue
                if not any(read_value == result_store_value for _addr, read_value in light._raw_reads(row)):
                    continue
                if light._after_reg_value(rows, row_id, "EAX") != result_store_value:
                    continue
                native_exit = row_id
                break
            if native_exit is not None:
                buckets["native"].add(native_exit)
                sinks["native"].add(native_exit)
                reverse_candidates |= reverse_slice(accesses, start, native_exit)
                break

    selected: set[int] = set()
    for row_ids in buckets.values():
        selected.update(row_ids)

    return ReverseSelection(
        trace_name=trace_name,
        rows=selected,
        buckets={key: set(value) for key, value in buckets.items()},
        sinks={key: set(value) for key, value in sinks.items()},
        reverse_candidates=reverse_candidates,
        frame=frame,
    )


def manual_rows_for_trace(trace_path: Path) -> list[int]:
    doc = ROOT / "docs/mv_adimeht/trace_notes/recovered_arithmetic_samples" / f"{trace_path.stem}.md"
    text = doc.read_text()
    match = re.search(r"Manual row list: (.*)", text)
    if not match:
        raise RuntimeError(f"manual row list not found: {doc}")
    return [int(value) for value in re.findall(r"`(\d+)`", match.group(1))]


def run_trace(trace_path: Path) -> tuple[ReverseSelection, list[int]]:
    rows = parse_trace(str(trace_path))
    light = run_lightfish(rows, quiet=True)
    with contextlib.redirect_stdout(io.StringIO()):
        selection = select_reverse_host_effect_rows(rows, light, trace_path.name)
    if selection is None:
        raise RuntimeError(f"reverse selection failed: {trace_path}")
    return selection, manual_rows_for_trace(trace_path)


def format_row_list(rows: list[int] | set[int]) -> str:
    values = sorted(rows)
    return "-" if not values else ", ".join(f"`{value}`" for value in values)


def build_report(results: list[tuple[ReverseSelection, list[int]]]) -> str:
    lines: list[str] = [
        "# Black Reverse Host-Effect Real-VI Comparison",
        "",
        f"- Generated: `{date.today().isoformat()}`",
        "- Tool: `tools/reverse_black_host_effect_real_vi.py`",
        "- Baseline: per-sample manual row lists under `recovered_arithmetic_samples/`",
        "",
        "## Summary",
        "",
        "| Trace | Reverse rows | Manual rows | Overlap | Missing | Extra | Result |",
        "| --- | ---: | ---: | ---: | --- | --- | --- |",
    ]

    total_reverse = total_manual = total_overlap = total_missing = total_extra = exact = 0
    for selection, manual in results:
        reverse = set(selection.rows)
        manual_set = set(manual)
        missing = sorted(manual_set - reverse)
        extra = sorted(reverse - manual_set)
        overlap = len(reverse & manual_set)
        is_exact = not missing and not extra
        exact += int(is_exact)
        total_reverse += len(reverse)
        total_manual += len(manual_set)
        total_overlap += overlap
        total_missing += len(missing)
        total_extra += len(extra)
        lines.append(
            f"| `{selection.trace_name}` | {len(reverse)} | {len(manual_set)} | {overlap} | "
            f"{format_row_list(missing)} | {format_row_list(extra)} | {'exact' if is_exact else 'mismatch'} |"
        )

    lines.extend(
        [
            "",
            "Totals:",
            "",
            f"- Reverse selected rows: `{total_reverse}`",
            f"- Manual baseline rows: `{total_manual}`",
            f"- Overlap rows: `{total_overlap}`",
            f"- Missing rows: `{total_missing}`",
            f"- Extra rows: `{total_extra}`",
            f"- Exact sample matches: `{exact} / {len(results)}`",
            "",
            "## Bucket Counts",
            "",
            "| Trace | Buckets | Sink counts | Reverse candidate rows |",
            "| --- | --- | --- | ---: |",
        ]
    )

    for selection, _manual in results:
        buckets = ", ".join(f"{key}={len(value)}" for key, value in sorted(selection.buckets.items()))
        sinks = ", ".join(f"{key}={len(value)}" for key, value in sorted(selection.sinks.items()))
        lines.append(
            f"| `{selection.trace_name}` | {buckets or '-'} | {sinks or '-'} | {len(selection.reverse_candidates)} |"
        )

    lines.extend(
        [
            "",
            "## Notes",
            "",
            "- `idiv` is modeled as reading `EDX:EAX`; this lets the reverse slice include the preceding `cdq` row.",
            "- Native `EAX` materialization is accepted only after a concrete result store to the guest local/result slot is observed.",
            "- Native result sinks are therefore ignored unless the trace contains a preceding concrete result commit.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("traces", nargs="*", type=Path)
    parser.add_argument("--all-black", action="store_true", help="run every black arithmetic trace under traces/")
    parser.add_argument("--write-report", type=Path)
    args = parser.parse_args()

    trace_paths = list(args.traces)
    if args.all_black:
        trace_paths = sorted((ROOT / "traces").glob("themida_vm_*_fish_black_*.trace32"))
    if not trace_paths:
        parser.error("provide trace paths or --all-black")

    results: list[tuple[ReverseSelection, list[int]]] = []
    for trace_path in trace_paths:
        print(f"[reverse-host-effect] {trace_path.name}", flush=True)
        selection, manual = run_trace(trace_path)
        results.append((selection, manual))
        reverse = set(selection.rows)
        manual_set = set(manual)
        print(
            f"  selected={len(reverse)} manual={len(manual_set)} "
            f"overlap={len(reverse & manual_set)} "
            f"missing={sorted(manual_set - reverse)} extra={sorted(reverse - manual_set)}",
            flush=True,
        )

    report = build_report(results)
    if args.write_report:
        args.write_report.write_text(report)
        print(f"[reverse-host-effect] wrote {args.write_report}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
