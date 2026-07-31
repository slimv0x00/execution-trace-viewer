#!/usr/bin/env python3
"""Second-stage semantic filter for FISH VI row candidates.

This pass consumes the broad candidates from extract_fish_vi_slices.py and
keeps rows whose concrete values cross into a guest-semantic domain:

* guest stack/frame memory accesses,
* vSP/vBP architectural state updates,
* base+displacement address calculations for those memory accesses,
* guest-data arithmetic that reaches a guest memory write.

It deliberately excludes VM scratch writeback/restore rows even when those
rows carry the same concrete value.
"""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

from extract_fish_vi_slices import (
    MASK32,
    REG_INDEX,
    VALUE_MOVE_MNEMONICS,
    VALUE_OP_MNEMONICS,
    OperandType,
    build_model,
    build_windows,
    dst_vm_label,
    explicit_and_implicit_ops,
    explicit_ops,
    extract_candidates,
    extract_vi_row_candidates,
    is_vm_internal_addr,
    mem_operand_addr,
    parse_trace,
    reg_value,
    root_reg,
    run_lightfish,
)


KNOWN_SAMPLE_EXPECTED_VI = {
    48490,
    48580,
    50407,
    51331,
    51476,
    55062,
    55073,
    55084,
    56636,
    57339,
    60877,
    60925,
    60955,
    62913,
    67829,
    67840,
    67852,
    69453,
    70050,
    74010,
    74021,
    74032,
    75472,
    76602,
    80308,
    80353,
    80371,
    82479,
    85602,
    86726,
}


@dataclass(frozen=True)
class GuestActivation:
    vsp_label: str
    vbp_label: str
    start_row: int
    bp_set_row: int
    end_row: int
    base: int
    frame_lo: int
    frame_hi: int


@dataclass(frozen=True)
class SemanticSelection:
    rows: list[int]
    reasons: dict[int, list[str]]
    activation: GuestActivation
    endpoint_addrs: set[int]
    guest_read_values: set[int]
    guest_write_values: set[int]
    native_islands: list["NativeIsland"]
    semantic_seed_rows: set[int]
    address_decode_rows: set[int]


@dataclass(frozen=True)
class NativeIsland:
    target_write_row: int
    ret_row: int
    native_row: int
    vm_return_row: int | None


NATIVE_SEMANTIC_MNEMONICS = {
    "CDQ",
    "CWD",
    "CWDE",
    "CDQE",
    "DIV",
    "IDIV",
}

FRAME_FALLBACK_LABEL = "<stack-frame>"
FALLBACK_FRAME_OFFSETS = (-4, 0, 4, 8, 0xC, 0x10, 0x14, 0x18, 0x1C, 0x20)


def mnemonic(rows: list[dict], row_id: int) -> str:
    inst = rows[row_id].get("instruction_obj")
    return inst.mnemonic.upper() if inst else ""


def signed32(value: int) -> int:
    value &= MASK32
    return value if value < 0x80000000 else value - 0x100000000


def after_reg_value(rows: list[dict], row_id: int, reg_name: str) -> int | None:
    if row_id + 1 >= len(rows):
        return None
    regs = rows[row_id + 1].get("regs") or []
    idx = REG_INDEX.get(root_reg(reg_name))
    if idx is None or idx >= len(regs) or regs[idx] is None:
        return None
    return regs[idx] & MASK32


def dst_reg(row: dict) -> str | None:
    ops = explicit_ops(row)
    if ops and ops[0].type == OperandType.REG:
        return root_reg(ops[0].reg_name)
    return None


def output_value(rows: list[dict], row_id: int) -> int | None:
    reg = dst_reg(rows[row_id])
    if reg is None:
        return None
    return after_reg_value(rows, row_id, reg)


def source_value_for_store(row: dict) -> int | None:
    ops = explicit_ops(row)
    if len(ops) < 2:
        return None
    src = ops[1]
    if src.type == OperandType.REG:
        return reg_value(row, src.reg_name) & MASK32
    if src.type == OperandType.IMM:
        return src.imm_value & MASK32
    return None


def non_vm_mem_accesses(row: dict, model) -> list[tuple[object, int, str]]:
    accesses = []
    for op in explicit_and_implicit_ops(row):
        if op.type != OperandType.MEM:
            continue
        addr = mem_operand_addr(op, row)
        if addr is None or is_vm_internal_addr(model, addr):
            continue
        accesses.append((op, addr & MASK32, str(op.access).split(".")[-1]))
    return accesses


def raw_mem_reads(row: dict) -> list[tuple[int, int]]:
    reads = []
    for access in row.get("mem") or []:
        if access.get("access") != "READ":
            continue
        reads.append((access.get("addr", 0) & MASK32, access.get("value", 0) & MASK32))
    return reads


def raw_mem_writes(row: dict) -> list[tuple[int, int]]:
    writes = []
    for access in row.get("mem") or []:
        if access.get("access") != "WRITE":
            continue
        writes.append((access.get("addr", 0) & MASK32, access.get("value", 0) & MASK32))
    return writes


def source_reg_values(row: dict) -> list[tuple[str, int]]:
    values = []
    for op in explicit_ops(row):
        if op.type == OperandType.REG:
            values.append((root_reg(op.reg_name), reg_value(row, op.reg_name) & MASK32))
        elif op.type == OperandType.MEM:
            mem = op.mem_info or {}
            for reg_key in ("base", "index"):
                reg_name = mem.get(reg_key)
                if reg_name:
                    values.append((root_reg(reg_name), reg_value(row, reg_name) & MASK32))
    return values


def frame_addr_set(base: int) -> set[int]:
    return {((base + offset) & MASK32) for offset in FALLBACK_FRAME_OFFSETS}


def mentions_vmbblob_addr(row: dict, addr: int) -> bool:
    return f"vmblob_0x{addr & MASK32:x}" in (row.get("comment") or "").lower()


def mentions_any_frame_addr(row: dict, addrs: set[int]) -> bool:
    return any(mentions_vmbblob_addr(row, addr) for addr in addrs)


def reg_before_value(row: dict, reg_name: str) -> int | None:
    regs = row.get("regs") or []
    idx = REG_INDEX.get(root_reg(reg_name))
    if idx is None or idx >= len(regs) or regs[idx] is None:
        return None
    return regs[idx] & MASK32


def in_linear_range(value: int | None, lo: int, hi: int) -> bool:
    if value is None:
        return False
    return lo <= (value & MASK32) <= hi


def infer_vsp_label(rows: list[dict], vi_by_row: dict[int, object], model) -> str:
    counts: Counter[str] = Counter()
    for row_id in vi_by_row:
        label = dst_vm_label(rows[row_id], model)
        if not label:
            continue
        if mnemonic(rows, row_id) not in {"ADD", "SUB"}:
            continue
        ops = explicit_ops(rows[row_id])
        if len(ops) < 2 or ops[1].type != OperandType.IMM:
            continue
        imm = ops[1].imm_value & MASK32
        if imm in {4, 0xFFFFFFFC}:
            counts[label] += 1
    if not counts:
        raise RuntimeError("could not infer vSP label")
    return counts.most_common(1)[0][0]


def infer_stack_frame_fallback_activation(
    rows: list[dict],
    vi_by_row: dict[int, object],
    model,
    vsp_label: str,
    initial_esp: int,
) -> GuestActivation | None:
    # Black FISH variants can pass frame values through stack-staged VMBLOB
    # fetches instead of the red/white MOV-vBP + PUSH/POP prologue shape.
    # The protected x86 function still enters with a normal host ESP, so the
    # guest frame base is the post-call stack slot used by push-ebp prologues.
    base = (initial_esp - 8) & MASK32
    frame_lo = (base - 4) & MASK32
    frame_hi = (base + 0x20) & MASK32
    frame_addrs = frame_addr_set(base)
    near_lo = (frame_lo - 0x20) & MASK32
    near_hi = (frame_hi + 0x20) & MASK32

    def has_frame_mem(row: dict) -> bool:
        return any((addr & MASK32) in frame_addrs for _op, addr, _access in non_vm_mem_accesses(row, model))

    anchors: list[int] = []
    vsp_anchors: list[int] = []
    for row_id in vi_by_row:
        row = rows[row_id]
        mn = mnemonic(rows, row_id)
        comment = row.get("comment") or ""
        frame_mention = mentions_any_frame_addr(row, frame_addrs)
        frame_mem = has_frame_mem(row)

        if frame_mention or (frame_mem and "STACK_" not in comment):
            anchors.append(row_id)

        if dst_vm_label(row, model) != vsp_label:
            continue
        if mn not in {"ADD", "SUB", "INC", "DEC", "MOV", "POP"}:
            continue
        esp = reg_before_value(row, "ESP")
        if in_linear_range(esp, near_lo, near_hi) or frame_mention or frame_mem:
            vsp_anchors.append(row_id)

    if not anchors and not vsp_anchors:
        return None

    start_row = min(vsp_anchors) if vsp_anchors else min(anchors)
    end_candidates = [row_id for row_id in anchors + vsp_anchors if row_id >= start_row]
    if not end_candidates:
        return None

    return GuestActivation(
        vsp_label=vsp_label,
        vbp_label=FRAME_FALLBACK_LABEL,
        start_row=start_row,
        bp_set_row=start_row,
        end_row=max(end_candidates),
        base=base,
        frame_lo=frame_lo,
        frame_hi=frame_hi,
    )


def infer_activation(rows: list[dict], vi_by_row: dict[int, object], model, vsp_label: str) -> GuestActivation:
    initial_regs = rows[0].get("regs") or []
    initial_esp = initial_regs[REG_INDEX["ESP"]]
    initial_ebp = initial_regs[REG_INDEX["EBP"]]
    host_frame_base = (initial_esp - 8) & MASK32
    near_lo = min(initial_esp, initial_ebp) - 0x400
    near_hi = max(initial_esp, initial_ebp) + 0x400

    movs: dict[str, list[tuple[int, int]]] = defaultdict(list)
    pops: dict[str, list[tuple[int, int]]] = defaultdict(list)

    for row_id in vi_by_row:
        label = dst_vm_label(rows[row_id], model)
        if not label:
            continue
        mn = mnemonic(rows, row_id)
        if mn == "MOV":
            value = source_value_for_store(rows[row_id])
            if value is not None and near_lo <= value <= near_hi:
                movs[label].append((row_id, value))
        elif mn == "POP":
            read_addrs = [
                addr
                for _op, addr, access in non_vm_mem_accesses(rows[row_id], model)
                if access in {"READ", "READ_WRITE"}
            ]
            if read_addrs and near_lo <= read_addrs[0] <= near_hi:
                pops[label].append((row_id, read_addrs[0]))

    activation_candidates: list[tuple[float, int, str, int, int, int, int, dict[str, object]]] = []

    def candidate_semantic_score(label: str, start_row: int, bp_set_row: int, end_row: int, base: int) -> tuple[float, dict[str, object]]:
        base &= MASK32
        local_addr = (base - 4) & MASK32
        arg1_addr = (base + 8) & MASK32
        arg2_addr = (base + 0xC) & MASK32
        post_pop_sp = (base + 4) & MASK32

        first_arg1_read = None
        first_arg2_read = None
        first_local_write = None
        first_local_read = None
        vsp_base_write = None
        vsp_local_write = None
        vbp_restore = None

        upper = min(end_row, len(rows) - 1)
        for row_id in range(max(0, start_row), upper + 1):
            row = rows[row_id]
            for addr, _value in raw_mem_reads(row):
                if addr == arg1_addr and first_arg1_read is None:
                    first_arg1_read = row_id
                elif addr == arg2_addr and first_arg2_read is None:
                    first_arg2_read = row_id
                elif addr == local_addr and first_local_read is None:
                    first_local_read = row_id

            for addr, value in raw_mem_writes(row):
                if addr == local_addr and first_local_write is None:
                    first_local_write = row_id
                if model.vb_addr_map.get(addr) == vsp_label:
                    if value == base and vsp_base_write is None:
                        vsp_base_write = row_id
                    elif value == local_addr and vsp_local_write is None:
                        vsp_local_write = row_id
                if model.vb_addr_map.get(addr) == label and value == initial_ebp and vbp_restore is None:
                    vbp_restore = row_id

        score = 0.0
        if base == host_frame_base:
            score += 10000.0
        else:
            # v2 samples can produce plausible helper activations one slot off
            # from the source frame.  Keep them as candidates, but make the
            # host-call frame anchor dominate when present.
            score -= min(abs(signed32(base - host_frame_base)), 0x100) * 10.0

        if label != vsp_label:
            score += 3500.0
        else:
            # vSP and vBP being the same slot is possible as transient helper
            # traffic, but it is a weak source-level frame model.
            score -= 3500.0

        for marker in (first_arg1_read, first_arg2_read, first_local_write):
            if marker is not None:
                score += 2200.0
        if first_local_read is not None:
            score += 900.0
        if first_arg1_read is not None and first_arg2_read is not None and first_arg1_read < first_arg2_read:
            score += 800.0
        if first_local_write is not None and first_arg1_read is not None and first_local_write > first_arg1_read:
            score += 500.0
        if vsp_base_write is not None:
            score += 450.0
        if vsp_local_write is not None:
            score += 450.0
        if vbp_restore is not None:
            score += 450.0

        # Span remains a tie-breaker only.  The previous "largest span wins"
        # policy over-selected white v2 helper traffic before the real add body.
        score += min(max(end_row - start_row, 0), 100000) / 1000.0

        evidence = {
            "host_frame_base": host_frame_base,
            "local_addr": local_addr,
            "arg1_addr": arg1_addr,
            "arg2_addr": arg2_addr,
            "post_pop_sp": post_pop_sp,
            "first_arg1_read": first_arg1_read,
            "first_arg2_read": first_arg2_read,
            "first_local_write": first_local_write,
            "first_local_read": first_local_read,
            "vsp_base_write": vsp_base_write,
            "vsp_local_write": vsp_local_write,
            "vbp_restore": vbp_restore,
        }
        return score, evidence

    for label, stores in movs.items():
        for bp_set_row, bp_value in stores:
            prev_push = None
            for prev in range(bp_set_row - 1, max(-1, bp_set_row - 5000), -1):
                if prev not in vi_by_row or mnemonic(rows, prev) != "PUSH":
                    continue
                if any(
                    access == "WRITE" and addr == bp_value
                    for _op, addr, access in non_vm_mem_accesses(rows[prev], model)
                ):
                    prev_push = prev
                    break
            if prev_push is None:
                continue

            next_pop = None
            for pop_row, pop_addr in pops.get(label, []):
                if pop_row > bp_set_row and pop_addr == bp_value:
                    next_pop = pop_row
                    break
            if next_pop is None:
                continue

            span = next_pop - prev_push
            score, evidence = candidate_semantic_score(label, prev_push, bp_set_row, next_pop, bp_value)
            activation_candidates.append((score, span, label, prev_push, bp_set_row, next_pop, bp_value, evidence))

    if not activation_candidates:
        fallback = infer_stack_frame_fallback_activation(rows, vi_by_row, model, vsp_label, initial_esp)
        if fallback is not None:
            return fallback
        raise RuntimeError("could not infer guest frame activation")

    _score, _span, vbp_label, start_row, bp_set_row, end_row, base, _evidence = max(activation_candidates)
    return GuestActivation(
        vsp_label=vsp_label,
        vbp_label=vbp_label,
        start_row=start_row,
        bp_set_row=bp_set_row,
        end_row=end_row,
        base=base,
        frame_lo=(base - 0x100) & MASK32,
        frame_hi=(base + 0x100) & MASK32,
    )


def find_native_islands(rows: list[dict], activation: GuestActivation) -> list[NativeIsland]:
    islands: list[NativeIsland] = []
    for ret_row in range(activation.start_row, activation.end_row):
        if mnemonic(rows, ret_row) not in {"RET", "RETN"}:
            continue

        native_row = ret_row + 1
        if native_row >= len(rows):
            continue
        if mnemonic(rows, native_row) not in NATIVE_SEMANTIC_MNEMONICS:
            continue

        native_ip = rows[native_row].get("ip", 0) & MASK32
        ret_targets = [(addr, value) for addr, value in raw_mem_reads(rows[ret_row]) if value == native_ip]
        if not ret_targets:
            continue

        target_addr, target_value = ret_targets[0]
        target_write_row = None
        for prev in range(ret_row - 1, max(-1, ret_row - 1000), -1):
            if any(addr == target_addr and value == target_value for addr, value in raw_mem_writes(rows[prev])):
                target_write_row = prev
                break
        if target_write_row is None:
            continue

        vm_return_row = None
        for nxt in range(native_row + 1, min(len(rows), native_row + 10000)):
            if "VPC moved" in (rows[nxt].get("comment") or ""):
                vm_return_row = nxt
                break

        islands.append(
            NativeIsland(
                target_write_row=target_write_row,
                ret_row=ret_row,
                native_row=native_row,
                vm_return_row=vm_return_row,
            )
        )
    return islands


def select_semantic_rows(rows: list[dict], model, windows, vi_rows: list[object]) -> SemanticSelection:
    vi_by_row = {candidate.row: candidate for candidate in vi_rows}
    vsp_label = infer_vsp_label(rows, vi_by_row, model)
    activation = infer_activation(rows, vi_by_row, model, vsp_label)
    native_islands = find_native_islands(rows, activation)
    native_rows = {island.native_row for island in native_islands}
    native_bridge_rows: set[int] = set()
    for island in native_islands:
        bridge_end = island.vm_return_row if island.vm_return_row is not None else island.ret_row
        native_bridge_rows.update(range(island.target_write_row, bridge_end + 1))
    native_bridge_rows.difference_update(native_rows)
    fallback_frame = activation.vbp_label == FRAME_FALLBACK_LABEL
    selected: set[int] = set()
    semantic_seed_rows: set[int] = set()
    address_decode_rows: set[int] = set()
    reasons: dict[int, list[str]] = defaultdict(list)

    def select_row(row_id: int, reason: str, *, seed: bool = False, address_decode: bool = False) -> None:
        selected.add(row_id)
        reasons[row_id].append(reason)
        if seed:
            semantic_seed_rows.add(row_id)
        if address_decode:
            address_decode_rows.add(row_id)

    def in_activation(row_id: int) -> bool:
        return activation.start_row <= row_id <= activation.end_row

    def in_semantic_frame(value: int | None) -> bool:
        if value is None:
            return False
        value &= MASK32
        # Native bridge stubs use scratch stack slots below the guest frame.
        # Do not let those temporary slots become guest semantic endpoints.
        return ((activation.base - 4) & MASK32) <= value <= activation.frame_hi

    def is_base(value: int | None) -> bool:
        return value is not None and (value & MASK32) == activation.base

    def is_disp(value: int | None) -> bool:
        if value is None:
            return False
        disp = signed32(value)
        return disp != 0 and -0x40 <= disp <= 0x40

    def is_vsp_update(row_id: int) -> bool:
        return (
            dst_vm_label(rows[row_id], model) == activation.vsp_label
            and mnemonic(rows, row_id) in {"ADD", "SUB", "INC", "DEC"}
        )

    def is_vsp_absolute_write(row_id: int) -> bool:
        if dst_vm_label(rows[row_id], model) != activation.vsp_label:
            return False
        if mnemonic(rows, row_id) not in {"MOV", "POP"}:
            return False
        value = source_value_for_store(rows[row_id])
        return in_semantic_frame(value)

    def is_vbp_write(row_id: int) -> bool:
        if fallback_frame:
            return False
        return (
            row_id in {activation.bp_set_row, activation.end_row}
            and dst_vm_label(rows[row_id], model) == activation.vbp_label
            and mnemonic(rows, row_id) in {"MOV", "POP"}
        )

    window_by_row: dict[int, int] = {}
    for window in windows:
        for row_id in range(window.start, window.end + 1):
            window_by_row[row_id] = window.index

    vsp_update_windows = {
        window_by_row[row_id]
        for row_id in vi_by_row
        if in_activation(row_id) and row_id in window_by_row and is_vsp_update(row_id)
    }
    direct_frame_rows: set[int] = set()
    if not fallback_frame:
        for row_id in range(activation.start_row, activation.end_row + 1):
            if row_id in vi_by_row:
                continue
            if row_id in native_bridge_rows:
                continue
            mn = mnemonic(rows, row_id)
            if mn in {"RET", "RETN", "PUSH", "POP", "PUSHFD", "POPFD"}:
                continue
            if any(in_semantic_frame(addr) for _op, addr, _access in non_vm_mem_accesses(rows[row_id], model)):
                direct_frame_rows.add(row_id)

    semantic_candidate_rows = set(vi_by_row) | direct_frame_rows
    last_guest_push_by_slot: dict[tuple[int, int], int] = {}
    for row_id in vi_by_row:
        if not in_activation(row_id):
            continue
        if row_id in native_bridge_rows:
            continue
        if mnemonic(rows, row_id) != "PUSH":
            continue
        window_index = window_by_row.get(row_id)
        if window_index not in vsp_update_windows:
            continue
        for _op, addr, access in non_vm_mem_accesses(rows[row_id], model):
            if access in {"WRITE", "READ_WRITE"} and in_semantic_frame(addr):
                key = (window_index, addr)
                last_guest_push_by_slot[key] = max(row_id, last_guest_push_by_slot.get(key, -1))

    def is_last_guest_push(row_id: int, addr: int) -> bool:
        window_index = window_by_row.get(row_id)
        if window_index is None:
            return False
        return last_guest_push_by_slot.get((window_index, addr)) == row_id

    semantic_stack_windows: set[int] = set()
    for row_id in vi_by_row:
        if not in_activation(row_id):
            continue
        if row_id in native_bridge_rows:
            continue
        window_index = window_by_row.get(row_id)
        if window_index not in vsp_update_windows:
            continue
        mn = mnemonic(rows, row_id)
        for _op, addr, access in non_vm_mem_accesses(rows[row_id], model):
            if not in_semantic_frame(addr):
                continue
            if mn == "PUSH" and access in {"WRITE", "READ_WRITE"}:
                if is_last_guest_push(row_id, addr):
                    semantic_stack_windows.add(window_index)
            elif mn == "POP" and is_vbp_write(row_id) and access in {"READ", "READ_WRITE"}:
                semantic_stack_windows.add(window_index)
    if fallback_frame:
        semantic_stack_windows.update(vsp_update_windows)

    for row_id in semantic_candidate_rows:
        if not in_activation(row_id):
            continue
        if row_id in native_bridge_rows:
            continue
        mn = mnemonic(rows, row_id)

        if is_vsp_update(row_id) and window_by_row.get(row_id) in semantic_stack_windows:
            select_row(row_id, "vSP update", seed=True)

        if is_vsp_absolute_write(row_id):
            select_row(row_id, "vSP absolute write", seed=True)

        if is_vbp_write(row_id):
            select_row(row_id, "vBP write/pop", seed=True)

        for _op, addr, access in non_vm_mem_accesses(rows[row_id], model):
            if not in_semantic_frame(addr):
                continue
            if mn == "PUSH":
                if window_by_row.get(row_id) in semantic_stack_windows and is_last_guest_push(row_id, addr):
                    select_row(row_id, f"guest push {addr:#x}", seed=True)
            elif mn == "POP":
                if is_vbp_write(row_id):
                    select_row(row_id, f"guest pop {addr:#x}", seed=True)
            elif mn not in {"RET", "RETN", "PUSHFD", "POPFD"}:
                select_row(row_id, f"guest mem {access} {addr:#x}", seed=True)

    for native_row in sorted(native_rows):
        if in_activation(native_row):
            select_row(native_row, "native island VI", seed=True)

    endpoint_addrs: set[int] = set()
    for row_id in selected:
        for _op, addr, _access in non_vm_mem_accesses(rows[row_id], model):
            if in_semantic_frame(addr) and addr != activation.base:
                endpoint_addrs.add(addr)

    address_sink_rows: set[int] = set()
    for row_id in vi_by_row:
        if not in_activation(row_id):
            continue
        if row_id in native_bridge_rows:
            continue
        out = output_value(rows, row_id)
        if out is None or (out & MASK32) not in endpoint_addrs:
            continue
        src_values = source_reg_values(rows[row_id])
        has_base = any(is_base(value) for _reg, value in src_values)
        has_disp = any(is_disp(value) for _reg, value in src_values)
        if mnemonic(rows, row_id) not in {"ADD", "SUB", "LEA"} or not (has_base and has_disp):
            continue

        select_row(row_id, f"base+disp addr {out:#x}", seed=True)
        address_sink_rows.add(row_id)

    guest_read_values: set[int] = set()
    guest_write_values: set[int] = set()
    for row_id in set(selected):
        mn = mnemonic(rows, row_id)
        for _op, addr, access in non_vm_mem_accesses(rows[row_id], model):
            if not in_semantic_frame(addr):
                continue
            if access in {"READ", "READ_WRITE"} and mn not in {"PUSH", "POP", "RET", "RETN"}:
                out = output_value(rows, row_id)
                if out is not None:
                    guest_read_values.add(out & MASK32)
            if access in {"WRITE", "READ_WRITE"}:
                value = source_value_for_store(rows[row_id])
                if value is not None:
                    guest_write_values.add(value & MASK32)

    for row_id in vi_by_row:
        if not in_activation(row_id):
            continue
        if row_id in native_bridge_rows:
            continue
        if mnemonic(rows, row_id) not in VALUE_OP_MNEMONICS:
            continue
        ops = explicit_ops(rows[row_id])
        if any(op.type == OperandType.MEM for op in ops):
            continue
        out = output_value(rows, row_id)
        if out is None or (out & MASK32) not in guest_write_values:
            continue
        src_values = [reg_value(rows[row_id], op.reg_name) & MASK32 for op in ops if op.type == OperandType.REG]
        semantic_sources = sum(value in guest_read_values or value in guest_write_values for value in src_values)
        if len(src_values) >= 2 and semantic_sources >= 2:
            select_row(row_id, "guest data arithmetic", seed=True)

    for row_id in sorted(address_sink_rows):
        src_values = source_reg_values(rows[row_id])
        for reg, read_value in src_values:
            if not (is_base(read_value) or is_disp(read_value)):
                continue
            for prev in range(row_id - 1, activation.start_row - 1, -1):
                if prev not in vi_by_row:
                    continue
                if dst_reg(rows[prev]) != reg:
                    continue
                prev_out = output_value(rows, prev)
                if prev_out is None or (prev_out & MASK32) != read_value:
                    continue
                if mnemonic(rows, prev) in VALUE_OP_MNEMONICS | VALUE_MOVE_MNEMONICS:
                    select_row(prev, f"addr decode operand for {row_id}", address_decode=True)
                break

    return SemanticSelection(
        rows=sorted(selected),
        reasons=dict(reasons),
        activation=activation,
        endpoint_addrs=endpoint_addrs,
        guest_read_values=guest_read_values,
        guest_write_values=guest_write_values,
        native_islands=native_islands,
        semantic_seed_rows=semantic_seed_rows,
        address_decode_rows=address_decode_rows,
    )


def write_report(path: str, rows: list[dict], selection: SemanticSelection) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    activation = selection.activation
    lines = [
        "# FISH Semantic VI Filter",
        "",
        "## Inferred Activation",
        "",
        f"- vSP label: `{activation.vsp_label}`",
        f"- vBP label: `{activation.vbp_label}`",
        f"- Start row: `{activation.start_row}`",
        f"- vBP set row: `{activation.bp_set_row}`",
        f"- End row: `{activation.end_row}`",
        f"- Frame base: `{activation.base:#x}`",
        f"- Frame window: `{activation.frame_lo:#x}..{activation.frame_hi:#x}`",
        f"- Guest endpoint addresses: `{', '.join(hex(v) for v in sorted(selection.endpoint_addrs))}`",
        f"- Decoded semantic seeds: `{len(selection.semantic_seed_rows)}`",
        f"- Address decode operands: `{len(selection.address_decode_rows)}`",
    ]
    if selection.native_islands:
        lines.extend(
            [
                f"- Native islands: `{len(selection.native_islands)}`",
                "",
                "## Native Islands",
                "",
                "| Target Write | RET | Native VI | VM Return | Instruction |",
                "| ---: | ---: | ---: | ---: | --- |",
            ]
        )
        for island in selection.native_islands:
            native = rows[island.native_row]
            vm_return = "-" if island.vm_return_row is None else str(island.vm_return_row)
            lines.append(
                f"| {island.target_write_row} | {island.ret_row} | {island.native_row} | "
                f"{vm_return} | `{native.get('disasm', '')}` |"
            )
    lines.extend(
        [
            "",
            "## Selected Rows",
            "",
            f"- Count: {len(selection.rows)}",
            "",
            "| Row | IP | Instruction | Reason |",
            "| ---: | --- | --- | --- |",
        ]
    )
    for row_id in selection.rows:
        row = rows[row_id]
        reason = "; ".join(selection.reasons.get(row_id, [])) or "-"
        lines.append(f"| {row_id} | `{row.get('ip', 0):#x}` | `{row.get('disasm', '')}` | {reason} |")
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Refine FISH VI candidates using concrete semantic domains.")
    parser.add_argument("--trace", default="traces/themida_vm_add_fish_red_v3.0.3.0.trace32")
    parser.add_argument("--out", default="docs/mv_adimeht/trace_notes/fish_vi_semantic_filter.md")
    parser.add_argument("--vi-min-score", type=int, default=3)
    parser.add_argument("--quiet-lightfish", action="store_true")
    parser.add_argument("--check-known-sample", action="store_true")
    args = parser.parse_args()

    rows = parse_trace(args.trace)
    light = run_lightfish(rows, quiet=args.quiet_lightfish)
    model = build_model(rows, light)
    windows = build_windows(rows, model)
    candidates = extract_candidates(rows, model, windows)
    vi_rows = extract_vi_row_candidates(rows, model, windows, candidates, min_score=args.vi_min_score)
    selection = select_semantic_rows(rows, model, windows, vi_rows)
    write_report(args.out, rows, selection)

    print(f"selected={len(selection.rows)}")
    print(f"activation={selection.activation.start_row}-{selection.activation.end_row}")
    print(f"vSP={selection.activation.vsp_label}")
    print(f"vBP={selection.activation.vbp_label}")
    print(f"base={selection.activation.base:#x}")
    print(f"endpoint_addrs={','.join(hex(v) for v in sorted(selection.endpoint_addrs))}")
    if selection.native_islands:
        print(
            "native_islands="
            + ",".join(
                f"{island.ret_row}->{island.native_row}:{rows[island.native_row].get('disasm', '')}"
                for island in selection.native_islands
            )
        )
    if args.check_known_sample:
        selected = set(selection.rows)
        print(f"target_present={len(selected & KNOWN_SAMPLE_EXPECTED_VI)}/{len(KNOWN_SAMPLE_EXPECTED_VI)}")
        print(f"extra={len(selected - KNOWN_SAMPLE_EXPECTED_VI)}")
        if selected - KNOWN_SAMPLE_EXPECTED_VI:
            print("extra_rows=" + ",".join(str(v) for v in sorted(selected - KNOWN_SAMPLE_EXPECTED_VI)))
        if KNOWN_SAMPLE_EXPECTED_VI - selected:
            print("missing_rows=" + ",".join(str(v) for v in sorted(KNOWN_SAMPLE_EXPECTED_VI - selected)))
    print(f"wrote={args.out}")


if __name__ == "__main__":
    main()
