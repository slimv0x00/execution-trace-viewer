#!/usr/bin/env python3
"""Heuristic FISH VM virtual-instruction slice extractor.

The extractor intentionally does not consume pre-labeled VI rows.  It uses the
current LightFISH structural annotations to split dispatch windows, then finds
guest-visible sinks and backward-slices the concrete trace operands that feed
those sinks.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import capstone

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.trace_files import open_trace
from plugins.TraceAdimehtLightFISH import TraceAdimehtLightFISH
from plugins.TraceContext import TraceContext
from plugins.TraceInstruction import TraceInstruction
from plugins.TraceOperand import OperandAccess, OperandType


MASK32 = 0xFFFFFFFF
EBP_INDEX = 5

REG_SLICE = {
    "EAX": ("EAX", 0, 32),
    "AX": ("EAX", 0, 16),
    "AL": ("EAX", 0, 8),
    "AH": ("EAX", 8, 8),
    "EBX": ("EBX", 0, 32),
    "BX": ("EBX", 0, 16),
    "BL": ("EBX", 0, 8),
    "BH": ("EBX", 8, 8),
    "ECX": ("ECX", 0, 32),
    "CX": ("ECX", 0, 16),
    "CL": ("ECX", 0, 8),
    "CH": ("ECX", 8, 8),
    "EDX": ("EDX", 0, 32),
    "DX": ("EDX", 0, 16),
    "DL": ("EDX", 0, 8),
    "DH": ("EDX", 8, 8),
    "ESI": ("ESI", 0, 32),
    "SI": ("ESI", 0, 16),
    "EDI": ("EDI", 0, 32),
    "DI": ("EDI", 0, 16),
    "ESP": ("ESP", 0, 32),
    "SP": ("ESP", 0, 16),
    "EBP": ("EBP", 0, 32),
    "BP": ("EBP", 0, 16),
}

REG_INDEX = {
    "EAX": 0,
    "ECX": 1,
    "EDX": 2,
    "EBX": 3,
    "ESP": 4,
    "EBP": 5,
    "ESI": 6,
    "EDI": 7,
    "EIP": 8,
    "EFLAGS": 9,
}

JCC_MNEMONICS = {
    "JA",
    "JAE",
    "JB",
    "JBE",
    "JC",
    "JE",
    "JG",
    "JGE",
    "JL",
    "JLE",
    "JNA",
    "JNAE",
    "JNB",
    "JNBE",
    "JNC",
    "JNE",
    "JNG",
    "JNGE",
    "JNL",
    "JNLE",
    "JNO",
    "JNP",
    "JNS",
    "JNZ",
    "JO",
    "JP",
    "JPE",
    "JPO",
    "JS",
    "JZ",
}

CONTROL_FLOW_MNEMONICS = JCC_MNEMONICS | {"JMP", "CALL"}
FLAG_ONLY_MNEMONICS = {"CMP", "TEST"}
SEMANTIC_LOAD_MNEMONICS = {"MOV", "MOVZX", "MOVSX", "MOVSXD", "LEA", "POP"}
SMALL_SP_ARITH = {"ADD", "SUB", "INC", "DEC"}
VALUE_OP_MNEMONICS = {
    "ADD",
    "SUB",
    "XOR",
    "AND",
    "OR",
    "SHL",
    "SHR",
    "SAR",
    "IMUL",
    "MUL",
    "ROL",
    "ROR",
    "NOT",
    "NEG",
}
VALUE_MOVE_MNEMONICS = {"MOV", "MOVZX", "MOVSX", "MOVSXD", "LEA"}
STRUCTURAL_COMMENT_MARKERS = (
    "vpc stride",
    "VPC moved",
    "vhtp index",
    "load vhtp handler",
    "vmop :",
    "conditional branch",
)

VM_LABEL_RE = re.compile(r"\b(?:VB|VPC|VHTP|VMOP|VCH|VTABLE|VMBLOB)_0x[0-9a-fA-F]+\b|\bVTABLE\b")
STACK_TEMP_RE = re.compile(r"\bSTACK_0x([0-9a-fA-F]+)\b")
DECODE_RE = re.compile(r"\[decode\s*:\s*(0x[0-9a-fA-F]+)\]")
BRANCH_BY_RE = re.compile(r"conditional branch by (VB_0x[0-9a-fA-F]+|VMOP_0x[0-9a-fA-F]+|VHTP_0x[0-9a-fA-F]+|VPC_0x[0-9a-fA-F]+|VCH_0x[0-9a-fA-F]+|VTABLE)")

OVERSIZED_WINDOW_ROWS = 4096
OVERSIZED_SPLIT_MIN_GAP = 512
WINDOW_SINK_PRUNE_THRESHOLD = 512
SINK_KEEP_FIRST_PER_KEY = 1
SINK_KEEP_LAST_PER_KEY = 3


@dataclass(frozen=True)
class VMModel:
    vbr: int
    vpc_addr: int | None
    vhtp_addr: int | None
    vmop_addr: int | None
    vhtp_value: int | None
    vm_intervals: tuple[tuple[int, int], ...]
    vb_addr_map: dict[int, str]
    control_labels: set[str]
    guest_state_labels: set[str]


@dataclass
class AccessInfo:
    reads: set[str] = field(default_factory=set)
    writes: set[str] = field(default_factory=set)
    vm_labels: set[str] = field(default_factory=set)
    source_rows: set[int] = field(default_factory=set)


@dataclass
class Window:
    index: int
    start: int
    end: int
    decode_rows: list[int]
    fetch_rows: list[int]
    vpc_move_row: int | None


@dataclass
class SliceCandidate:
    window_index: int
    sink_row: int
    sink_kind: str
    sink_detail: str
    confidence: str
    score: int
    decoded_values: list[str]
    source_rows: list[int]
    slice_rows: list[int]


@dataclass
class VIRowCandidate:
    row: int
    confidence: str
    score: int
    reasons: list[str]
    window_indices: list[int]
    via_sinks: list[int]


def bitmask(bits: int) -> int:
    return (1 << bits) - 1


def reg_slice(reg_name: str | None) -> tuple[str, int, int]:
    return REG_SLICE.get((reg_name or "").upper(), ((reg_name or "").upper(), 0, 32))


def root_reg(reg_name: str | None) -> str:
    return reg_slice(reg_name)[0]


def reg_value(row: dict, reg_name: str) -> int:
    root, low, bits = reg_slice(reg_name)
    regs = row.get("regs") or []
    idx = REG_INDEX.get(root)
    if idx is None or idx >= len(regs) or regs[idx] is None:
        return 0
    return (regs[idx] >> low) & bitmask(bits)


def mem_operand_addr(op, row: dict) -> int | None:
    if op.type != OperandType.MEM:
        return None
    mem = op.mem_info or {}
    addr = mem.get("disp") or 0
    base = mem.get("base")
    index = mem.get("index")
    if base:
        addr += reg_value(row, base)
    if index:
        addr += reg_value(row, index) * (mem.get("scale") or 1)
    return addr & MASK32


def explicit_and_implicit_ops(row: dict) -> list:
    return list(row.get("parsed_operands") or [])


def explicit_ops(row: dict) -> list:
    return [op for op in row.get("parsed_operands") or [] if not op.is_implicit]


def parse_trace(path: str) -> list[dict]:
    trace_data = open_trace(path)
    if trace_data is None:
        raise RuntimeError(f"failed to open trace: {path}")
    rows = trace_data.trace
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    for row in rows:
        inst = TraceInstruction(row, md)
        row["parsed_operands"] = inst.get_operands()
        row["instruction_obj"] = inst
    return rows


def run_lightfish(rows: list[dict], quiet: bool) -> TraceAdimehtLightFISH:
    ctx_taint = TraceContext(arch_mode=32)
    ctx_adimeht = TraceContext(arch_mode=32)
    ctx_adimeht.cap_enabled = True

    def build() -> TraceAdimehtLightFISH:
        return TraceAdimehtLightFISH(ctx_adimeht, rows, ctx_taint=ctx_taint)

    if quiet:
        with contextlib.redirect_stdout(io.StringIO()):
            light = build()
    else:
        light = build()

    for row in rows:
        ctx_taint.load_register_state(row)
        in_vm = light.is_trace_in_vm(row)
        row["comment"] = "[VM]" if in_vm else ""
        light.process_instruction(row)
    return light


def parse_vm_labels(text: str) -> set[str]:
    return set(VM_LABEL_RE.findall(text or ""))


def parse_stack_temp_addrs(text: str) -> set[int]:
    return {int(value, 16) & MASK32 for value in STACK_TEMP_RE.findall(text or "")}


def row_decode_values(row: dict) -> list[str]:
    return DECODE_RE.findall(row.get("comment") or "")


def is_vm_row(row: dict, model: VMModel) -> bool:
    row_id = row.get("id")
    if row_id is not None and model.vm_intervals:
        return any(start <= row_id <= end for start, end in model.vm_intervals)
    regs = row.get("regs") or []
    return len(regs) > EBP_INDEX and regs[EBP_INDEX] == model.vbr


def label_for_addr(model: VMModel, addr: int) -> str | None:
    addr &= MASK32
    label = model.vb_addr_map.get(addr)
    if label is not None:
        return label
    if model.vhtp_value is not None and addr >= model.vhtp_value:
        off = addr - model.vhtp_value
        if off % 4 == 0 and 0 <= off // 4 < 0x1000:
            idx = off // 4
            return "VTABLE" if idx == 0 else f"VCH_0x{idx:x}"
    return None


def storage_for_mem(model: VMModel, addr: int, size: int) -> str:
    label = label_for_addr(model, addr)
    if label:
        return f"vm:{label}"
    return f"mem:{addr & MASK32:08x}:{size}"


def storage_for_reg(reg_name: str) -> str:
    return f"reg:{root_reg(reg_name)}"


def is_vm_internal_addr(model: VMModel, addr: int) -> bool:
    addr &= MASK32
    if addr in model.vb_addr_map:
        return True
    if model.vhtp_value is not None and model.vhtp_value <= addr < model.vhtp_value + 0x10000:
        return True
    return False


def access_info(row: dict, model: VMModel) -> AccessInfo:
    info = AccessInfo()
    comment = row.get("comment") or ""
    info.vm_labels |= parse_vm_labels(comment)
    if "[fetch" in comment or row_decode_values(row):
        info.source_rows.add(row["id"])

    for op in explicit_and_implicit_ops(row):
        if op.type == OperandType.REG:
            key = storage_for_reg(op.reg_name)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                info.reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                info.writes.add(key)
            continue

        if op.type == OperandType.MEM:
            mem = op.mem_info or {}
            for reg_key in ("base", "index"):
                reg_name = mem.get(reg_key)
                if reg_name:
                    info.reads.add(storage_for_reg(reg_name))

            addr = mem_operand_addr(op, row)
            if addr is None:
                continue
            label = label_for_addr(model, addr)
            if label is not None:
                info.vm_labels.add(label)
                info.source_rows.add(row["id"])
            key = storage_for_mem(model, addr, op.size)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                info.reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                info.writes.add(key)

    return info


def data_access_info(row: dict, model: VMModel) -> AccessInfo:
    """Accesses for semantic value slicing.

    VM slot/VHTP memory operands are treated as named values, so their concrete
    address-calculation registers are not pulled into the slice.  Concrete
    non-VM memory operands keep their address dependencies because those are
    guest-visible memory addresses.
    """
    info = AccessInfo()
    comment = row.get("comment") or ""
    info.vm_labels |= parse_vm_labels(comment)
    if "[fetch" in comment or row_decode_values(row):
        info.source_rows.add(row["id"])

    for op in explicit_and_implicit_ops(row):
        if op.type == OperandType.REG:
            key = storage_for_reg(op.reg_name)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                info.reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                info.writes.add(key)
            continue

        if op.type == OperandType.MEM:
            addr = mem_operand_addr(op, row)
            if addr is None:
                continue
            label = label_for_addr(model, addr)
            if label is not None:
                info.vm_labels.add(label)
                info.source_rows.add(row["id"])
            else:
                mem = op.mem_info or {}
                for reg_key in ("base", "index"):
                    reg_name = mem.get(reg_key)
                    if reg_name:
                        info.reads.add(storage_for_reg(reg_name))

            key = storage_for_mem(model, addr, op.size)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                info.reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                info.writes.add(key)

    return info


def infer_control_labels(rows: list[dict], light: TraceAdimehtLightFISH) -> set[str]:
    labels: set[str] = set()
    if light.vpc_slot is not None:
        labels.add(f"VPC_0x{light.vpc_slot:x}")
    if light.vhtp_slot is not None:
        labels.add(f"VHTP_0x{light.vhtp_slot:x}")
    if light.vmop_slot is not None:
        labels.add(f"VMOP_0x{light.vmop_slot:x}")

    for row in rows:
        comment = row.get("comment") or ""
        labels |= set(BRANCH_BY_RE.findall(comment))
        if "vhtp index" in comment or "vpc stride" in comment or "vpc move" in comment:
            labels |= {label for label in parse_vm_labels(comment) if not label.startswith("VMBLOB_")}
    return labels


def infer_guest_state_labels(rows: list[dict], model: VMModel) -> set[str]:
    labels: set[str] = set()
    for row in rows:
        if not is_vm_row(row, model):
            continue
        inst = row.get("instruction_obj")
        mnemonic = inst.mnemonic.upper() if inst else ""
        if mnemonic not in SMALL_SP_ARITH and mnemonic not in {"MOV", "POP"}:
            continue
        ops = explicit_ops(row)
        if not ops:
            continue
        dst = ops[0]
        if dst.type != OperandType.MEM or dst.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
            continue
        addr = mem_operand_addr(dst, row)
        if addr is None:
            continue
        label = model.vb_addr_map.get(addr)
        if not label:
            continue
        if len(ops) > 1 and ops[1].type == OperandType.IMM:
            imm = ops[1].imm_value & MASK32
            if (
                mnemonic in {"ADD", "SUB"}
                and (imm <= 8 or imm >= 0xFFFFFFF8)
                and not any(marker in (row.get("comment") or "") for marker in STRUCTURAL_COMMENT_MARKERS)
            ):
                labels.add(label)
        elif mnemonic in {"MOV", "POP"} and label not in model.control_labels:
            labels.add(label)
    return labels


def is_guest_state_write_row(row: dict, label: str, model: VMModel) -> bool:
    if label not in model.guest_state_labels:
        return False
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    ops = explicit_ops(row)
    if not ops:
        return False
    if label in model.control_labels and mnemonic not in {"ADD", "SUB", "INC", "DEC"}:
        return False
    if mnemonic in {"MOV", "POP"}:
        if len(ops) > 1 and ops[1].type == OperandType.IMM:
            return False
        return True
    if mnemonic in {"ADD", "SUB"} and len(ops) > 1 and ops[1].type == OperandType.IMM:
        imm = ops[1].imm_value & MASK32
        return imm <= 8 or imm >= 0xFFFFFFF8
    if mnemonic in {"INC", "DEC"}:
        return True
    return False


def build_model(rows: list[dict], light: TraceAdimehtLightFISH) -> VMModel:
    if light.vbr is None:
        raise RuntimeError("LightFISH could not detect VBR")
    control = infer_control_labels(rows, light)
    model = VMModel(
        vbr=light.vbr,
        vpc_addr=light.vbr + light.vpc_slot if light.vpc_slot is not None else None,
        vhtp_addr=light.vbr + light.vhtp_slot if light.vhtp_slot is not None else None,
        vmop_addr=light.vbr + light.vmop_slot if light.vmop_slot is not None else None,
        vhtp_value=light.vhtp_value,
        vm_intervals=tuple(light.vm_intervals),
        vb_addr_map={addr & MASK32: label for addr, label in light.vb_addr_map.items()},
        control_labels=control,
        guest_state_labels=set(),
    )
    model.guest_state_labels.update(infer_guest_state_labels(rows, model))
    return model


def build_windows(rows: list[dict], model: VMModel) -> list[Window]:
    windows: list[Window] = []
    current_start: int | None = None
    last_move: int | None = None
    decode_rows: list[int] = []
    fetch_rows: list[int] = []

    def close(end_row: int) -> None:
        nonlocal current_start, last_move, decode_rows, fetch_rows
        if current_start is None or end_row < current_start:
            return
        windows.append(
            Window(
                index=len(windows),
                start=current_start,
                end=end_row,
                decode_rows=list(decode_rows),
                fetch_rows=list(fetch_rows),
                vpc_move_row=last_move,
            )
        )
        current_start = None
        last_move = None
        decode_rows = []
        fetch_rows = []

    for row in rows:
        row_id = row["id"]
        in_vm = is_vm_row(row, model)
        if not in_vm:
            if current_start is not None:
                close(row_id - 1)
            continue

        comment = row.get("comment") or ""
        has_fetch = "[fetch" in comment
        has_decode = bool(row_decode_values(row))
        has_vpc_move = "[VPC moved" in comment

        if current_start is None and not (has_fetch or has_decode or has_vpc_move):
            continue

        if current_start is None:
            current_start = row_id

        if (
            current_start is not None
            and row_id > current_start
            and row_id - current_start + 1 > OVERSIZED_WINDOW_ROWS
            and row_id - current_start >= OVERSIZED_SPLIT_MIN_GAP
            and (has_fetch or has_decode)
        ):
            close(row_id - 1)
            current_start = row_id
            last_move = None
            decode_rows = []
            fetch_rows = []

        if "[fetch" in comment:
            fetch_rows.append(row_id)
        if has_decode:
            decode_rows.append(row_id)

        if has_vpc_move:
            close(row_id)
            current_start = row_id + 1
            last_move = row_id
            decode_rows = []
            fetch_rows = []

    if current_start is not None and rows:
        close(rows[-1]["id"])
    return [w for w in windows if w.start <= w.end]


def mem_write_operands(row: dict) -> list:
    return [
        op
        for op in explicit_and_implicit_ops(row)
        if op.type == OperandType.MEM and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE)
    ]


def mem_read_operands(row: dict) -> list:
    return [
        op
        for op in explicit_and_implicit_ops(row)
        if op.type == OperandType.MEM and op.access in (OperandAccess.READ, OperandAccess.READ_WRITE)
    ]


def written_regs(row: dict) -> set[str]:
    regs = set()
    for op in explicit_and_implicit_ops(row):
        if op.type == OperandType.REG and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
            regs.add(root_reg(op.reg_name))
    return regs


def sink_kinds(row: dict, model: VMModel) -> list[tuple[str, str]]:
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    comment = row.get("comment") or ""
    if not mnemonic or "[fetch" in comment or "VPC moved" in comment:
        return []
    if mnemonic in CONTROL_FLOW_MNEMONICS or mnemonic in FLAG_ONLY_MNEMONICS:
        return []
    if mnemonic in {"PUSHFD", "POPFD"}:
        return []

    stack_temp_addrs = parse_stack_temp_addrs(comment)

    result: list[tuple[str, str]] = []
    for op in mem_write_operands(row):
        addr = mem_operand_addr(op, row)
        if addr is None:
            continue
        if (addr & MASK32) in stack_temp_addrs:
            continue
        label = model.vb_addr_map.get(addr & MASK32)
        if label is not None:
            if is_guest_state_write_row(row, label, model):
                result.append(("guest_state_write", label))
            continue
        if not is_vm_internal_addr(model, addr):
            if mnemonic in {"PUSH", "CALL"}:
                result.append(("guest_stack_write", hex(addr)))
            else:
                result.append(("guest_mem_write", hex(addr)))

    if mnemonic in {"RET", "RETN"}:
        result.append(("guest_control_transfer", mnemonic.lower()))

    if mnemonic in SEMANTIC_LOAD_MNEMONICS and written_regs(row):
        for op in mem_read_operands(row):
            if op.is_implicit:
                continue
            addr = mem_operand_addr(op, row)
            if addr is None:
                continue
            if (addr & MASK32) in stack_temp_addrs:
                continue
            if is_vm_internal_addr(model, addr):
                continue
            if "[fetch" in comment or "VCH_" in comment or "VTABLE" in comment:
                continue
            result.append(("guest_mem_read", hex(addr)))

    return result


def backward_slice(rows: list[dict], model: VMModel, start: int, sink_row: int) -> list[int]:
    sink_info = access_info(rows[sink_row], model)
    needed = set(sink_info.reads)
    selected = {sink_row}

    for row_id in range(sink_row - 1, start - 1, -1):
        info = access_info(rows[row_id], model)
        hit = needed & info.writes
        if not hit:
            continue
        selected.add(row_id)
        needed -= hit
        needed |= info.reads

    return sorted(selected)


def source_rows_for_slice(rows: list[dict], model: VMModel, slice_rows: list[int]) -> list[int]:
    sources = set()
    for row_id in slice_rows:
        info = access_info(rows[row_id], model)
        sources |= info.source_rows
    return sorted(sources & set(slice_rows))


def confidence_for(score: int) -> str:
    if score >= 6:
        return "high"
    if score >= 3:
        return "medium"
    return "low"


def row_has_decoded_source(row: dict, model: VMModel) -> bool:
    info = access_info(row, model)
    if row_decode_values(row):
        return True
    if "[fetch" in (row.get("comment") or ""):
        return True
    return bool(info.vm_labels - model.control_labels)


def extract_candidates(rows: list[dict], model: VMModel, windows: list[Window]) -> list[SliceCandidate]:
    candidates: list[SliceCandidate] = []
    access_cache = [access_info(row, model) for row in rows]
    sink_cache = [sink_kinds(row, model) if is_vm_row(row, model) else [] for row in rows]

    def window_sink_items(window: Window) -> list[tuple[int, list[tuple[str, str]]]]:
        items = [
            (row_id, sink_cache[row_id])
            for row_id in range(window.start, window.end + 1)
            if sink_cache[row_id]
        ]
        if len(items) <= WINDOW_SINK_PRUNE_THRESHOLD:
            return items

        keyed_rows: dict[tuple[str, str], list[int]] = {}
        keep_rows: set[int] = set()
        for row_id, kinds in items:
            for kind, detail in kinds:
                if kind in {"guest_state_write", "guest_control_transfer"}:
                    keep_rows.add(row_id)
                    continue
                keyed_rows.setdefault((kind, detail), []).append(row_id)

        for row_ids in keyed_rows.values():
            keep_rows.update(row_ids[:SINK_KEEP_FIRST_PER_KEY])
            keep_rows.update(row_ids[-SINK_KEEP_LAST_PER_KEY:])

        pruned = []
        for row_id, kinds in items:
            if row_id not in keep_rows:
                continue
            kept_kinds = []
            for kind, detail in kinds:
                if kind in {"guest_state_write", "guest_control_transfer"}:
                    kept_kinds.append((kind, detail))
                    continue
                row_ids = keyed_rows.get((kind, detail), [])
                if row_id in set(row_ids[:SINK_KEEP_FIRST_PER_KEY]) | set(row_ids[-SINK_KEEP_LAST_PER_KEY:]):
                    kept_kinds.append((kind, detail))
            if kept_kinds:
                pruned.append((row_id, kept_kinds))
        return pruned

    def backward_slice_cached(start: int, sink_row: int) -> list[int]:
        sink_info = access_cache[sink_row]
        needed = set(sink_info.reads)
        selected = {sink_row}

        for row_id in range(sink_row - 1, start - 1, -1):
            info = access_cache[row_id]
            hit = needed & info.writes
            if not hit:
                continue
            selected.add(row_id)
            needed -= hit
            needed |= info.reads

        return sorted(selected)

    def source_rows_for_slice_cached(slice_rows: list[int]) -> list[int]:
        sources = set()
        for row_id in slice_rows:
            sources |= access_cache[row_id].source_rows
        return sorted(sources & set(slice_rows))

    def row_has_decoded_source_cached(row_id: int) -> bool:
        row = rows[row_id]
        info = access_cache[row_id]
        if row_decode_values(row):
            return True
        if "[fetch" in (row.get("comment") or ""):
            return True
        return bool(info.vm_labels - model.control_labels)

    for window in windows:
        if not window.decode_rows and not window.fetch_rows:
            continue
        decoded_values = []
        for row_id in window.decode_rows:
            decoded_values.extend(row_decode_values(rows[row_id]))
        for row_id, kinds in window_sink_items(window):
            row = rows[row_id]
            if not is_vm_row(row, model):
                continue
            slice_rows = backward_slice_cached(window.start, row_id)
            sources = source_rows_for_slice_cached(slice_rows)
            source_hit = any(row_has_decoded_source_cached(r) for r in slice_rows)
            if not source_hit:
                continue

            for kind, detail in kinds:
                score = 1
                if kind in {"guest_mem_write", "guest_stack_write", "guest_control_transfer"}:
                    score += 2
                if kind == "guest_state_write":
                    score += 1
                if kind == "guest_mem_read":
                    score += 1
                if decoded_values:
                    score += 2
                if sources:
                    score += 1
                if len(slice_rows) <= 8:
                    score += 1
                if any(row_decode_values(rows[r]) for r in slice_rows):
                    score += 1
                candidates.append(
                    SliceCandidate(
                        window_index=window.index,
                        sink_row=row_id,
                        sink_kind=kind,
                        sink_detail=detail,
                        confidence=confidence_for(score),
                        score=score,
                        decoded_values=decoded_values,
                        source_rows=sources,
                        slice_rows=slice_rows,
                    )
                )
    return candidates


def operand_value_reads(row: dict, op, model: VMModel) -> set[str]:
    reads: set[str] = set()
    if op.type == OperandType.REG:
        reads.add(storage_for_reg(op.reg_name))
        return reads
    if op.type != OperandType.MEM:
        return reads

    addr = mem_operand_addr(op, row)
    if addr is None:
        return reads
    if not is_vm_internal_addr(model, addr):
        mem = op.mem_info or {}
        for reg_key in ("base", "index"):
            reg_name = mem.get(reg_key)
            if reg_name:
                reads.add(storage_for_reg(reg_name))
    reads.add(storage_for_mem(model, addr, op.size))
    return reads


def architectural_state_labels(rows: list[dict], candidates: list[SliceCandidate]) -> set[str]:
    labels: set[str] = set()
    for candidate in candidates:
        if candidate.sink_kind != "guest_state_write":
            continue
        row = rows[candidate.sink_row]
        inst = row.get("instruction_obj")
        mnemonic = inst.mnemonic.upper() if inst else ""
        if mnemonic == "POP":
            labels.add(candidate.sink_detail)
        elif mnemonic in {"ADD", "SUB", "INC", "DEC"}:
            labels.add(candidate.sink_detail)
    return labels


def is_arch_state_effect_row(row: dict, label: str | None, arch_labels: set[str]) -> bool:
    if label is None or label not in arch_labels:
        return False
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    if mnemonic in {"POP", "ADD", "SUB", "INC", "DEC"}:
        return True
    if mnemonic == "MOV":
        return True
    return False


def dst_vm_label(row: dict, model: VMModel) -> str | None:
    ops = explicit_ops(row)
    if not ops:
        return None
    dst = ops[0]
    if dst.type != OperandType.MEM:
        return None
    addr = mem_operand_addr(dst, row)
    if addr is None:
        return None
    return model.vb_addr_map.get(addr & MASK32)


def is_generic_vm_writeback(row: dict, model: VMModel, arch_labels: set[str]) -> bool:
    label = dst_vm_label(row, model)
    if label is None or label in model.control_labels or label in arch_labels:
        return False
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    if mnemonic != "MOV":
        return False
    ops = explicit_ops(row)
    return len(ops) > 1 and ops[1].type == OperandType.REG


def focused_initial_needed(
    rows: list[dict],
    model: VMModel,
    candidate: SliceCandidate,
    arch_labels: set[str],
) -> set[str]:
    row = rows[candidate.sink_row]
    info = data_access_info(row, model)
    if candidate.sink_kind != "guest_state_write":
        return set(info.reads)

    if is_arch_state_effect_row(row, candidate.sink_detail, arch_labels):
        return set(info.reads)

    ops = explicit_ops(row)
    if len(ops) > 1:
        return operand_value_reads(row, ops[1], model)
    return set(info.reads)


def focused_backward_slice(
    rows: list[dict],
    model: VMModel,
    start: int,
    sink_row: int,
    needed: set[str],
) -> list[int]:
    selected = {sink_row}
    pending = set(needed)

    for row_id in range(sink_row - 1, start - 1, -1):
        info = data_access_info(rows[row_id], model)
        hit = pending & info.writes
        if not hit:
            continue
        selected.add(row_id)
        pending -= hit
        pending |= info.reads

    return sorted(selected)


def has_non_vm_mem_access(row: dict, model: VMModel) -> bool:
    for op in explicit_and_implicit_ops(row):
        if op.type != OperandType.MEM:
            continue
        addr = mem_operand_addr(op, row)
        if addr is None:
            continue
        if not is_vm_internal_addr(model, addr):
            return True
    return False


def is_pure_address_setup(row: dict) -> bool:
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    ops = explicit_ops(row)
    if len(ops) != 2:
        return False
    dst, src = ops
    if dst.type != OperandType.REG:
        return False
    if mnemonic == "MOV" and src.type == OperandType.REG and root_reg(src.reg_name) == "EBP":
        return True
    if mnemonic in {"ADD", "SUB"} and src.type == OperandType.IMM:
        imm = src.imm_value & MASK32
        small = imm <= 0x1000 or imm >= 0xFFFFF000
        return small and not parse_vm_labels(row.get("comment") or "")
    return False


def is_structural_row(row: dict) -> bool:
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    if mnemonic in CONTROL_FLOW_MNEMONICS or mnemonic in FLAG_ONLY_MNEMONICS:
        return True
    comment = row.get("comment") or ""
    return any(marker in comment for marker in STRUCTURAL_COMMENT_MARKERS)


def vi_row_score(
    rows: list[dict],
    model: VMModel,
    candidate: SliceCandidate,
    row_id: int,
    arch_labels: set[str],
) -> tuple[int, set[str]]:
    row = rows[row_id]
    if not is_vm_row(row, model) or is_structural_row(row):
        return 0, set()

    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    info = data_access_info(row, model)
    non_control_labels = info.vm_labels - model.control_labels
    score = 0
    reasons: set[str] = set()
    label = dst_vm_label(row, model)

    if row_id == candidate.sink_row:
        if candidate.sink_kind in {"guest_mem_write", "guest_stack_write", "guest_mem_read"}:
            score += 6
            reasons.add(candidate.sink_kind)
        elif candidate.sink_kind == "guest_control_transfer":
            score += 5
            reasons.add(candidate.sink_kind)
        elif candidate.sink_kind == "guest_state_write" and is_arch_state_effect_row(
            row, candidate.sink_detail, arch_labels
        ):
            score += 5
            reasons.add("architectural_state_effect")

    if is_generic_vm_writeback(row, model, arch_labels):
        return score, reasons

    if has_non_vm_mem_access(row, model):
        score += 4
        reasons.add("guest_memory_access")

    if is_pure_address_setup(row):
        return score, reasons

    if mnemonic in VALUE_OP_MNEMONICS and written_regs(row):
        score += 3
        reasons.add("value_op")
        if any(op.type == OperandType.IMM for op in explicit_ops(row)[1:]):
            score += 1
            reasons.add("immediate_operand")
        if non_control_labels:
            score += 1
            reasons.add("vm_value_operand")

    if mnemonic in VALUE_MOVE_MNEMONICS and written_regs(row):
        if has_non_vm_mem_access(row, model):
            score += 2
            reasons.add("value_load")
        elif non_control_labels and not any(label.startswith("VMBLOB_") for label in non_control_labels):
            score += 1
            reasons.add("vm_value_load")

    return score, reasons


def extract_vi_row_candidates(
    rows: list[dict],
    model: VMModel,
    windows: list[Window],
    candidates: list[SliceCandidate],
    min_score: int,
) -> list[VIRowCandidate]:
    arch_labels = architectural_state_labels(rows, candidates)
    window_by_index = {window.index: window for window in windows}
    aggregate: dict[int, dict] = {}

    for candidate in candidates:
        window = window_by_index.get(candidate.window_index)
        if window is None:
            continue
        needed = focused_initial_needed(rows, model, candidate, arch_labels)
        focused_rows = focused_backward_slice(rows, model, window.start, candidate.sink_row, needed)
        for row_id in focused_rows:
            score, reasons = vi_row_score(rows, model, candidate, row_id, arch_labels)
            if score < min_score or not reasons:
                continue
            item = aggregate.setdefault(
                row_id,
                {
                    "score": 0,
                    "reasons": set(),
                    "windows": set(),
                    "sinks": set(),
                },
            )
            item["score"] = max(item["score"], score)
            item["reasons"].update(reasons)
            item["windows"].add(candidate.window_index)
            item["sinks"].add(candidate.sink_row)

    result = []
    for row_id, item in aggregate.items():
        score = item["score"]
        result.append(
            VIRowCandidate(
                row=row_id,
                confidence=confidence_for(score),
                score=score,
                reasons=sorted(item["reasons"]),
                window_indices=sorted(item["windows"]),
                via_sinks=sorted(item["sinks"]),
            )
        )
    result.sort(key=lambda c: (c.row, -c.score))
    return result


def confidence_rank(value: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}[value]


def filter_candidates(
    candidates: list[SliceCandidate],
    min_confidence: str,
    row_start: int | None,
    row_end: int | None,
    kinds: set[str] | None,
) -> list[SliceCandidate]:
    min_rank = confidence_rank(min_confidence)
    result = [c for c in candidates if confidence_rank(c.confidence) >= min_rank]
    if row_start is not None:
        result = [c for c in result if c.sink_row >= row_start]
    if row_end is not None:
        result = [c for c in result if c.sink_row <= row_end]
    if kinds:
        result = [c for c in result if c.sink_kind in kinds]
    result.sort(key=lambda c: (-c.score, c.sink_row, c.sink_kind))
    return result


def short_comment(row: dict) -> str:
    comment = row.get("comment") or ""
    parts = [part.strip() for part in comment.split("|")]
    keep = []
    for part in parts:
        if part in {"[VM]", ""}:
            continue
        if (
            "[fetch" in part
            or "decode" in part
            or "VPC moved" in part
            or "conditional branch by" in part
            or VM_LABEL_RE.search(part)
        ):
            keep.append(part)
    return " | ".join(keep[:5])


def write_report(
    path: str,
    trace_path: str,
    rows: list[dict],
    model: VMModel,
    windows: list[Window],
    all_candidates: list[SliceCandidate],
    shown_candidates: list[SliceCandidate],
    vi_rows: list[VIRowCandidate],
    shown_vi_rows: list[VIRowCandidate],
) -> None:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for candidate in all_candidates:
        counts[candidate.confidence] = counts.get(candidate.confidence, 0) + 1

    lines = [
        "# FISH VI Slice Candidates",
        "",
        "## Source",
        "",
        f"- Trace file: `{trace_path}`",
        "- Method: VPC-window segmentation, guest-visible sink detection, and backward slicing.",
        "- Ground-truth `VI` labels are not used.",
        "",
        "## VM Model",
        "",
        f"- VBR: `{hex(model.vbr)}`",
        f"- VPC: `{hex(model.vpc_addr) if model.vpc_addr is not None else '-'}`",
        f"- VHTP: `{hex(model.vhtp_addr) if model.vhtp_addr is not None else '-'}`",
        f"- VMOP: `{hex(model.vmop_addr) if model.vmop_addr is not None else '-'}`",
        f"- VHTP value: `{hex(model.vhtp_value) if model.vhtp_value is not None else '-'}`",
        f"- VM intervals: `{', '.join(f'{start}..{end}' for start, end in model.vm_intervals) or '-'}`",
        f"- Control/scratch labels: `{', '.join(sorted(model.control_labels)) or '-'}`",
        f"- Guest-state label candidates: `{', '.join(sorted(model.guest_state_labels)) or '-'}`",
        "",
        "## Summary",
        "",
        f"- Windows: {len(windows)}",
        f"- All candidates: {len(all_candidates)}",
        f"- Shown candidates: {len(shown_candidates)}",
        f"- Confidence counts: high={counts.get('high', 0)}, medium={counts.get('medium', 0)}, low={counts.get('low', 0)}",
        f"- Filtered VI row candidates: {len(vi_rows)}",
        f"- Shown VI row candidates: {len(shown_vi_rows)}",
        "",
        "## Filtered VI Row Candidate Index",
        "",
        "| Row | Confidence | Score | Windows | Via sinks | Reasons | Instruction | Role hints |",
        "| ---: | --- | ---: | --- | --- | --- | --- | --- |",
    ]
    for c in shown_vi_rows:
        row = rows[c.row]
        windows_text = ", ".join(str(w) for w in c.window_indices) or "-"
        sinks_text = ", ".join(str(s) for s in c.via_sinks[:8])
        if len(c.via_sinks) > 8:
            sinks_text += ", ..."
        reasons = ", ".join(c.reasons) or "-"
        hint = short_comment(row).replace("|", "\\|") or "-"
        lines.append(
            f"| {c.row} | {c.confidence} | {c.score} | {windows_text} | {sinks_text or '-'} "
            f"| {reasons} | `{row.get('disasm', '')}` | {hint} |"
        )

    lines += [
        "",
        "## Candidate Index",
        "",
        "| Sink row | Confidence | Kind | Window | Decoded | Slice rows |",
        "| ---: | --- | --- | ---: | --- | --- |",
    ]
    for c in shown_candidates:
        decoded = ", ".join(dict.fromkeys(c.decoded_values)) or "-"
        slice_text = ", ".join(str(r) for r in c.slice_rows)
        lines.append(
            f"| {c.sink_row} | {c.confidence} ({c.score}) | {c.sink_kind} `{c.sink_detail}` "
            f"| {c.window_index} | {decoded} | {slice_text} |"
        )

    lines += ["", "## Candidate Details", ""]
    for c in shown_candidates:
        sink = rows[c.sink_row]
        decoded = ", ".join(dict.fromkeys(c.decoded_values)) or "-"
        sources = ", ".join(str(r) for r in c.source_rows) or "-"
        lines += [
            f"### Row {c.sink_row} - {c.sink_kind}",
            "",
            f"- Sink: `{sink.get('disasm', '')}` at `{hex(sink.get('ip', 0))}`",
            f"- Detail: `{c.sink_detail}`",
            f"- Window: {c.window_index}",
            f"- Decoded values in window: {decoded}",
            f"- Source rows in slice: {sources}",
            "",
            "| Row | IP | Instruction | Role hints |",
            "| ---: | --- | --- | --- |",
        ]
        for row_id in c.slice_rows:
            row = rows[row_id]
            hint = short_comment(row).replace("|", "\\|") or "-"
            lines.append(
                f"| {row_id} | `{hex(row.get('ip', 0))}` | `{row.get('disasm', '')}` | {hint} |"
            )
        lines.append("")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract heuristic FISH VM VI slice candidates.")
    parser.add_argument("--trace", default="traces/themida_vm_add_fish_red_v3.0.3.0.trace32")
    parser.add_argument("--out", default="docs/mv_adimeht/trace_notes/fish_vi_slice_candidates.md")
    parser.add_argument("--limit", type=int, default=120, help="maximum candidates to write; 0 means all")
    parser.add_argument("--min-confidence", choices=("low", "medium", "high"), default="medium")
    parser.add_argument(
        "--kind",
        action="append",
        choices=(
            "guest_control_transfer",
            "guest_mem_read",
            "guest_mem_write",
            "guest_stack_write",
            "guest_state_write",
        ),
        help="sink kind to include; may be passed multiple times",
    )
    parser.add_argument("--row-start", type=int)
    parser.add_argument("--row-end", type=int)
    parser.add_argument("--vi-min-score", type=int, default=3)
    parser.add_argument("--vi-limit", type=int, default=0, help="maximum filtered VI rows to write; 0 means all")
    parser.add_argument("--quiet-lightfish", action="store_true")
    args = parser.parse_args()

    rows = parse_trace(args.trace)
    light = run_lightfish(rows, quiet=args.quiet_lightfish)
    model = build_model(rows, light)
    windows = build_windows(rows, model)
    all_candidates = extract_candidates(rows, model, windows)
    vi_rows = extract_vi_row_candidates(rows, model, windows, all_candidates, min_score=args.vi_min_score)
    shown_candidates = filter_candidates(
        all_candidates,
        min_confidence=args.min_confidence,
        row_start=args.row_start,
        row_end=args.row_end,
        kinds=set(args.kind or []),
    )
    if args.limit > 0:
        shown_candidates = shown_candidates[: args.limit]
    shown_vi_rows = list(vi_rows)
    if args.row_start is not None:
        shown_vi_rows = [c for c in shown_vi_rows if c.row >= args.row_start]
    if args.row_end is not None:
        shown_vi_rows = [c for c in shown_vi_rows if c.row <= args.row_end]
    if args.vi_limit > 0:
        shown_vi_rows = shown_vi_rows[: args.vi_limit]

    write_report(
        args.out,
        args.trace,
        rows,
        model,
        windows,
        all_candidates,
        shown_candidates,
        vi_rows,
        shown_vi_rows,
    )
    counts: dict[str, int] = {}
    for candidate in all_candidates:
        counts[candidate.confidence] = counts.get(candidate.confidence, 0) + 1
    print(f"windows={len(windows)}")
    print(f"candidates={len(all_candidates)}")
    print(f"confidence=high:{counts.get('high', 0)}, medium:{counts.get('medium', 0)}, low:{counts.get('low', 0)}")
    print(f"vi_rows={len(vi_rows)}")
    print(f"shown_vi_rows={len(shown_vi_rows)}")
    print(f"shown={len(shown_candidates)}")
    print(f"wrote={args.out}")


if __name__ == "__main__":
    main()
