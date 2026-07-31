#!/usr/bin/env python3
"""Independent VMBLOB fetch auditor for the Themida FISH trace.

This script deliberately separates two concerns:

1. Candidate fetch enumeration and current comments are taken from the current
   LightFISH plugin output. This is only the list of rows to audit.
2. Propagation, role detection, and kill points are computed by a separate
   one-label dataflow over the raw trace, Capstone operands, and concrete
   register/memory values. The LightFISH runtime state is not used for the
   verdict.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
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


VBR = 0x4545B8
VPC_ADDR = 0x454617
VHTP_VALUE = 0x444988
VMOP_ADDR = 0x45466D
MASK32 = 0xFFFFFFFF

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

FLAG_MNEMONICS = {
    "CMP",
    "TEST",
    "ADD",
    "SUB",
    "XOR",
    "OR",
    "AND",
    "ADC",
    "SBB",
    "NEG",
    "INC",
    "DEC",
    "SHL",
    "SHR",
    "SAR",
    "ROL",
    "ROR",
    "MUL",
    "IMUL",
    "XADD",
    "CMPXCHG",
}

JCC_MNEMONICS = {
    "JE",
    "JNE",
    "JZ",
    "JNZ",
    "JA",
    "JAE",
    "JB",
    "JBE",
    "JC",
    "JNC",
    "JG",
    "JGE",
    "JL",
    "JLE",
    "JS",
    "JNS",
    "JO",
    "JNO",
    "JP",
    "JNP",
    "JPE",
    "JPO",
}

MOV_MNEMONICS = {"MOV", "MOVZX", "MOVSX", "MOVSXD", "POP"}
ARITH_MNEMONICS = {"ADD", "SUB", "INC", "DEC", "ADC", "SBB"}
BITWISE_MNEMONICS = {"XOR", "OR", "AND"}
SHIFT_MNEMONICS = {"SHL", "SHR", "SAR", "ROL", "ROR"}


@dataclass(frozen=True)
class Role:
    kind: str
    row: int
    detail: str | None = None

    def text(self) -> str:
        if self.detail:
            return f"[{self.row} : {self.kind} : {self.detail}]"
        return f"[{self.row} : {self.kind}]"


@dataclass
class Candidate:
    row: int
    label: str
    addr: int
    size: int | None
    value: int | None
    comment: str
    comment_roles: list[Role]
    disasm: str
    ip: int
    opcodes: str


def bitmask(bits: int) -> int:
    return (1 << bits) - 1


def reg_slice(reg_name: str | None) -> tuple[str, int, int]:
    return REG_SLICE.get((reg_name or "").upper(), ((reg_name or "").upper(), 0, 32))


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


def explicit_ops(row: dict) -> list:
    return [op for op in row.get("parsed_operands") or [] if not op.is_implicit]


def same_storage(lhs, rhs, row: dict) -> bool:
    if lhs.type != rhs.type:
        return False
    if lhs.type == OperandType.REG:
        return reg_slice(lhs.reg_name) == reg_slice(rhs.reg_name)
    if lhs.type == OperandType.MEM:
        return mem_operand_addr(lhs, row) == mem_operand_addr(rhs, row)
    return False


def vb_label(addr: int) -> str | None:
    off = (addr - VBR) & MASK32
    if 0 <= off < 0x200:
        return f"VB_0x{off:x}"
    return None


def vch_index(addr: int) -> int | None:
    if addr < VHTP_VALUE:
        return None
    off = addr - VHTP_VALUE
    if off % 4:
        return None
    idx = off // 4
    if 0 <= idx < 0x400:
        return idx
    return None


def mem_read_value(row: dict, addr: int) -> int | None:
    for mem in row.get("mem") or []:
        if mem.get("access") == "READ" and (mem.get("addr", 0) & MASK32) == (addr & MASK32):
            return mem.get("value", 0)
    return None


def mem_write_value(row: dict, addr: int) -> int | None:
    for mem in row.get("mem") or []:
        if mem.get("access") != "READ" and (mem.get("addr", 0) & MASK32) == (addr & MASK32):
            return mem.get("value", 0)
    return None


def operand_concrete_value(op, row: dict) -> int | None:
    if op.type == OperandType.REG:
        return reg_value(row, op.reg_name)
    if op.type == OperandType.IMM:
        return op.imm_value
    if op.type == OperandType.MEM:
        addr = mem_operand_addr(op, row)
        if addr is None:
            return None
        return mem_read_value(row, addr)
    return None


def estimate_mem_write_value(row: dict, addr: int) -> int | None:
    inst = row.get("instruction_obj")
    if inst is None:
        return None
    ops = explicit_ops(row)
    if not ops:
        return None
    dst = ops[0]
    if dst.type != OperandType.MEM:
        return None
    if mem_operand_addr(dst, row) != (addr & MASK32):
        return None
    if dst.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
        return None

    bits = max(dst.size * 8, 1)
    mask = bitmask(bits)
    src_val = operand_concrete_value(ops[1], row) if len(ops) > 1 else None
    if src_val is None:
        return None
    src_val &= mask

    mnemonic = inst.mnemonic.upper()
    if mnemonic in MOV_MNEMONICS:
        return src_val

    old_val = mem_read_value(row, addr)
    if old_val is None:
        return None
    old_val &= mask
    if mnemonic == "ADD":
        return (old_val + src_val) & mask
    if mnemonic == "SUB":
        return (old_val - src_val) & mask
    if mnemonic == "XOR":
        return (old_val ^ src_val) & mask
    if mnemonic == "OR":
        return (old_val | src_val) & mask
    if mnemonic == "AND":
        return (old_val & src_val) & mask
    return None


class SingleLabelTaint:
    def __init__(self) -> None:
        self.reg_masks: dict[str, int] = {}
        self.mem_bytes: set[int] = set()

    def live(self) -> bool:
        return any(self.reg_masks.values()) or bool(self.mem_bytes)

    def reg_tainted(self, reg_name: str) -> bool:
        root, low, bits = reg_slice(reg_name)
        mask = bitmask(bits) << low
        return bool(self.reg_masks.get(root, 0) & mask)

    def reg_slice_mask(self, reg_name: str) -> int:
        root, low, bits = reg_slice(reg_name)
        return (self.reg_masks.get(root, 0) >> low) & bitmask(bits)

    def write_reg_mask(self, reg_name: str, slice_mask: int) -> None:
        root, low, bits = reg_slice(reg_name)
        write_mask = bitmask(bits) << low
        old = self.reg_masks.get(root, 0)
        new = (old & ~write_mask) | ((slice_mask << low) & write_mask)
        if new:
            self.reg_masks[root] = new & MASK32
        else:
            self.reg_masks.pop(root, None)

    def write_reg_bool(self, reg_name: str, tainted: bool) -> None:
        _, _, bits = reg_slice(reg_name)
        self.write_reg_mask(reg_name, bitmask(bits) if tainted else 0)

    def mem_tainted(self, addr: int, size: int) -> bool:
        return any(((addr + i) & MASK32) in self.mem_bytes for i in range(size))

    def write_mem_bool(self, addr: int, size: int, tainted: bool) -> None:
        for i in range(size):
            byte_addr = (addr + i) & MASK32
            if tainted:
                self.mem_bytes.add(byte_addr)
            else:
                self.mem_bytes.discard(byte_addr)

    def clear_special_cursor_memory(self, addr: int, size: int) -> None:
        # VPC is a cursor, not bytecode payload storage. A bytecode-derived
        # stride updates the cursor but does not remain semantically alive inside it.
        if addr == VPC_ADDR:
            self.write_mem_bool(addr, size, False)

    def clear_all(self) -> None:
        self.reg_masks.clear()
        self.mem_bytes.clear()

    def snapshot(self) -> str:
        regs = {k: hex(v) for k, v in sorted(self.reg_masks.items()) if v}
        if not self.mem_bytes:
            return f"regs={regs} mem=[]"
        ranges = []
        bytes_sorted = sorted(self.mem_bytes)
        start = prev = bytes_sorted[0]
        for byte_addr in bytes_sorted[1:]:
            if byte_addr == prev + 1:
                prev = byte_addr
                continue
            ranges.append(f"{hex(start)}-{hex(prev)}" if start != prev else hex(start))
            start = prev = byte_addr
        ranges.append(f"{hex(start)}-{hex(prev)}" if start != prev else hex(start))
        return f"regs={regs} mem={ranges}"


def op_value_tainted(op, row: dict, taint: SingleLabelTaint) -> bool:
    if op.type == OperandType.REG:
        return taint.reg_tainted(op.reg_name)
    if op.type == OperandType.MEM:
        addr = mem_operand_addr(op, row)
        if addr is None or addr == VPC_ADDR:
            return False
        return taint.mem_tainted(addr, op.size)
    return False


def op_addr_tainted(op, taint: SingleLabelTaint) -> bool:
    if op.type != OperandType.MEM:
        return False
    mem = op.mem_info or {}
    return bool(
        (mem.get("base") and taint.reg_tainted(mem.get("base")))
        or (mem.get("index") and taint.reg_tainted(mem.get("index")))
    )


def read_value_taint(row: dict, taint: SingleLabelTaint) -> bool:
    result = False
    for op in explicit_ops(row):
        if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
            result = result or op_value_tainted(op, row, taint)
    return result


def source_taint_excluding_dst(row: dict, taint: SingleLabelTaint) -> bool:
    ops = explicit_ops(row)
    result = False
    for index, op in enumerate(ops):
        if op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
            continue
        if index == 0 and op.access == OperandAccess.READ_WRITE:
            continue
        result = result or op_value_tainted(op, row, taint)
    return result


def result_taint(row: dict, taint: SingleLabelTaint) -> bool:
    inst = row.get("instruction_obj")
    if inst is None:
        return False
    mnemonic = inst.mnemonic.upper()
    ops = explicit_ops(row)
    if not ops:
        return False
    if len(ops) >= 2 and mnemonic in ("XOR", "SUB") and same_storage(ops[0], ops[1], row):
        return False
    if mnemonic == "LEA":
        return len(ops) >= 2 and op_addr_tainted(ops[1], taint)
    if mnemonic in MOV_MNEMONICS:
        return len(ops) >= 2 and op_value_tainted(ops[1], row, taint)
    if mnemonic in ("CMP", "TEST"):
        return False
    if (
        mnemonic in BITWISE_MNEMONICS
        and len(ops) >= 2
        and ops[0].type == OperandType.REG
        and ops[1].type == OperandType.IMM
    ):
        old = taint.reg_slice_mask(ops[0].reg_name)
        imm = ops[1].imm_value & bitmask(ops[0].size * 8)
        if mnemonic == "AND":
            return bool(old & imm)
        if mnemonic == "OR":
            return bool(old & (~imm & bitmask(ops[0].size * 8)))
        return bool(old)
    if mnemonic in ARITH_MNEMONICS or mnemonic in BITWISE_MNEMONICS or mnemonic in SHIFT_MNEMONICS:
        return read_value_taint(row, taint)
    return read_value_taint(row, taint)


def apply_writes(row: dict, taint: SingleLabelTaint) -> None:
    inst = row.get("instruction_obj")
    mnemonic = inst.mnemonic.upper() if inst else ""
    ops = explicit_ops(row)
    if not ops:
        return
    dst = ops[0]
    if dst.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
        return
    res = result_taint(row, taint)
    if dst.type == OperandType.REG:
        if mnemonic in ("CMP", "TEST"):
            return
        if (
            mnemonic in BITWISE_MNEMONICS
            and len(ops) >= 2
            and ops[1].type == OperandType.IMM
            and dst.access == OperandAccess.READ_WRITE
        ):
            old = taint.reg_slice_mask(dst.reg_name)
            imm = ops[1].imm_value & bitmask(dst.size * 8)
            if mnemonic == "AND":
                taint.write_reg_mask(dst.reg_name, old & imm)
            elif mnemonic == "OR":
                taint.write_reg_mask(dst.reg_name, old & (~imm & bitmask(dst.size * 8)))
            else:
                taint.write_reg_bool(dst.reg_name, bool(old))
            return
        taint.write_reg_bool(dst.reg_name, res)
        return
    if dst.type == OperandType.MEM:
        addr = mem_operand_addr(dst, row)
        if addr is None:
            return
        if addr == VPC_ADDR:
            taint.clear_special_cursor_memory(addr, dst.size)
        else:
            taint.write_mem_bool(addr, dst.size, res)


def parse_comment_roles(comment: str) -> list[Role]:
    roles = []
    for match in re.finditer(r"\[(\d+) : ([^\]]+)\]", comment or ""):
        row = int(match.group(1))
        body = match.group(2)
        if body.startswith("vhtp index : "):
            roles.append(Role("vhtp index", row, body.split(" : ", 1)[1]))
        elif body.startswith("vb offset : "):
            roles.append(Role("vb offset", row, body.split(" : ", 1)[1]))
        elif body.startswith("vmop : "):
            roles.append(Role("vmop", row, body.split(" : ", 1)[1]))
        elif body == "conditional branch":
            roles.append(Role("conditional branch", row))
        elif body == "vpc stride":
            roles.append(Role("vpc stride", row))
        elif body == "vpc move":
            roles.append(Role("vpc move", row))
        elif body.startswith("vtable offset : "):
            roles.append(Role("vtable offset", row, body.split(" : ", 1)[1]))
    return roles


def add_role(roles: list[Role], role: Role) -> None:
    if role not in roles:
        roles.append(role)


def analyze_candidate(candidate: Candidate, rows: list[dict]) -> dict:
    taint = SingleLabelTaint()
    events: list[str] = []
    roles: list[Role] = []
    semantic_uses: list[str] = []
    pending_flag_row: int | None = None

    fetch = rows[candidate.row]
    dst = next(
        (op for op in explicit_ops(fetch) if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE)),
        None,
    )
    if dst is None:
        return {
            "init_ok": False,
            "events": [f"{candidate.row}: no explicit destination"],
            "roles": [],
            "semantic_uses": [],
            "death": None,
        }
    if dst.type == OperandType.REG:
        taint.write_reg_bool(dst.reg_name, True)
        events.append(f"{candidate.row}: init {dst.reg_name.upper()} from {candidate.label}")
    elif dst.type == OperandType.MEM:
        addr = mem_operand_addr(dst, fetch)
        if addr is None:
            return {
                "init_ok": False,
                "events": [f"{candidate.row}: destination address unavailable"],
                "roles": [],
                "semantic_uses": [],
                "death": None,
            }
        taint.write_mem_bool(addr, dst.size, True)
        events.append(f"{candidate.row}: init [{hex(addr)}] size {dst.size} from {candidate.label}")
    else:
        return {
            "init_ok": False,
            "events": [f"{candidate.row}: unsupported destination"],
            "roles": [],
            "semantic_uses": [],
            "death": None,
        }

    death = None
    for row_index in range(candidate.row + 1, len(rows)):
        if not taint.live():
            death = row_index
            break
        row = rows[row_index]
        inst = row.get("instruction_obj")
        mnemonic = inst.mnemonic.upper() if inst else ""

        if mnemonic in JCC_MNEMONICS:
            if pending_flag_row is not None:
                role = Role("conditional branch", row_index)
                add_role(roles, role)
                semantic_uses.append(f"{row_index}: conditional branch by flags from {pending_flag_row}")
                taint.clear_all()
            pending_flag_row = None

        consume_after_role = False
        for op in explicit_ops(row):
            if op.type != OperandType.MEM:
                continue
            addr = mem_operand_addr(op, row)
            if addr is None:
                continue
            addr_tainted = op_addr_tainted(op, taint)
            value_tainted = source_taint_excluding_dst(row, taint)
            if op.access == OperandAccess.READ_WRITE and addr != VPC_ADDR:
                value_tainted = value_tainted or taint.mem_tainted(addr, op.size)

            if addr_tainted:
                vb = vb_label(addr)
                if vb is not None:
                    role = Role("vb offset", row_index, vb)
                    add_role(roles, role)
                    semantic_uses.append(f"{row_index}: address selects {vb}")
                    consume_after_role = True
                idx = vch_index(addr)
                if idx is not None and op.access != OperandAccess.WRITE:
                    role = Role("vhtp index", row_index, hex(idx))
                    add_role(roles, role)
                    semantic_uses.append(f"{row_index}: address selects VCH index {hex(idx)}")
                    consume_after_role = True

            if addr == VPC_ADDR and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE) and value_tainted:
                kind = "vpc stride" if mnemonic in ARITH_MNEMONICS or op.access == OperandAccess.READ_WRITE else "vpc move"
                role = Role(kind, row_index)
                add_role(roles, role)
                semantic_uses.append(f"{row_index}: {kind}")
                consume_after_role = True

            if addr == VMOP_ADDR and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE) and value_tainted:
                value = mem_write_value(row, addr)
                if value is None:
                    value = estimate_mem_write_value(row, addr)
                detail = hex((value or 0) & 0xFF)
                role = Role("vmop", row_index, detail)
                add_role(roles, role)
                semantic_uses.append(f"{row_index}: vmop {detail}")

        if consume_after_role:
            taint.clear_all()

        if mnemonic in FLAG_MNEMONICS:
            ops = explicit_ops(row)
            if len(ops) >= 2 and mnemonic in ("XOR", "SUB", "CMP") and same_storage(ops[0], ops[1], row):
                pending_flag_row = None
            else:
                pending_flag_row = row_index if read_value_taint(row, taint) else None

        before = taint.snapshot()
        apply_writes(row, taint)
        after = taint.snapshot()
        same_row_roles = [role for role in roles if role.row == row_index]
        if before != after or same_row_roles:
            role_text = ""
            if same_row_roles:
                role_text = " roles=" + ", ".join(role.text() for role in same_row_roles)
            events.append(f"{row_index}: {mnemonic} {inst.op_str if inst else ''}{role_text} -> {after}")

    if death is None and not taint.live():
        death = len(rows) - 1
    return {
        "init_ok": True,
        "events": events,
        "roles": roles,
        "semantic_uses": semantic_uses,
        "death": death,
    }


def parse_trace(path: str) -> list[dict]:
    trace_data = open_trace(path)
    rows = trace_data.trace
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True
    for row in rows:
        inst = TraceInstruction(row, md)
        row["parsed_operands"] = inst.get_operands()
        row["instruction_obj"] = inst
    return rows


def extract_candidates(rows: list[dict]) -> list[Candidate]:
    ctx_taint = TraceContext(arch_mode=32)
    ctx_adimeht = TraceContext(arch_mode=32)
    ctx_adimeht.cap_enabled = True
    light = TraceAdimehtLightFISH(ctx_adimeht, rows, ctx_taint=ctx_taint)

    for row in rows:
        ctx_taint.load_register_state(row)
        in_vm = light.is_trace_in_vm(row)
        row["comment"] = "[VM]" if in_vm else ""
        light.process_instruction(row)

    candidates = []
    for row in rows:
        comment = row.get("comment") or ""
        label_match = re.search(r"\b(VMBLOB_0x[0-9a-fA-F]+)\b", comment)
        if label_match is None or "[fetch" not in comment:
            continue
        label = label_match.group(1)
        addr = int(label.split("_0x", 1)[1], 16)
        fetch_match = re.search(r"\[fetch\s*:\s*[+-]0x[0-9a-fA-F]+(?: \((\d+)\))?\]", comment)
        size = int(fetch_match.group(1)) if fetch_match and fetch_match.group(1) else None
        candidates.append(
            Candidate(
                row=row["id"],
                label=label,
                addr=addr,
                size=size,
                value=mem_read_value(row, addr),
                comment=comment,
                comment_roles=parse_comment_roles(comment),
                disasm=row.get("disasm", ""),
                ip=row.get("ip", 0),
                opcodes=row.get("opcodes", ""),
            )
        )
    return candidates


def verdict_for(expected: list[Role], observed: list[Role], init_ok: bool) -> tuple[str, list[Role], list[Role]]:
    if not init_ok:
        return "UNKNOWN", [], []
    expected_set = set(expected)
    observed_set = set(observed)
    missing = sorted(expected_set - observed_set, key=lambda role: (role.row, role.kind, str(role.detail)))
    extra = sorted(observed_set - expected_set, key=lambda role: (role.row, role.kind, str(role.detail)))
    if not missing and not extra:
        return "OK", missing, extra
    if missing and extra:
        return "MISMATCH", missing, extra
    if missing:
        return "MISSING", missing, extra
    return "EXTRA", missing, extra


def write_report(path: str, trace_path: str, rows: list[dict], results: list[tuple[Candidate, dict, str, list[Role], list[Role]]]) -> None:
    counts: dict[str, int] = {}
    for _, _, verdict, _, _ in results:
        counts[verdict] = counts.get(verdict, 0) + 1

    lines = [
        "# Independent VMBLOB Fetch Audit",
        "",
        "## Source",
        "",
        f"- Trace file: `{trace_path}`",
        "- Candidate list source: current plugin comments, used only to enumerate fetch rows and current annotations.",
        "- Independent analysis source: raw `.trace32` register/memory trace plus Capstone operands.",
        "- Target analyzer state is not used for propagation, role, or kill decisions.",
        "- VPC is modeled as a cursor sink: bytecode-derived strides do not remain tainted inside `VPC_0x5f`.",
        "- Date: 2026-05-23",
        "",
        "## Verdict Summary",
        "",
        "주의:",
        "",
        "- `OK`는 독립 추적기가 본 role set과 현재 comment role set이 일치한다는 뜻이다.",
        "- `MISSING`은 독립 추적기가 현재 comment보다 더 많은 downstream dependency를 관찰했다는 뜻이다.",
        "- 현재 독립 추적기는 단일 label 보수적 taint이므로, `MISSING`이 곧바로 플러그인 버그를 의미하지는 않는다.",
        "- 특히 `VMBLOB` 값이 `VB` slot 같은 virtual state에 저장된 뒤 오래 살아남는 경우, 이후 역할들이 모두 downstream use로 잡힐 수 있다.",
        "- 따라서 `MISSING` 항목은 수동 검토 우선순위이며, plugin comment 오류로 확정하려면 해당 row의 propagation events를 확인해야 한다.",
        "",
        "| Verdict | Count |",
        "| --- | ---: |",
    ]
    for verdict in ("OK", "EXTRA", "MISSING", "MISMATCH", "UNKNOWN"):
        lines.append(f"| {verdict} | {counts.get(verdict, 0)} |")

    problems = [(cand, verdict, missing, extra) for cand, _, verdict, missing, extra in results if verdict != "OK"]
    lines += ["", "## Mismatch Index", ""]
    if not problems:
        lines.append("- No mismatches found by the independent checker.")
    else:
        lines += [
            "| Row | Label | Verdict | Missing independent roles | Extra comment roles |",
            "| --- | --- | --- | --- | --- |",
        ]
        for cand, verdict, missing, extra in problems:
            missing_text = ", ".join(role.text() for role in missing) or "-"
            extra_text = ", ".join(role.text() for role in extra) or "-"
            lines.append(f"| {cand.row} | `{cand.label}` | {verdict} | {missing_text} | {extra_text} |")

    lines += ["", "## Audits", ""]
    for cand, analysis, verdict, missing, extra in results:
        value = "unknown" if cand.value is None else hex(cand.value)
        size = "?" if cand.size is None else str(cand.size)
        expected = ", ".join(role.text() for role in analysis["roles"]) or "-"
        observed = ", ".join(role.text() for role in cand.comment_roles) or "-"
        lines += [
            f"### Row {cand.row} - `{cand.label}`",
            "",
            f"- Instruction: `{cand.disasm}`",
            f"- IP/opcode: `{hex(cand.ip)}` / `{cand.opcodes}`",
            f"- Fetch address: `{hex(cand.addr)}`",
            f"- Size/value: `{size}` bytes / `{value}`",
            f"- Verdict: {verdict}",
            f"- Current comment: `{cand.comment}`",
            f"- Independent roles: {expected}",
            f"- Comment roles: {observed}",
        ]
        if missing:
            lines.append(f"- Missing roles: {', '.join(role.text() for role in missing)}")
        if extra:
            lines.append(f"- Extra comment roles: {', '.join(role.text() for role in extra)}")
        if analysis["semantic_uses"]:
            lines.append(f"- Semantic uses: {'; '.join(dict.fromkeys(analysis['semantic_uses']))}")
        death = analysis["death"]
        if death is not None:
            lines.append(f"- Physical taint death: row {death}, `{rows[death].get('disasm', '')}`")
        else:
            lines.append("- Physical taint death: not observed before trace end")
        lines += ["", "Propagation events:", ""]
        for event in analysis["events"][:40]:
            lines.append(f"- {event}")
        if len(analysis["events"]) > 40:
            lines.append(f"- ... {len(analysis['events']) - 40} more events omitted")
        lines.append("")

    with open(path, "w", encoding="utf-8") as report:
        report.write("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace", default="traces/themida_vm_add_fish_red_v3.0.3.0.trace32")
    parser.add_argument("--out", default="docs/mv_adimeht/trace_notes/vmblob_fetch_independent_audit.md")
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()

    rows = parse_trace(args.trace)
    candidates = extract_candidates(rows)
    if args.limit:
        candidates = candidates[: args.limit]

    results = []
    for index, candidate in enumerate(candidates, 1):
        if index == 1 or index % 25 == 0 or index == len(candidates):
            print(f"[*] audit {index}/{len(candidates)} row={candidate.row} label={candidate.label}", flush=True)
        analysis = analyze_candidate(candidate, rows)
        verdict, missing, extra = verdict_for(analysis["roles"], candidate.comment_roles, analysis["init_ok"])
        results.append((candidate, analysis, verdict, missing, extra))

    write_report(args.out, args.trace, rows, results)
    counts: dict[str, int] = {}
    for _, _, verdict, _, _ in results:
        counts[verdict] = counts.get(verdict, 0) + 1
    print(f"candidates={len(candidates)}")
    print("summary=" + ", ".join(f"{key}:{counts.get(key, 0)}" for key in ("OK", "EXTRA", "MISSING", "MISMATCH", "UNKNOWN")))
    print(f"wrote={args.out}")


if __name__ == "__main__":
    main()
