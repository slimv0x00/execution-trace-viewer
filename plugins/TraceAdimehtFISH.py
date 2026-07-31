import collections

import z3

from .TraceTaint import TraceTaint
from .TraceOperand import OperandType, OperandAccess
from .TraceContext import _z3_bv_to_str


# EBP index in x64dbg 32-bit register snapshot: ['eax','ecx','edx','ebx','esp','ebp',...]
_EBP_IDX = 5

_VBR_SLOT_RANGE   = 0x200
_VPC_LOOKAHEAD    = 20
_VPC_OFFSET_SLACK = 16
_VPC_MIN_READS    = 3
_VPC_MIN_SCORE    = 0.5
_VHTP_MAX_WRITES    = 3
_VMOP_MIN_WRITES    = 3
_VMOP_MIN_RPW       = 5.0   # minimum reads-per-write ratio
_VMOP_MAX_PTR_RATIO = 0.1   # must NOT behave like a pointer (opposite of VPC)

_JCC_MNEMONICS = frozenset({
    'JE', 'JNE', 'JZ', 'JNZ', 'JA', 'JAE', 'JB', 'JBE',
    'JC', 'JNC', 'JG', 'JGE', 'JL', 'JLE',
    'JS', 'JNS', 'JO', 'JNO', 'JP', 'JNP', 'JPE', 'JPO',
})
# Instructions that update eflags (comparison/arithmetic result written to flags)
_FLAG_MNEMONICS = frozenset({
    'CMP', 'TEST', 'ADD', 'SUB', 'XOR', 'OR', 'AND',
    'ADC', 'SBB', 'NEG', 'INC', 'DEC',
    'SHL', 'SHR', 'SAR', 'ROL', 'ROR',
    'MUL', 'IMUL', 'XADD', 'CMPXCHG',
})


class TraceAdimehtFISH(TraceTaint):

    def __init__(self, ctx, traces: list, ctx_taint=None):
        super().__init__(ctx)
        self.traces = traces
        self.ctx_taint = ctx_taint  # external taint context for fallback symbol lookup
        self.vbr:       int | None = None
        self.vpc_slot: int | None = None  # VBR-relative offset of the virtual program counter slot
        self.vhtp_slot:  int | None = None  # VBR-relative offset of the virtual handler table pointer slot
        self.vmop_slot: int | None = None  # VBR-relative offset of the virtual opcode slot

        self.is_in_vm: bool = False
        self._vb_slots:      dict[str, z3.BitVecRef] = {}  # label → z3 symbol
        self._vb_addr_map:   dict[int, str] = {}           # concrete addr → label (all bytes)
        self._vb_base_addrs: dict[str, int] = {}           # label → base concrete addr
        self.last_vmi_str: str = ''
        self._vpc_prev_value: int | None = None
        self._current_vpc:   int | None = None
        self._fetch_traces:   dict[str, dict] = {}  # VMBLOB label → trace dict of fetch row
        self._vmop_cmp_detected: dict | None = None  # {vmop_value} set at FLAG instr, consumed at Jcc
        self._vmop_cycle_value: int | None = None    # opcode byte read from VMOP slot this cycle
        self._vmop_derived_vars: set = set()         # free var names present in VMOP slot sym at last READ
        self._eflags_syms: list = []                 # symbolic exprs from last FLAG instr's src operands
        self._eflags_has_vmop: bool = False          # True when eflags src free vars overlap _vmop_derived_vars
        self._reg_vb_source: dict = {}               # root_reg → VB_ label (set on direct VB MEM→reg WRITE, cleared otherwise)
        self._eflags_vb_label: str | None = None     # VB_ label looked up from _reg_vb_source at last FLAG instr
        self._eflags_vmblob_label: str | None = None  # VMBLOB_ label when eflags src is VMBLOB-derived (not VB/VMOP)
        self._eflags_vmblob_conc_val: int | None = None  # concrete value of the VMBLOB-derived src operand at FLAG time

        self._detect_vbr()
        self._detect_vpc_and_vhtp()

    # =========================================================================
    # VM scope
    # =========================================================================

    def enter_vm(self) -> None:
        """Mark entry into VM scope and seed EBP with VBR symbol."""
        self.is_in_vm = True
        self.add_taint_register('ebp', 'VBR')

    def exit_vm(self) -> None:
        """Mark exit from VM scope and clear all adimehts symbolic state."""
        self.is_in_vm = False
        self.ctx.regs_symbolic.clear()
        self.ctx.mem_symbolic.clear()
        self.ctx.mem_wide_symbolic.clear()
        self.initial_symbols.clear()
        self._vb_slots.clear()
        self._vb_addr_map.clear()
        self._vb_base_addrs.clear()
        self._current_vpc = None
        self._fetch_traces.clear()
        self._vmop_cmp_detected = None
        self._vmop_cycle_value = None
        self._vmop_derived_vars = set()
        self._eflags_syms = []
        self._eflags_has_vmop = False
        self._reg_vb_source = {}
        self._eflags_vb_label = None
        self._eflags_vmblob_label = None
        self._eflags_vmblob_conc_val = None

    # =========================================================================
    # Snapshot
    # =========================================================================

    def get_snapshot(self) -> list:
        """Return adimehts state as a list of {'name', 'symbol'} dicts."""
        result = []
        for entry in self.ctx.get_symbolic_state_snapshot():
            name = entry.get('name', '')
            if name.startswith('Mem['):
                try:
                    addr = int(name[4:name.index(']')], 16)
                    if addr in self._vb_addr_map:
                        continue  # shown as VB slot below
                except ValueError:
                    pass
            result.append(entry)
        for label in self._vb_slots:
            sym_str = label  # fallback: original free variable name
            base_addr = self._vb_base_addrs.get(label)
            if base_addr is not None:
                _, current_sym = self.ctx.get_memory(base_addr, self.ctx.root_reg_size)
                if current_sym is not None and not z3.is_bv_value(current_sym):
                    sym_str = _z3_bv_to_str(current_sym)
            result.append({'name': label, 'symbol': sym_str})
        if self._eflags_syms:
            non_trivial = [s for s in self._eflags_syms
                           if s is not None and not z3.is_bv_value(s)]
            if non_trivial:
                result.append({'name': 'eflags', 'symbol': ', '.join(_z3_bv_to_str(s) for s in non_trivial)})
        if self._eflags_has_vmop and self.vmop_slot is not None:
            result.append({'name': 'eflags_vmop', 'symbol': f'VMOP_0x{self.vmop_slot:x}'})
        return result

    # =========================================================================
    # Instruction processing — VB slot detection
    # =========================================================================

    @staticmethod
    def _extract_vbr_offset(expr) -> 'int | None':
        """Return the constant offset if expr is VBR or VBR + constant, else None."""
        if z3.is_const(expr) and not z3.is_bv_value(expr) and str(expr) == 'VBR':
            return 0
        if z3.is_app(expr) and expr.decl().name() == 'bvadd' and expr.num_args() == 2:
            a, b = expr.arg(0), expr.arg(1)
            if z3.is_bv_value(a) and z3.is_const(b) and str(b) == 'VBR':
                return a.as_long()
            if z3.is_bv_value(b) and z3.is_const(a) and str(a) == 'VBR':
                return b.as_long()
        return None

    @staticmethod
    def _collect_free_vars(expr) -> set:
        """Return the set of free variable names (non-value z3 constants) in expr."""
        if expr is None or not z3.is_expr(expr):
            return set()
        if z3.is_const(expr) and not z3.is_bv_value(expr):
            return {str(expr)}
        result = set()
        for i in range(expr.num_args()):
            result |= TraceAdimehtFISH._collect_free_vars(expr.arg(i))
        return result

    @staticmethod
    def _jcc_taken(mnemonic: str, flags_c: int) -> bool:
        """Return True if the Jcc branch condition is satisfied (branch would be taken)."""
        zf = (flags_c >> 6) & 1
        sf = (flags_c >> 7) & 1
        of = (flags_c >> 11) & 1
        cf = (flags_c >> 0) & 1
        pf = (flags_c >> 2) & 1
        m = mnemonic.upper()
        if m in ('JE',  'JZ'):         return zf == 1
        if m in ('JNE', 'JNZ'):        return zf == 0
        if m in ('JA',  'JNBE'):       return cf == 0 and zf == 0
        if m in ('JAE', 'JNB', 'JNC'): return cf == 0
        if m in ('JB',  'JNAE', 'JC'): return cf == 1
        if m in ('JBE', 'JNA'):        return cf == 1 or zf == 1
        if m in ('JG',  'JNLE'):       return zf == 0 and sf == of
        if m in ('JGE', 'JNL'):        return sf == of
        if m in ('JL',  'JNGE'):       return sf != of
        if m in ('JLE', 'JNG'):        return zf == 1 or sf != of
        if m in ('JS',):               return sf == 1
        if m in ('JNS',):              return sf == 0
        if m in ('JO',):               return of == 1
        if m in ('JNO',):              return of == 0
        if m in ('JP',  'JPE'):        return pf == 1
        if m in ('JNP', 'JPO'):        return pf == 0
        return False

    @staticmethod
    def _sym_contains(expr, sym) -> bool:
        """Return True if the named z3 variable sym appears anywhere in expr."""
        if expr is None or not z3.is_expr(expr):
            return False
        if z3.is_const(expr) and not z3.is_bv_value(expr):
            return expr.eq(sym)
        return any(TraceAdimehtFISH._sym_contains(expr.arg(i), sym)
                   for i in range(expr.num_args()))

    def _annotate_fetch_sources(self, expr, tag: str) -> None:
        """Walk a z3 expression tree and append tag to any VMBLOB fetch trace found."""
        if expr is None or not z3.is_expr(expr):
            return
        if z3.is_const(expr) and not z3.is_bv_value(expr):
            fetch_trace = self._fetch_traces.get(str(expr))
            if fetch_trace is not None:
                existing = fetch_trace.get('comment') or ''
                if tag not in existing:
                    fetch_trace['comment'] = (existing + f' | {tag}').lstrip(' | ')
            return
        for i in range(expr.num_args()):
            self._annotate_fetch_sources(expr.arg(i), tag)

    def _detect_vb_accesses(self, trace) -> None:
        """Scan MEM operands and register VB/VMBLOB slots in adimehts.

        VBR+offset  → VB_0x{offset} / VPC_0x{offset} / VHTP_0x{offset}
        VPC-derived → VMBLOB_0x{concrete_addr}
        """
        ip = trace.get('ip', 0)
        operands = trace.get('parsed_operands') or []

        vpc_sym = None
        if self.vpc_slot is not None:
            vpc_label = f'VPC_0x{self.vpc_slot:x}'
            vpc_sym = self._vb_slots.get(vpc_label)

        vhtp_sym = None
        if self.vhtp_slot is not None:
            vhtp_label = f'VHTP_0x{self.vhtp_slot:x}'
            vhtp_sym = self._vb_slots.get(vhtp_label)

        for op in operands:
            if op.type != OperandType.MEM:
                continue
            mem = op.mem_info
            base = (mem.get('base') or '').lower()
            if not base:
                continue
            root, _, _ = self.ctx._get_root_register_info(base)
            base_sym = self.ctx.regs_symbolic.get(root)
            if base_sym is None:
                continue

            # ── Case 1: VBR+offset → VB / VPC / VHTP slot ────────────────────
            # Index register not supported for VBR-relative detection
            if not mem.get('index'):
                vbr_offset = self._extract_vbr_offset(base_sym)
                if vbr_offset is not None:
                    disp = mem.get('disp', 0)
                    total_offset = (vbr_offset + disp) & 0xFFFFFFFF
                    if total_offset == self.vpc_slot:
                        label = f'VPC_0x{total_offset:x}'
                    elif total_offset == self.vhtp_slot:
                        label = f'VHTP_0x{total_offset:x}'
                    elif total_offset == self.vmop_slot:
                        label = f'VMOP_0x{total_offset:x}'
                    else:
                        label = f'VB_0x{total_offset:x}'
                    concrete_addr = (self.vbr + total_offset) & 0xFFFFFFFF
                    self._register_slot(label, concrete_addr)
                    continue
                # VBR present but offset is symbolic — derive slot from concrete address
                _vbr_sym = z3.BitVec('VBR', self.ctx.arch_mode)
                if self.vbr is not None and self._sym_contains(base_sym, _vbr_sym):
                    concrete_addr, _ = op.resolve_addr(self.ctx, ip)
                    concrete_addr &= 0xFFFFFFFF
                    total_offset = (concrete_addr - self.vbr) & 0xFFFFFFFF
                    if total_offset < _VBR_SLOT_RANGE:
                        if total_offset == self.vpc_slot:
                            label = f'VPC_0x{total_offset:x}'
                        elif total_offset == self.vhtp_slot:
                            label = f'VHTP_0x{total_offset:x}'
                        elif total_offset == self.vmop_slot:
                            label = f'VMOP_0x{total_offset:x}'
                        else:
                            label = f'VB_0x{total_offset:x}'
                        self._register_slot(label, concrete_addr)
                        self._annotate_fetch_sources(base_sym, f'[vb offset : {label}]')
                    continue

            # ── Case 2: VPC-derived base → VMBLOB ───────────────────────────
            if vpc_sym is not None and self._sym_contains(base_sym, vpc_sym):
                concrete_addr, _ = op.resolve_addr(self.ctx, ip)
                concrete_addr &= 0xFFFFFFFF
                self._register_slot(f'VMBLOB_0x{concrete_addr:x}', concrete_addr)

            # ── Case 3: VHTP[index] → VCH ─────────────────────────────────────
            elif vhtp_sym is not None and self._sym_contains(base_sym, vhtp_sym):
                index_name = (mem.get('index') or '').lower()
                concrete_addr, _ = op.resolve_addr(self.ctx, ip)
                concrete_addr &= 0xFFFFFFFF
                if index_name:
                    # [VHTP_reg + index_reg * scale]: index drives the slot
                    scale = mem.get('scale', 1)
                    index_root, _, _ = self.ctx._get_root_register_info(index_name)
                    index_conc = self.ctx.regs_concrete.get(index_root, 0)
                    effective = (index_conc * scale) & 0xFFFFFFFF
                    handler_index = effective // 4
                    index_sym = self.ctx.regs_symbolic.get(index_root)
                    self._annotate_fetch_sources(index_sym, f'[vhtp index : {handler_index}]')
                else:
                    # [base_reg] where base already holds VHTP + offset (pre-computed)
                    vhtp_addr = (self.vbr + self.vhtp_slot) & 0xFFFFFFFF
                    vhtp_conc, _ = self.ctx.get_memory(vhtp_addr, self.ctx.root_reg_size)
                    handler_index = (concrete_addr - vhtp_conc) // 4
                    self._annotate_fetch_sources(base_sym, f'[vhtp index : {handler_index}]')
                self._register_slot(f'VCH_0x{handler_index:x}', concrete_addr)

    def _register_slot(self, label: str, concrete_addr: int) -> None:
        """Register a new VB/VMBLOB/VCH slot: seed symbol in ctx and update maps."""
        if label in self._vb_slots:
            return
        sym = z3.BitVec(label, self.ctx.arch_mode)
        self._vb_slots[label] = sym
        self._vb_base_addrs[label] = concrete_addr
        for i in range(self.ctx.root_reg_size):
            self._vb_addr_map[concrete_addr + i] = label
        conc_val, _ = self.ctx.get_memory(concrete_addr, self.ctx.root_reg_size)
        self.ctx.set_memory(concrete_addr, self.ctx.root_reg_size, conc_val, sym)

    def _sync_src_from_taint(self, trace) -> None:
        """Before super().process_instruction(), if dst is a known VB slot and src
        has no adimehts symbolic, import the taint symbolic from ctx_taint."""
        if self.ctx_taint is None:
            return
        ip = trace.get('ip', 0)
        operands = trace.get('parsed_operands') or []
        explicit_ops = [op for op in operands if not op.is_implicit]
        dst_ops = [op for op in explicit_ops
                   if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE)]
        src_ops = [op for op in explicit_ops if op.access == OperandAccess.READ]

        for dst_op in dst_ops:
            if dst_op.type != OperandType.MEM:
                continue
            dst_addr, _ = dst_op.resolve_addr(self.ctx, ip)
            dst_addr &= 0xFFFFFFFF
            if dst_addr not in self._vb_addr_map:
                continue
            # dst is a known VB slot — sync each src from taint if missing in adimehts
            for src_op in src_ops:
                if src_op.type == OperandType.REG:
                    root, _, _ = self.ctx._get_root_register_info(src_op.reg_name)
                    adimeht_sym = self.ctx.regs_symbolic.get(root)
                    if adimeht_sym is None or z3.is_bv_value(adimeht_sym):
                        taint_sym = self.ctx_taint.regs_symbolic.get(root)
                        if taint_sym is not None and not z3.is_bv_value(taint_sym):
                            conc, _, _ = self.ctx.get_register(root)
                            self.ctx.set_register(root, conc, taint_sym)
                elif src_op.type == OperandType.MEM:
                    src_addr, _ = src_op.resolve_addr(self.ctx, ip)
                    src_addr &= 0xFFFFFFFF
                    _, adimeht_sym = self.ctx.get_memory(src_addr, self.ctx.root_reg_size)
                    if adimeht_sym is None or z3.is_bv_value(adimeht_sym):
                        _, taint_sym = self.ctx_taint.get_memory(src_addr, self.ctx.root_reg_size)
                        if taint_sym is not None and not z3.is_bv_value(taint_sym):
                            conc_val, _ = self.ctx.get_memory(src_addr, self.ctx.root_reg_size)
                            self.ctx.set_memory(src_addr, self.ctx.root_reg_size, conc_val, taint_sym)

    # =========================================================================
    # VMI interpretation
    # =========================================================================

    def _find_vb_label_in_expr(self, expr) -> 'str | None':
        """Return the name of the first VB slot symbol found anywhere in expr, or None."""
        if expr is None or not z3.is_expr(expr):
            return None
        if z3.is_const(expr) and not z3.is_bv_value(expr):
            name = str(expr)
            return name if name in self._vb_slots else None
        for i in range(expr.num_args()):
            result = self._find_vb_label_in_expr(expr.arg(i))
            if result is not None:
                return result
        return None

    def _get_adimeht_label(self, op, ip) -> 'str | None':
        """Return the adimehts label for op if it is a tracked element, else None."""
        if op.type == OperandType.MEM:
            addr, _ = op.resolve_addr(self.ctx, ip)
            return self._vb_addr_map.get(addr & 0xFFFFFFFF)
        if op.type == OperandType.REG:
            root, _, _ = self.ctx._get_root_register_info(op.reg_name)
            sym = self.ctx.regs_symbolic.get(root)
            if sym is not None and not z3.is_bv_value(sym):
                name = str(sym)
                if name in self._vb_slots:
                    return name
        return None

    def _interpret_vmi(self, trace) -> str:
        """Return a VMI string if any explicit operand is an adimehts element, else ''."""
        inst = trace.get('instruction_obj')
        if inst is None:
            return ''
        operands = trace.get('parsed_operands') or []
        explicit_ops = [op for op in operands if not op.is_implicit]
        if not explicit_ops:
            return ''

        ip = trace.get('ip', 0)
        op_strs = [s.strip() for s in inst.op_str.split(',')] if inst.op_str else []

        parts = []
        has_adimeht = False
        for i, op in enumerate(explicit_ops):
            raw_str = op_strs[i] if i < len(op_strs) else '?'
            if op.type == OperandType.REG:
                # REG operands always display as raw register name.
                # For src/read-write, still check for VB symbol to trigger VMI output.
                if op.access != OperandAccess.WRITE:
                    label = self._get_adimeht_label(op, ip)
                    if label:
                        has_adimeht = True
                    else:
                        root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                        sym = self.ctx.regs_symbolic.get(root)
                        if sym is not None and not z3.is_bv_value(sym) and self._find_vb_label_in_expr(sym):
                            has_adimeht = True
                parts.append(raw_str)
            else:
                # MEM operand: show VB label if registered, else raw string
                label = self._get_adimeht_label(op, ip)
                if label:
                    parts.append(label)
                    has_adimeht = True
                else:
                    parts.append(raw_str)

        if not has_adimeht:
            return ''
        return f'{inst.mnemonic} {", ".join(parts)}'

    # =========================================================================
    # Internal events
    # =========================================================================

    def get_internal_events(self, trace) -> str:
        """Detect VM internal events for the current instruction and return an annotation string."""
        if not self.is_in_vm:
            return ''
        events = []

        # VPC write → [VPC moved : ...]
        if self.vpc_slot is not None and self.vbr is not None:
            vpc_addr = self.vbr + self.vpc_slot
            for m in (trace.get('mem') or []):
                if m.get('addr') == vpc_addr and m.get('access') != 'READ':
                    new_val = m.get('value', 0)
                    inst = trace.get('instruction_obj')
                    mnemonic = inst.mnemonic.upper() if inst else ''
                    _MOV_MNEMONICS = frozenset({'MOV', 'MOVZX', 'MOVSX', 'MOVSXD'})
                    _ARITH_MNEMONICS = frozenset({'ADD', 'SUB', 'INC', 'DEC', 'ADC', 'SBB'})
                    mask = (1 << self.ctx.arch_mode) - 1
                    half = 1 << (self.ctx.arch_mode - 1)

                    def _signed_delta(a, b):
                        """Return (sign_char, abs_val) for (b - a) as signed."""
                        raw = (b - a) & mask
                        if raw >= half:
                            return '-', (1 << self.ctx.arch_mode) - raw
                        return '+', raw

                    if mnemonic in _MOV_MNEMONICS:
                        events.append(f'[VPC moved : {hex(new_val)}]')
                        self._current_vpc = new_val
                        self._vmop_cmp_detected = None   # new dispatch cycle
                        self._vmop_cycle_value  = None   # reset opcode tracking
                        self._vmop_derived_vars = set()  # reset VMOP free-var set
                    elif mnemonic in _ARITH_MNEMONICS and self._vpc_prev_value is not None:
                        old_val = self._vpc_prev_value
                        step_sign, abs_step = _signed_delta(old_val, new_val)
                        base = self._current_vpc if self._current_vpc is not None else old_val
                        disp_sign, abs_disp = _signed_delta(base, new_val)
                        events.append(
                            f'[VPC moved : {step_sign}{hex(abs_step)}'
                            f' ({hex(base)} {disp_sign} {hex(abs_disp)})]'
                        )
                        # _current_vpc intentionally NOT updated — base stays at last MOV/POP value
                        # Annotate fetch rows that contributed the stride value
                        ip = trace.get('ip', 0)
                        for op in (trace.get('parsed_operands') or []):
                            if op.is_implicit or op.access != OperandAccess.READ:
                                continue
                            if op.type == OperandType.REG:
                                root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                                self._annotate_fetch_sources(self.ctx.regs_symbolic.get(root), '[vpc stride]')
                            elif op.type == OperandType.MEM:
                                try:
                                    addr, _ = op.resolve_addr(self.ctx, ip)
                                    _, sym = self.ctx.get_memory(addr & 0xFFFFFFFF, self.ctx.root_reg_size)
                                    self._annotate_fetch_sources(sym, '[vpc stride]')
                                except Exception:
                                    pass
                    else:
                        events.append(f'[VPC moved : {hex(new_val)}]')
                        self._current_vpc = new_val
                    break

        # READ from VPC-derived address → [fetch : +/-offset (size)]
        for m in (trace.get('mem') or []):
            if m.get('access') == 'READ':
                fetch_addr = m.get('addr', 0) & 0xFFFFFFFF
                label = self._vb_addr_map.get(fetch_addr, '')
                if label.startswith('VMBLOB_'):
                    self._fetch_traces[label] = trace
                    _SIZE_KEYWORDS = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8}
                    disasm = (trace.get('disasm') or '').lower()
                    fetch_size = next((v for k, v in _SIZE_KEYWORDS.items() if k + ' ptr' in disasm), None)
                    size_str = f' ({fetch_size})' if fetch_size is not None else ''
                    if self._current_vpc is not None:
                        mask = (1 << self.ctx.arch_mode) - 1
                        delta = (fetch_addr - self._current_vpc) & mask
                        if delta >= (1 << (self.ctx.arch_mode - 1)):
                            abs_delta = (1 << self.ctx.arch_mode) - delta
                            events.append(f'[fetch : -{hex(abs_delta)}{size_str}]')
                        else:
                            events.append(f'[fetch : +{hex(delta)}{size_str}]')
                    else:
                        events.append(f'[fetch{size_str}]')
                    break

        # READ from VHTP[index] address → [VCH[{index}] load]
        for m in (trace.get('mem') or []):
            if m.get('access') == 'READ':
                label = self._vb_addr_map.get(m.get('addr', 0) & 0xFFFFFFFF, '')
                if label.startswith('VCH_'):
                    handler_index = int(label.split('_0x')[1], 16)
                    events.append(f'[VCH[{handler_index}] load]')
                    break

        # JMP/CALL to a VCH address → [========== VCH moved ==========]
        inst = trace.get('instruction_obj')
        if inst and inst.mnemonic.upper() in ('JMP', 'CALL'):
            ip = trace.get('ip', 0)
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit:
                    continue
                label = self._get_adimeht_label(op, ip)
                if label and label.startswith('VCH_'):
                    handler_index = int(label.split('_0x')[1], 16)
                    events.append(f'========== [VCH moved : VCH[{handler_index}]] ==========')
                    break

        # VMOP slot WRITE → annotate the fetch row that contributed the opcode value.
        # The src operand (e.g. dl) carries the VMBLOB-derived symbol; walk its expression
        # tree to find which fetch row produced the byte and tag it with [vmop : 0xXX].
        if self.vmop_slot is not None and self.vbr is not None:
            vmop_addr = (self.vbr + self.vmop_slot) & 0xFFFFFFFF
            for m in (trace.get('mem') or []):
                if m.get('addr') == vmop_addr and m.get('access') != 'READ':
                    vmop_value = m.get('value', 0) & 0xFF
                    tag = f'[vmop : {hex(vmop_value)}]'
                    ip = trace.get('ip', 0)
                    for op in (trace.get('parsed_operands') or []):
                        if op.is_implicit or op.access != OperandAccess.READ:
                            continue
                        if op.type == OperandType.REG:
                            root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                            self._annotate_fetch_sources(self.ctx.regs_symbolic.get(root), tag)
                        elif op.type == OperandType.MEM:
                            try:
                                addr, _ = op.resolve_addr(self.ctx, ip)
                                _, sym = self.ctx.get_memory(addr & 0xFFFFFFFF, self.ctx.root_reg_size)
                                self._annotate_fetch_sources(sym, tag)
                            except Exception:
                                pass
                    break

        # VMOP slot READ → record opcode byte + snapshot current VMOP slot free variables.
        # Free variables are captured once per READ: by this point process_instruction has run,
        # but a READ does not modify the slot sym, so get_memory still reflects the post-WRITE state.
        if self.vmop_slot is not None and self.vbr is not None:
            vmop_addr = (self.vbr + self.vmop_slot) & 0xFFFFFFFF
            for m in (trace.get('mem') or []):
                if m.get('access') == 'READ' and m.get('addr') == vmop_addr:
                    self._vmop_cycle_value = m.get('value', 0) & 0xFF
                    _, vmop_slot_sym = self.ctx.get_memory(vmop_addr, self.ctx.root_reg_size)
                    self._vmop_derived_vars = self._collect_free_vars(vmop_slot_sym)
                    break

        # Track register VB provenance: when a reg is directly written from a VB MEM READ,
        # record root_reg → VB_label. On any other WRITE, clear the provenance for that reg.
        # READ_WRITE (in-place ALU) intentionally left unchanged — the reg still carries VB-derived data.
        # This avoids the "last VB read wins" staleness bug of the old _var_to_vb approach.
        _ip_prov = trace.get('ip', 0)
        _prov_ops = [op for op in (trace.get('parsed_operands') or []) if not op.is_implicit]
        _prov_write_regs = [op for op in _prov_ops
                            if op.type == OperandType.REG and op.access == OperandAccess.WRITE]
        if _prov_write_regs:
            _vb_src_label = None
            # Use trace mem entries for address lookup: resolve_addr is unreliable post-instruction
            # when the base register is also the write destination (e.g. mov bl, [ebx]).
            for m in (trace.get('mem') or []):
                if m.get('access') == 'READ':
                    _mlabel = self._vb_addr_map.get(m.get('addr', 0) & 0xFFFFFFFF, '')
                    if _mlabel.startswith('VB_'):
                        _vb_src_label = _mlabel
                        break
            # Propagate provenance through REG→REG (e.g. movzx ebx, bl) when no VB MEM src.
            if _vb_src_label is None:
                for op in _prov_ops:
                    if op.type == OperandType.REG and op.access == OperandAccess.READ:
                        _src_root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                        _src_label = self._reg_vb_source.get(_src_root)
                        if _src_label:
                            _vb_src_label = _src_label
                            break
            for op in _prov_write_regs:
                root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                if _vb_src_label:
                    self._reg_vb_source[root] = _vb_src_label
                else:
                    self._reg_vb_source.pop(root, None)

        # Flag-setting instruction → record src symbolic expressions as eflags.
        # Arm decode detector only when VMOP symbol is present in a src operand (precision guard).
        # Checking the src register symbols (not eflags symbolic) is more reliable because
        # ALU operand tracking is direct whereas eflags symbolic propagation is lossy.
        if inst and inst.mnemonic.upper() in _FLAG_MNEMONICS:
            ip_flag = trace.get('ip', 0)
            syms = []
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    continue
                if op.type == OperandType.REG:
                    root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                    sym = self.ctx.regs_symbolic.get(root)
                    if sym is not None and not z3.is_bv_value(sym):
                        syms.append(sym)
                elif op.type == OperandType.MEM:
                    try:
                        addr, _ = op.resolve_addr(self.ctx, ip_flag)
                        _, sym = self.ctx.get_memory(addr & 0xFFFFFFFF, self.ctx.root_reg_size)
                        if sym is not None and not z3.is_bv_value(sym):
                            syms.append(sym)
                    except Exception:
                        pass
            self._eflags_syms = syms
            # Determine if eflags is VMOP-derived via free-variable intersection.
            # _vmop_derived_vars holds the free vars that were in the VMOP slot sym when it was
            # last READ. If any of those vars appear in a src sym, this FLAG op depends on VMOP.
            # This is more robust than _sym_contains(s, VMOP_free_var) because the VMOP slot sym
            # is typically a VMBLOB-derived expression (overwritten by dispatch WRITE), not the
            # original seeded free variable.
            src_vars: set = set()
            for s in syms:
                src_vars |= self._collect_free_vars(s)
            eflags_has_vmop = bool(src_vars & self._vmop_derived_vars) if self._vmop_derived_vars else False
            self._eflags_has_vmop = eflags_has_vmop
            if self._vmop_cycle_value is not None:
                if eflags_has_vmop:
                    self._vmop_cmp_detected = {'vmop_value': self._vmop_cycle_value}
                else:
                    self._vmop_cmp_detected = None  # CMP is not VMOP-derived; disarm
            # Look up the originating VB slot via register provenance (_reg_vb_source).
            # Only applies when not VMOP-derived (those cases go through the decode path instead).
            # Checks each explicit READ src register in instruction order; first hit wins.
            eflags_vb_label = None
            eflags_vmblob_label = None
            eflags_vmblob_conc_val = None
            if not eflags_has_vmop:
                for op in (trace.get('parsed_operands') or []):
                    if op.is_implicit or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                        continue
                    if op.type == OperandType.REG:
                        root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                        label = self._reg_vb_source.get(root)
                        if label:
                            eflags_vb_label = label
                            break
                # If no VB label, check syms for VMBLOB-derived free vars.
                # CMP doesn't write to src registers, so their concrete values are still valid post-instruction.
                if eflags_vb_label is None:
                    for op in (trace.get('parsed_operands') or []):
                        if op.is_implicit or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                            continue
                        if op.type != OperandType.REG:
                            continue
                        root, _, _ = self.ctx._get_root_register_info(op.reg_name)
                        sym = self.ctx.regs_symbolic.get(root)
                        if sym is None:
                            continue
                        for var in self._collect_free_vars(sym):
                            if var.startswith('VMBLOB_'):
                                eflags_vmblob_label = var
                                conc, _, _ = self.ctx.get_register(op.reg_name)
                                eflags_vmblob_conc_val = conc
                                break
                        if eflags_vmblob_label:
                            break
            self._eflags_vb_label = eflags_vb_label
            self._eflags_vmblob_label = eflags_vmblob_label
            self._eflags_vmblob_conc_val = eflags_vmblob_conc_val

        # Jcc after VMOP comparison → decode if ZF=1 (equal match found).
        # ZF=1 covers both "jne falls through" (equal → not taken) and "je branches" (equal → taken).
        # eflags concrete at this row reflects the preceding CMP/flag-setting result.
        if inst and inst.mnemonic.upper() in _JCC_MNEMONICS:
            flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'
            flags_c, _, _ = self.ctx.get_register(flags_reg)
            zf = (flags_c >> 6) & 1
            decode_emitted = False
            if self._vmop_cmp_detected is not None:
                detected = self._vmop_cmp_detected
                self._vmop_cmp_detected = None
                if zf == 1:
                    events.append(f'========== [decode : {hex(detected["vmop_value"])}] ==========')
                    decode_emitted = True
            # VB-derived branch (not a VMOP decode) → annotate with originating VB slot + concrete value.
            # Condition: ZF=1 (values equal). VM dispatch falls through on match (ZF=1), so conditional
            # branch is meaningful only when the compared values are equal.
            # _eflags_vb_label is resolved at FLAG time via _reg_vb_source provenance tracking,
            # so it shows the directly-read VB slot (e.g. VB_0x8) not the inner VMBLOB expression.
            if not decode_emitted and zf == 1 and self._eflags_vb_label:
                vb_label = self._eflags_vb_label
                if vb_label in self._vb_base_addrs:
                    conc_val, _ = self.ctx.get_memory(self._vb_base_addrs[vb_label], self.ctx.root_reg_size)
                    events.append(f'[conditional branch : {hex(conc_val)} (from {vb_label})]')
            elif not decode_emitted and zf == 1 and self._eflags_vmblob_label and self._eflags_vmblob_conc_val is not None:
                events.append(f'[conditional branch : {hex(self._eflags_vmblob_conc_val)} (from {self._eflags_vmblob_label})]')

        return ' '.join(events)

    def process_instruction(self, trace) -> bool:
        self.last_vmi_str = ''
        self._vpc_prev_value = None
        if self.is_in_vm:
            # Capture VPC value before execution for [VPC moved] annotation
            if self.vpc_slot is not None and self.vbr is not None:
                vpc_addr = self.vbr + self.vpc_slot
                self._vpc_prev_value, _ = self.ctx.get_memory(vpc_addr, self.ctx.root_reg_size)
            self._detect_vb_accesses(trace)
            self._sync_src_from_taint(trace)
            self.last_vmi_str = self._interpret_vmi(trace)
        result = super().process_instruction(trace)
        if self.is_in_vm:
            self._simplify_symbolic_state()
        return result

    def _simplify_symbolic_state(self) -> None:
        """Apply z3.simplify() to composite symbolic expressions in register state.

        Skips atoms (free variables, bv constants) since simplify() is a no-op on them.
        mem_symbolic intentionally excluded: set_memory stores raw Extract slices that must
        not be simplified before reassembly (see set_memory comment '절대 하지 마세요').
        Called after every instruction to prevent expression tree bloat.
        """
        for reg, sym in self.ctx.regs_symbolic.items():
            if sym is not None and z3.is_expr(sym) and not z3.is_const(sym):
                self.ctx.regs_symbolic[reg] = z3.simplify(sym)

    # =========================================================================
    # VMOP detection
    # =========================================================================

    def _detect_vmop(self) -> None:
        """Detect the VMOP (Virtual Micro Opcode) VB slot.

        The VMOP slot stores the decoded opcode byte before dispatch:
          - Written once per dispatch cycle (opcode value: 0x00–0xFF)
          - Read many times per write (dispatch loop consults it repeatedly)
          - Values are NOT dereferenced as pointers (opposite of VPC)

        Requires self.vpc_slot to be set and self._slot_reads/_slot_writes to exist.
        """
        if self.vpc_slot is None or not hasattr(self, '_slot_reads'):
            print('[TraceAdimehtFISH] VMOP detection skipped: VPC not set')
            return

        slot_reads  = self._slot_reads
        slot_writes = self._slot_writes

        best_offset = None
        best_rpw    = -1.0

        for offset, reads in slot_reads.items():
            if offset == self.vpc_slot or offset == self.vhtp_slot:
                continue
            writes = slot_writes.get(offset, 0)
            if writes < _VMOP_MIN_WRITES:
                continue
            # All observed values must fit in a byte (opcode is 1 byte)
            vals = [v for (_, v) in reads if v != 0]
            if not vals or max(vals) > 0xFF:
                continue
            rpw = len(reads) / writes
            if rpw < _VMOP_MIN_RPW:
                continue
            # Compute pointer-dereference ratio — must be LOW for VMOP
            ptr_hits = 0
            for (ri, val) in reads:
                if val == 0:
                    continue
                found = False
                for j in range(ri + 1, min(ri + _VPC_LOOKAHEAD, len(self.traces))):
                    for m2 in (self.traces[j].get('mem') or []):
                        if val <= m2.get('addr', 0) <= val + _VPC_OFFSET_SLACK:
                            found = True
                            break
                    if found:
                        break
                if found:
                    ptr_hits += 1
            ptr_ratio = ptr_hits / len(reads)
            if ptr_ratio > _VMOP_MAX_PTR_RATIO:
                continue
            if rpw > best_rpw:
                best_rpw    = rpw
                best_offset = offset

        if best_offset is not None:
            self.vmop_slot = best_offset
            rc = len(slot_reads[best_offset])
            wc = slot_writes.get(best_offset, 0)
            print(f'[TraceAdimehtFISH] VMOP = VB_0x{self.vmop_slot:x}'
                  f'  addr={hex(self.vbr + self.vmop_slot)}'
                  f'  reads={rc}  writes={wc}  rpw={best_rpw:.1f}')
        else:
            print('[TraceAdimehtFISH] VMOP detection failed: no byte-range high-RPW slot found')

    # =========================================================================
    # VBR detection
    # =========================================================================

    def _detect_vbr(self) -> None:
        """Find VBR by locating the most common EBP value across all trace rows."""
        counter = collections.Counter()
        for t in self.traces:
            regs = t.get('regs')
            if regs and len(regs) > _EBP_IDX:
                counter[regs[_EBP_IDX]] += 1
        if counter:
            top3 = counter.most_common(3)
            self.vbr, count = top3[0]
            print(f'[TraceAdimehtFISH] VBR = {hex(self.vbr)} (EBP held this value in {count} rows)')
            print(f'[TraceAdimehtFISH] Top EBP values:')
            for rank, (val, cnt) in enumerate(top3, 1):
                print(f'  #{rank}: {hex(val)} — {cnt} rows')
        else:
            print('[TraceAdimehtFISH] VBR detection failed: no register data found')

    # =========================================================================
    # VPC + VHTP detection (single mem pass)
    # =========================================================================

    def _detect_vpc_and_vhtp(self) -> None:
        """Detect the VPC and VHTP VB slots in one pass over mem entries.

        VPC: the slot whose value is dereferenced as a bytecode fetch address
              immediately after being read (highest pointer-dereference ratio).
        VHTP:  among remaining stable slots, the one whose single constant value
              is strictly below all observed VPC values.

        Requires self.vbr to be set; skips silently if not.
        """
        if self.vbr is None:
            print('[TraceAdimehtFISH] VPC/VHTP detection skipped: VBR not set')
            return

        # slot_reads[offset]  = [(row_idx, value), ...]
        # slot_writes[offset] = write count
        slot_reads  = collections.defaultdict(list)
        slot_writes = collections.defaultdict(int)

        for i, t in enumerate(self.traces):
            for m in (t.get('mem') or []):
                offset = m.get('addr', 0) - self.vbr
                if not (0 <= offset < _VBR_SLOT_RANGE):
                    continue
                if m.get('access') == 'READ':
                    slot_reads[offset].append((i, m.get('value', 0)))
                else:
                    slot_writes[offset] += 1

        # ── VPC ─────────────────────────────────────────────────────────────
        best_offset = None
        best_score  = -1.0
        for offset, reads in slot_reads.items():
            if len(reads) < _VPC_MIN_READS:
                continue
            ptr_hits = 0
            for (ri, val) in reads:
                if val == 0:
                    continue
                found = False
                for j in range(ri + 1, min(ri + _VPC_LOOKAHEAD, len(self.traces))):
                    for m2 in (self.traces[j].get('mem') or []):
                        if val <= m2.get('addr', 0) <= val + _VPC_OFFSET_SLACK:
                            found = True
                            break
                    if found:
                        break
                if found:
                    ptr_hits += 1
            score = ptr_hits / len(reads)
            if score > best_score:
                best_score  = score
                best_offset = offset

        if best_offset is not None and best_score > _VPC_MIN_SCORE:
            self.vpc_slot = best_offset
            rc = len(slot_reads[best_offset])
            wc = slot_writes.get(best_offset, 0)
            print(f'[TraceAdimehtFISH] VPC = VB_0x{self.vpc_slot:x}'
                  f'  addr={hex(self.vbr + self.vpc_slot)}'
                  f'  reads={rc}  writes={wc}  ptr_ratio={best_score:.1%}')
        else:
            print('[TraceAdimehtFISH] VPC detection failed: no slot with high pointer-dereference ratio')
            return  # VHTP needs VPC

        # ── VHTP ──────────────────────────────────────────────────────────────
        vpc_seen = {v for (_, v) in slot_reads[self.vpc_slot] if v}
        if not vpc_seen:
            print('[TraceAdimehtFISH] VHTP detection failed: no non-zero VPC values observed')
            return

        min_vpc = min(vpc_seen)
        best_vhtp_offset = None
        best_vhtp_reads  = -1
        best_vhtp_value  = None

        for offset, reads in slot_reads.items():
            if offset == self.vpc_slot:
                continue
            if slot_writes.get(offset, 0) > _VHTP_MAX_WRITES:
                continue
            vals = [v for (_, v) in reads if v]
            if not vals:
                continue
            unique = set(vals)
            if len(unique) != 1:
                continue                      # must be perfectly stable
            v = next(iter(unique))
            if v <= 0x10000:
                continue                      # skip non-address constants
            if v >= min_vpc:
                continue                      # must be strictly below all VPC values
            if not all(v <= vpc for vpc in vpc_seen):
                continue                      # 100 % coverage required
            if len(reads) > best_vhtp_reads:
                best_vhtp_reads  = len(reads)
                best_vhtp_offset = offset
                best_vhtp_value  = v

        if best_vhtp_offset is not None:
            self.vhtp_slot = best_vhtp_offset
            wc = slot_writes.get(self.vhtp_slot, 0)
            print(f'[TraceAdimehtFISH] VHTP = VB_0x{self.vhtp_slot:x}'
                  f'  addr={hex(self.vbr + self.vhtp_slot)}'
                  f'  value={hex(best_vhtp_value)}'
                  f'  reads={best_vhtp_reads}  writes={wc}')
        else:
            print('[TraceAdimehtFISH] VHTP detection failed: no stable lower-bound slot found')

        # preserve slot data for _detect_vmop
        self._slot_reads  = slot_reads
        self._slot_writes = slot_writes
        self._detect_vmop()
