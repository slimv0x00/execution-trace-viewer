from .TraceOperand import OperandType


class TraceAdimeht:
    """VM Structure Mapper — classifies VBR-relative memory accesses as VB/VR/VL.

    Register state model (no Z3):
        ('vbr_ptr', offset)    — register = VBR + constant
        ('vm_val', role)       — register holds value derived from a classified VM element
        ('vbr_val_ptr', role)  — register = VBR + value_from_{role}
        None                   — untracked
    """

    # Roles mapped to their depth
    ROLE_DEPTH = {'VB': 1, 'VR': 2, 'VL': 3}
    # Next role when dereferencing a value from a given role
    NEXT_ROLE = {'VB': 'VR', 'VR': 'VL'}

    def __init__(self, ctx):
        """
        :param ctx: TraceContext instance (used for concrete state + address resolution only)
        """
        self.ctx = ctx
        self.is_vbr_initialized = False

        # Register states: ROOT reg_name (lowercase) -> tuple or None
        self.reg_states = {}

        # Classified VM elements: concrete_addr -> (role, depth, offset)
        # e.g. 0x55568a + 0x1c -> ('VB', 1, 0x1c)
        self.vm_elements = {}

        # VBR register name (architecture-dependent)
        self._vbr_reg = 'ebp' if ctx.arch_mode == 32 else 'rbp'

        # Instruction handlers
        self._handlers = {
            'MOV': self._handle_mov,
            'MOVZX': self._handle_mov,
            'MOVSX': self._handle_mov,
            'ADD': self._handle_add_sub,
            'SUB': self._handle_add_sub,
            'LEA': self._handle_lea,
            'XCHG': self._handle_xchg,
        }

    # =========================================================================
    # Register Name Normalization (sub-register → root register)
    # =========================================================================
    def _root_reg(self, reg_name):
        """Normalize a register name to its root register.

        e.g. 32-bit: dx → edx, al → eax, esi → esi
             64-bit: eax → rax, r8d → r8
        """
        root, _, _ = self.ctx._get_root_register_info(reg_name.lower())
        return root

    def _get_state(self, reg_name):
        """Get reg_state using the root register name."""
        return self.reg_states.get(self._root_reg(reg_name))

    # =========================================================================
    # VBR Lifecycle
    # =========================================================================
    def init_vbr(self):
        self.reg_states[self._vbr_reg] = ('vbr_ptr', 0)
        self.is_vbr_initialized = True

    def clear_vbr(self):
        self.reg_states.clear()
        self.is_vbr_initialized = False

    # =========================================================================
    # Main Entry
    # =========================================================================
    def process_instruction(self, inst_data):
        if not self.is_vbr_initialized:
            return True

        inst_obj = inst_data.get('instruction_obj')
        if inst_obj:
            mnemonic = inst_obj.mnemonic.upper()
        else:
            disasm = inst_data.get('disasm', '').upper()
            parts = disasm.split()
            mnemonic = parts[0] if parts else ''
            if mnemonic == 'LOCK' and len(parts) > 1:
                mnemonic = parts[1]

        operands = inst_data.get('parsed_operands', [])
        ip = inst_data.get('ip')

        # Phase 1: Analyze instruction with CURRENT reg_states → classify + compute new tags
        # new_tags uses ROOT register names as keys
        new_tags = {}
        if mnemonic in self._handlers:
            new_tags = self._handlers[mnemonic](operands, ip, mnemonic)
        else:
            # Unknown instruction: clear all destination registers
            new_tags = self._clear_destinations(operands)

        # Phase 2: Parse regchanges → clear tags for modified registers (except freshly tagged)
        # regchanges already uses root register names (e.g. 'edx' not 'dx')
        regchanges_str = inst_data.get('regchanges', '')
        changed_regs = self._parse_regchanges(regchanges_str)
        for reg in changed_regs:
            root = self._root_reg(reg)
            if root not in new_tags:
                self.reg_states.pop(root, None)

        # Phase 3: Apply new tags
        for reg, state in new_tags.items():
            if state is None:
                self.reg_states.pop(reg, None)
            else:
                self.reg_states[reg] = state

        return True

    # =========================================================================
    # Instruction Handlers
    # Each returns dict of {ROOT_reg_name: new_state_or_None}
    # =========================================================================
    def _handle_mov(self, operands, ip, mnemonic):
        if len(operands) < 2:
            return {}
        dst, src = operands[0], operands[1]

        # Only handle reg destinations
        if dst.type != OperandType.REG:
            # MOV [mem], reg — check if writing to a classified address (no state change)
            if dst.type == OperandType.MEM:
                self._try_classify_mem_operand(dst, ip)
            return {}

        dst_reg = self._root_reg(dst.reg_name)

        # src = VBR register
        if src.type == OperandType.REG and self._root_reg(src.reg_name) == self._vbr_reg:
            return {dst_reg: ('vbr_ptr', 0)}

        # src = register → copy state
        if src.type == OperandType.REG:
            src_state = self._get_state(src.reg_name)
            return {dst_reg: src_state}

        # src = [mem] → try to classify the memory access
        if src.type == OperandType.MEM:
            classification = self._try_classify_mem_operand(src, ip)
            if classification is not None:
                role, depth, offset = classification
                return {dst_reg: ('vm_val', role, depth)}

            # Not VBR-relative, but check if base is VM-derived →
            # loading from a VM-derived address produces a VM-derived value
            mem = src.mem_info
            base = (mem.get('base') or '').lower()
            if base:
                base_state = self._get_state(base)
                if base_state and base_state[0] == 'vm_val' and len(base_state) >= 3:
                    return {dst_reg: ('vm_val', base_state[1], base_state[2])}

            return {dst_reg: None}

        # src = immediate → clear
        return {dst_reg: None}

    def _handle_add_sub(self, operands, ip, mnemonic):
        if len(operands) < 2:
            return {}
        dst, src = operands[0], operands[1]

        if dst.type != OperandType.REG:
            return {}

        dst_reg = self._root_reg(dst.reg_name)
        dst_state = self.reg_states.get(dst_reg)

        # dst = ('vbr_ptr', X), src = imm → ('vbr_ptr', X ± imm)
        if dst_state and dst_state[0] == 'vbr_ptr' and src.type == OperandType.IMM:
            old_offset = dst_state[1]
            imm = src.imm_value
            mask = (1 << self.ctx.arch_mode) - 1
            if mnemonic == 'ADD':
                new_offset = (old_offset + imm) & mask
            else:  # SUB
                new_offset = (old_offset - imm) & mask
            return {dst_reg: ('vbr_ptr', new_offset)}

        # dst = ('vm_val', role), src = imm → preserve ('vm_val', role)
        # Adding/subtracting a constant to a VM-derived value doesn't change its VM-derived nature
        if dst_state and dst_state[0] == 'vm_val' and src.type == OperandType.IMM:
            return {dst_reg: dst_state}

        # dst = ('vm_val', role), src = VBR register (ADD only) → ('vbr_val_ptr', role)
        if (mnemonic == 'ADD' and dst_state and dst_state[0] == 'vm_val'
                and src.type == OperandType.REG and self._root_reg(src.reg_name) == self._vbr_reg):
            return {dst_reg: ('vbr_val_ptr', dst_state[1])}

        # Symmetric: dst = VBR register state, src has ('vm_val', role) (ADD only)
        if (mnemonic == 'ADD' and dst_state and dst_state[0] == 'vbr_ptr' and dst_state[1] == 0
                and src.type == OperandType.REG):
            src_state = self._get_state(src.reg_name)
            if src_state and src_state[0] == 'vm_val':
                return {dst_reg: ('vbr_val_ptr', src_state[1])}

        # Everything else → clear
        return {dst_reg: None}

    def _handle_lea(self, operands, ip, mnemonic):
        if len(operands) < 2:
            return {}
        dst, src = operands[0], operands[1]

        if dst.type != OperandType.REG or src.type != OperandType.MEM:
            return {}

        dst_reg = self._root_reg(dst.reg_name)
        mem = src.mem_info
        base = (mem.get('base') or '').lower()
        index = (mem.get('index') or '').lower()
        disp = mem.get('disp', 0)

        mask = (1 << self.ctx.arch_mode) - 1

        base_root = self._root_reg(base) if base else ''
        index_root = self._root_reg(index) if index else ''

        # base=VBR, no index → ('vbr_ptr', disp)
        if base_root == self._vbr_reg and not index:
            return {dst_reg: ('vbr_ptr', disp & mask)}

        # base=VBR, index has ('vm_val', role) → ('vbr_val_ptr', role)
        if base_root == self._vbr_reg and index:
            idx_state = self._get_state(index)
            if idx_state and idx_state[0] == 'vm_val':
                return {dst_reg: ('vbr_val_ptr', idx_state[1])}

        # base has ('vbr_ptr', X), no index → ('vbr_ptr', X + disp)
        if base and not index:
            base_state = self._get_state(base)
            if base_state and base_state[0] == 'vbr_ptr':
                new_offset = (base_state[1] + disp) & mask
                return {dst_reg: ('vbr_ptr', new_offset)}

        # Everything else → clear
        return {dst_reg: None}

    def _handle_xchg(self, operands, ip, mnemonic):
        if len(operands) < 2:
            return {}
        op1, op2 = operands[0], operands[1]

        if op1.type != OperandType.REG or op2.type != OperandType.REG:
            # If either is memory, clear both reg states involved
            result = {}
            if op1.type == OperandType.REG:
                result[self._root_reg(op1.reg_name)] = None
            if op2.type == OperandType.REG:
                result[self._root_reg(op2.reg_name)] = None
            return result

        r1 = self._root_reg(op1.reg_name)
        r2 = self._root_reg(op2.reg_name)
        s1 = self.reg_states.get(r1)
        s2 = self.reg_states.get(r2)
        return {r1: s2, r2: s1}

    def _clear_destinations(self, operands):
        """For unhandled instructions, clear state of all written registers."""
        result = {}
        from .TraceOperand import OperandAccess
        for op in operands:
            if op.type == OperandType.REG and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                result[self._root_reg(op.reg_name)] = None
        return result

    # =========================================================================
    # Memory Access Classification
    # =========================================================================
    def _try_classify_mem_operand(self, mem_op, ip):
        """Classify a memory operand as VB/VR/VL if it's VBR-relative.

        Returns (role, depth, offset) or None.
        Already-classified addresses keep their existing role.
        """
        addr_c, _ = mem_op.resolve_addr(self.ctx, ip)

        # Already classified?
        if addr_c in self.vm_elements:
            return self.vm_elements[addr_c]

        mem = mem_op.mem_info
        base = (mem.get('base') or '').lower()
        index = (mem.get('index') or '').lower()
        disp = mem.get('disp', 0)

        classification = None
        mask = (1 << self.ctx.arch_mode) - 1

        base_root = self._root_reg(base) if base else ''
        index_root = self._root_reg(index) if index else ''

        # Pattern 1: base=VBR, no index → VB (depth 1)
        if base_root == self._vbr_reg and not index:
            vbr_c, _, _ = self.ctx.get_register(self._vbr_reg)
            offset = (addr_c - vbr_c) & mask
            classification = ('VB', 1, offset)

        # Pattern 2: base=VBR, index has ('vm_val', role) → next depth
        elif base_root == self._vbr_reg and index:
            idx_state = self._get_state(index)
            if idx_state and idx_state[0] == 'vm_val':
                src_role = idx_state[1]
                if src_role in self.NEXT_ROLE:
                    next_role = self.NEXT_ROLE[src_role]
                    vbr_c, _, _ = self.ctx.get_register(self._vbr_reg)
                    offset = (addr_c - vbr_c) & mask
                    classification = (next_role, self.ROLE_DEPTH[next_role], offset)

        # Pattern 3: base (non-VBR) with no index → check reg state
        elif base and not index:
            base_state = self._get_state(base)
            if base_state:
                if base_state[0] == 'vbr_ptr':
                    # register = VBR + const → VB (depth 1)
                    offset = (base_state[1] + disp) & mask
                    classification = ('VB', 1, offset)
                elif base_state[0] == 'vbr_val_ptr':
                    # register = VBR + value_from_{role} → next depth
                    src_role = base_state[1]
                    if src_role in self.NEXT_ROLE:
                        next_role = self.NEXT_ROLE[src_role]
                        vbr_c, _, _ = self.ctx.get_register(self._vbr_reg)
                        offset = (addr_c - vbr_c) & mask
                        classification = (next_role, self.ROLE_DEPTH[next_role], offset)
                elif base_state[0] == 'vm_val' and len(base_state) >= 3:
                    # Dereferencing a VM value as pointer → same role, depth + 1
                    src_role = base_state[1]
                    src_depth = base_state[2]
                    vbr_c, _, _ = self.ctx.get_register(self._vbr_reg)
                    offset = (addr_c - vbr_c) & mask
                    classification = (src_role, src_depth + 1, offset)

        if classification is not None:
            self.vm_elements[addr_c] = classification

        return classification

    # =========================================================================
    # Regchanges Parsing
    # =========================================================================
    @staticmethod
    def _parse_regchanges(regchanges_str):
        """Parse 'ebp: 0x4ff8 ecx: 0x1234' → {'ebp', 'ecx'}"""
        if not regchanges_str or not regchanges_str.strip():
            return set()
        result = set()
        raw = regchanges_str.replace(':', '').split()
        for i in range(0, len(raw), 2):
            result.add(raw[i].lower())
        return result

    # =========================================================================
    # Public Queries
    # =========================================================================
    def get_element_at(self, addr):
        """Return classification info (role, depth, offset) or None."""
        return self.vm_elements.get(addr)

    def get_vm_elements_snapshot(self):
        """Return list of classified elements for UI display.

        Format: [{'name': 'VB_1_0x1c @ 0x55568a', 'symbol': 'VB'}, ...]
        """
        result = []
        for addr, (role, depth, offset) in sorted(self.vm_elements.items()):
            label = f"{role}_{depth}_{hex(offset)}"
            result.append({
                'name': f"{label} @ {hex(addr)}",
                'symbol': role,
            })
        return result
