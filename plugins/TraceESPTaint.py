from plugins.TraceOperand import OperandType


class TraceESPTaint:
    """Tracks pure value transfers of ESP (and ESP-derived values) through the trace.

    Only transfer instructions are handled; arithmetic is ignored.
    ESP itself is the taint source and is never stored in _tainted_regs.
    """

    # Maps partial 32-bit register names to their root name.
    _REG_ALIASES_32 = {
        'eax': 'eax', 'ax': 'eax', 'al': 'eax', 'ah': 'eax',
        'ebx': 'ebx', 'bx': 'ebx', 'bl': 'ebx', 'bh': 'ebx',
        'ecx': 'ecx', 'cx': 'ecx', 'cl': 'ecx', 'ch': 'ecx',
        'edx': 'edx', 'dx': 'edx', 'dl': 'edx', 'dh': 'edx',
        'esi': 'esi', 'si': 'esi',
        'edi': 'edi', 'di': 'edi',
        'ebp': 'ebp', 'bp': 'ebp',
        'esp': 'esp', 'sp': 'esp',
    }

    def __init__(self, ctx):
        self._ctx = ctx
        self._tainted_regs = set()  # lowercase root reg names (never contains 'esp')
        self._tainted_mem = {}      # addr (int) → size (int)

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _root_reg(self, reg_name):
        return self._REG_ALIASES_32.get(reg_name.lower(), reg_name.lower())

    def _is_esp(self, reg_name):
        return self._root_reg(reg_name) == 'esp'

    def _resolve_mem_addr(self, operand, esp_override=None):
        """Compute concrete memory address from operand.mem_info (no Z3).

        esp_override: if given, use this value instead of the ctx ESP register.
        Used by the push handler where ctx ESP is already post-push (decremented).
        """
        if operand.mem_info is None:
            return None
        info = operand.mem_info
        addr = 0
        base = info.get('base')
        if base:
            if esp_override is not None and self._root_reg(base) == 'esp':
                addr += esp_override
            else:
                c, _, _ = self._ctx.get_register(base)
                addr += c
        index = info.get('index')
        if index:
            scale = info.get('scale', 1)
            if esp_override is not None and self._root_reg(index) == 'esp':
                addr += esp_override * scale
            else:
                c, _, _ = self._ctx.get_register(index)
                addr += c * scale
        disp = info.get('disp', 0)
        addr += disp
        return addr & 0xFFFFFFFF

    def _is_tainted(self, operand, esp_override=None):
        """Return True if this operand carries an ESP-derived value."""
        if operand.type == OperandType.REG:
            if self._is_esp(operand.reg_name):
                return True  # ESP is always the taint source
            return self._root_reg(operand.reg_name) in self._tainted_regs
        elif operand.type == OperandType.MEM:
            addr = self._resolve_mem_addr(operand, esp_override)
            return addr is not None and addr in self._tainted_mem
        return False

    def _taint_dst(self, operand):
        if operand.type == OperandType.REG:
            if not self._is_esp(operand.reg_name):
                self._tainted_regs.add(self._root_reg(operand.reg_name))
        elif operand.type == OperandType.MEM:
            addr = self._resolve_mem_addr(operand)
            if addr is not None:
                self._tainted_mem[addr] = operand.size

    def _untaint_dst(self, operand):
        if operand.type == OperandType.REG:
            self._tainted_regs.discard(self._root_reg(operand.reg_name))
        elif operand.type == OperandType.MEM:
            addr = self._resolve_mem_addr(operand)
            if addr is not None:
                self._tainted_mem.pop(addr, None)

    def _get_esp(self):
        esp_val, _, _ = self._ctx.get_register('esp')
        return esp_val & 0xFFFFFFFF

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def process_instruction(self, trace):
        """Update taint state for one instruction."""
        ops = trace.get('parsed_operands', [])
        inst = trace.get('instruction_obj')
        if inst is None:
            return

        mnemonic = inst.mnemonic.lower()
        explicit = [op for op in ops if not op.is_implicit]

        if mnemonic in ('mov', 'movzx', 'movsx'):
            if len(explicit) >= 2:
                dst, src = explicit[0], explicit[1]
                if self._is_tainted(src):
                    self._taint_dst(dst)
                else:
                    self._untaint_dst(dst)

        elif mnemonic == 'push':
            if explicit:
                # ctx ESP is post-push (already decremented by 4).
                # Source address must be evaluated at pre-push ESP.
                pre_esp = (self._get_esp() + 4) & 0xFFFFFFFF
                if self._is_tainted(explicit[0], esp_override=pre_esp):
                    # post-push ESP is where the value was written
                    self._tainted_mem[self._get_esp()] = 4

        elif mnemonic == 'pop':
            if explicit:
                dst = explicit[0]
                # Value was read from [post-pop ESP - 4]
                read_addr = (self._get_esp() - 4) & 0xFFFFFFFF
                if read_addr in self._tainted_mem:
                    self._taint_dst(dst)
                else:
                    self._untaint_dst(dst)

        elif mnemonic == 'xchg':
            if len(explicit) >= 2:
                op1, op2 = explicit[0], explicit[1]
                t1 = self._is_tainted(op1)
                t2 = self._is_tainted(op2)
                self._untaint_dst(op1)
                self._untaint_dst(op2)
                if t2:
                    self._taint_dst(op1)
                if t1:
                    self._taint_dst(op2)

        elif mnemonic == 'pushad':
            # PUSHAD pushes EAX,ECX,EDX,EBX,orig_ESP,EBP,ESI,EDI (EDI ends at top).
            # Stack layout from post-PUSHAD ESP:
            #   [esp+0]=EDI, [esp+4]=ESI, [esp+8]=EBP, [esp+12]=orig_ESP,
            #   [esp+16]=EBX, [esp+20]=EDX, [esp+24]=ECX, [esp+28]=EAX
            esp_val = self._get_esp()
            pushad_slots = ['edi', 'esi', 'ebp', None, 'ebx', 'edx', 'ecx', 'eax']
            for i, reg in enumerate(pushad_slots):
                slot_addr = (esp_val + i * 4) & 0xFFFFFFFF
                if reg is None:
                    # ESP-value slot is always tainted (it held the value of ESP)
                    self._tainted_mem[slot_addr] = 4
                elif reg in self._tainted_regs:
                    self._tainted_mem[slot_addr] = 4
                else:
                    self._tainted_mem.pop(slot_addr, None)

        elif mnemonic == 'popad':
            # POPAD pops EDI,ESI,EBP,(skip ESP),EBX,EDX,ECX,EAX; ESP += 32.
            # Pre-POPAD ESP = post-POPAD ESP - 32.
            pre_esp = (self._get_esp() - 32) & 0xFFFFFFFF
            popad_slots = ['edi', 'esi', 'ebp', None, 'ebx', 'edx', 'ecx', 'eax']
            for i, reg in enumerate(popad_slots):
                if reg is None:
                    continue  # ESP slot is skipped by POPAD
                slot_addr = (pre_esp + i * 4) & 0xFFFFFFFF
                if slot_addr in self._tainted_mem:
                    self._tainted_regs.add(reg)
                else:
                    self._tainted_regs.discard(reg)

    def get_snapshot(self):
        """Return list of {'name': str, 'symbol': 'esp'} for all tainted locations."""
        result = []
        for reg in sorted(self._tainted_regs):
            result.append({'name': reg.upper(), 'symbol': 'esp'})
        for addr in sorted(self._tainted_mem):
            result.append({'name': f'Mem[0x{addr:08x}]', 'symbol': 'esp'})
        return result
