from plugins.TraceTaintedOperand import TraceTaintedOperandForX64DbgTrace


class TraceAdimehtOperandForX64DbgTrace(TraceTaintedOperandForX64DbgTrace):
    assignable_roles = {
        'IMM': 'immediate',
        'VBR': 'virtual base register',
        'VB': 'virtual bridge',
        'VR': 'virtual register',
    }
    determined_role: str = ''
    vm_part: str = ''

    def __str__(self):
        return '< %s : %s : %s : %s : 0x%08x : %s >' % (
            self.get_determined_role(),
            str(self.get_tainted_by()),
            self.get_operand_type(),
            self.get_operand_name(),
            self.get_operand_value(),
            str(self.get_memory_formula()),
        )

    def get_determined_role(self) -> str:
        return self.determined_role

    def get_vm_part(self) -> str:
        return self.vm_part

    def set_determined_roles(self, determined_role: str):
        if determined_role not in self.assignable_roles.keys():
            raise Exception('[E] Cannot assign a role to operand : %s' % determined_role)
        self.determined_role = determined_role

    def set_vm_part_by_using_offset_from_vbr(self, vbr):
        _offset = self.get_operand_value() - vbr.get_operand_value()
        self.force_set_vm_part('%s_0x%x' % (self.get_determined_role(), _offset))

    def force_set_vm_part(self, vm_part: str):
        self.vm_part = vm_part

    def force_set_adimeht_operand(
        self,
        operand_type: str,
        operand_name: str,
        operand_value: int,
        operand_formula: list[str],
        tainted_by: list[str],
        determined_role: str,
    ):
        super().force_set_operand(operand_type, operand_name, operand_value, operand_formula)
        self.set_tainted_by(tainted_by)
        self.set_determined_roles(determined_role)

    def force_set_adimeht_operand_as_register(
        self,
        operand_name: str,
        tainted_by: list[str],
        determined_role: str,
    ):
        super().force_set_operand_as_register(operand_name)
        self.set_tainted_by(tainted_by)
        self.set_determined_roles(determined_role)
