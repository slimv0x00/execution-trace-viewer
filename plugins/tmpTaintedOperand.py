from plugins.tmpContext import TmpContext
from plugins.tmpOperand import TmpOperandForX64DbgTrace

import capstone


class TmpTaintedOperandForX64DbgTrace(TmpOperandForX64DbgTrace):
    tainted_by: list[str] = []
    determined_roles: list[str] = []
    vm_part: str = ''
    derived_from: str = ''

    def __str__(self):
        return '< %s : %s : %s : %s : 0x%08x : %s >' % (
            self.get_determined_roles(),
            str(self.get_tainted_by()),
            self.get_operand_type(),
            self.get_operand_name(),
            self.get_operand_value(),
            str(self.get_memory_formula()),
        )

    def get_tainted_by(self) -> list[str]:
        return self.tainted_by

    def get_determined_roles(self) -> list[str]:
        return self.determined_roles

    def get_vm_part(self) -> str:
        return self.vm_part

    def get_derived_from(self) -> str:
        return self.derived_from

    def set_tainted_by(self, tainted_by):
        self.tainted_by = tainted_by

    def set_determined_roles(self, determined_roles: list[str]):
        self.determined_roles = determined_roles

    def set_vm_part(self, vm_part):
        self.vm_part = vm_part

    def set_derived_from(self, derived_from: str):
        self.derived_from = derived_from

    def force_set_tainted_operand(
        self,
        operand_type: str,
        operand_name: str,
        operand_value: int,
        operand_formula: list[str],
        tainted_by: list[str],
        determined_roles: list[str],
    ):
        super().force_set_operand(operand_type, operand_name, operand_value, operand_formula)
        self.set_tainted_by(tainted_by)
        self.set_determined_roles(determined_roles)

    def force_set_tainted_operand_as_register(
        self,
        operand_name: str,
        tainted_by: list[str],
        determined_role: list[str],
    ):
        super().force_set_operand_as_register(operand_name)
        self.set_tainted_by(tainted_by)
        self.set_determined_roles(determined_role)

    def is_the_operand_derived_from_me(self, operand: TmpOperandForX64DbgTrace) -> bool:
        _my_operand_name = self.get_operand_name()
        _operand_formula = operand.get_memory_formula()
        for _operand_formula_element in _operand_formula:
            if _my_operand_name == _operand_formula_element:
                return True
        return False

    def has_determined_role(self, determined_role_to_find) -> bool:
        _determined_roles = self.get_determined_roles()
        return determined_role_to_find in _determined_roles
