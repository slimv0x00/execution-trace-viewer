from plugins.TraceOperand import TraceOperandForX64DbgTrace


class TraceTaintedOperandForX64DbgTrace(TraceOperandForX64DbgTrace):
    tainted_by: list[str] = []
    derived_from: list[str] = []

    def __str__(self):
        return '< %s : %s : %s : 0x%08x : %s >' % (
            str(self.get_tainted_by()),
            self.get_operand_type(),
            self.get_operand_name(),
            self.get_operand_value(),
            str(self.get_memory_formula()),
        )

    def get_tainted_by(self) -> list[str]:
        return self.tainted_by[:]

    def get_derived_from(self) -> list[str]:
        return self.derived_from[:]

    def set_tainted_by(self, tainted_by):
        self.tainted_by = tainted_by

    def set_derived_from(self, derived_from: list[str]):
        self.derived_from = derived_from

    def force_set_tainted_operand(
        self,
        operand_type: str,
        operand_name: str,
        operand_value: int,
        operand_formula: list[str],
        tainted_by: list[str],
    ):
        super().force_set_operand(operand_type, operand_name, operand_value, operand_formula)
        self.set_tainted_by(tainted_by)

    def force_set_tainted_operand_as_register(
        self,
        operand_name: str,
        tainted_by: list[str],
    ):
        super().force_set_operand_as_register(operand_name)
        self.set_tainted_by(tainted_by)
