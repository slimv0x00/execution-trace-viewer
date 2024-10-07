from plugins.TraceContext import TraceContext

import capstone


class TraceOperandForX64DbgTrace:
    operand_type: str = None
    operand_name: str = None
    operand_value: int = 0

    # data only exists when the type is mem
    memory_formula: list[str] = []
    # data only exists when the type is reg
    upper_register = None

    # context
    context: TraceContext = None

    # type : 'reg' | 'imm', | 'mem' | 'fp' | 'invalid' | 'unknown',
    # name : 'eax' | '0x100' | [0x401000] | ? | 'invalid' | 'unknown',
    # value : 0x100 | 0x100 | 0x401000 (=addr) | ? | ? | ?,
    # formula : None | None | ['[', 'esp', '+', 40, ']'] | None | None | None,
    def __init__(self, context: TraceContext, capstone_operand):
        self.context = context
        if capstone_operand is not None:
            self.init_operand_by_capstone_operand(capstone_operand)

    def force_set_operand(self, operand_type: str, operand_name: str, operand_value: int, memory_formula: list[str]):
        self.set_operand_type(operand_type)
        self.set_operand_name(operand_name)
        self.set_operand_value(operand_value)
        self.set_memory_formula(memory_formula)
        if operand_type == 'reg':
            _upper_register_name = self.context.get_upper_register_name(operand_name)
            self.set_upper_register(_upper_register_name)

    def force_set_operand_as_register(self, operand_name: str):
        self.set_operand_type('reg')
        self.set_operand_name(operand_name)
        self.set_operand_value(self.context.get_register_value(operand_name))
        self.set_memory_formula([])
        _upper_register_name = self.context.get_upper_register_name(operand_name)
        self.set_upper_register(_upper_register_name)

    def __str__(self):
        return '< %s : %s : 0x%08x : %s >' % (
            self.get_operand_type(),
            self.get_operand_name(),
            self.get_operand_value(),
            str(self.get_memory_formula())
        )

    def init_operand_by_capstone_operand(self, capstone_operand):
        if capstone_operand.type == capstone.x86.X86_OP_REG:
            _register_name = self.context.current_capstone_instruction.reg_name(capstone_operand.value.reg)
            _upper_register_name = self.context.get_upper_register_name(_register_name)
            _register_value = self.context.get_register_value(_register_name)
            self.set_operand_type('reg')
            self.set_operand_name(_register_name)
            self.set_operand_value(_register_value)
            self.set_memory_formula([])
            self.set_upper_register(_upper_register_name)
        elif capstone_operand.type == capstone.x86.X86_OP_IMM:
            self.set_operand_type('imm')
            self.set_operand_name('0x%x' % capstone_operand.value.imm)
            self.set_operand_value(capstone_operand.value.imm)
            self.set_memory_formula([])
        elif capstone_operand.type == capstone.x86.X86_OP_MEM:
            _memory_address, _memory_formula = self.retrieve_memory_address_and_formula_from_operand(capstone_operand)
            self.set_operand_type('mem')
            self.set_operand_name('[0x%08x]' % _memory_address)
            self.set_operand_value(_memory_address)
            self.set_memory_formula(_memory_formula)
        elif capstone_operand.type == capstone.x86.X86_OP_INVALID:
            raise Exception('[E] Operand with an invalid type has been found')
        else:
            raise Exception('[E] Operand with an unknown type has been found')

    def get_operand_type(self) -> str:
        return self.operand_type

    def get_operand_name(self) -> str:
        return self.operand_name

    def get_operand_value(self) -> int:
        return self.operand_value

    def get_memory_formula(self) -> list[str]:
        return self.memory_formula[:]

    def get_upper_register(self) -> str:
        return self.upper_register

    def set_operand_type(self, operand_type: str):
        self.operand_type = operand_type

    def set_operand_name(self, operand_name: str):
        self.operand_name = operand_name

    def set_operand_value(self, operand_value: int):
        self.operand_value = operand_value

    def set_memory_formula(self, memory_formula: list[str]):
        self.memory_formula = memory_formula

    def set_upper_register(self, upper_register: str):
        self.upper_register = upper_register

    def is_same_operand(self, operand) -> bool:
        _my_operand_type = self.get_operand_type()
        _entered_operand_type = operand.get_operand_type()
        if _my_operand_type != _entered_operand_type:
            return False
        _my_operand_name = self.get_operand_name()
        _entered_operand_name = operand.get_operand_name()
        if _my_operand_name != _entered_operand_name:
            return False
        return True

    def has_same_value(self, operand) -> bool:
        _my_operand_value = self.get_operand_value()
        _entered_operand_value = operand.get_operand_value()
        if _my_operand_value != _entered_operand_value:
            return False
        return True

    def retrieve_memory_address_and_formula_from_operand(self, operand) -> (int, list[str]):
        _memory_formula = ['[']
        _segment = operand.value.mem.segment
        _base = operand.value.mem.base
        _index = operand.value.mem.index
        _scale = operand.value.mem.scale
        _disp = operand.value.mem.disp
        _base_value = 0
        _index_value = 0
        if _segment != 0:
            _memory_formula.append(self.context.current_capstone_instruction.reg_name(_segment))
            _memory_formula.append(':')
        if _base != 0:
            _base_register_name = self.context.current_capstone_instruction.reg_name(_base)
            _base_value = self.context.get_register_value(_base_register_name)
            _memory_formula.append(_base_register_name)
        if _index != 0:
            _index_register_name = self.context.current_capstone_instruction.reg_name(_index)
            _index_value = self.context.get_register_value(_index_register_name)
            _memory_formula.append("+")
            _memory_formula.append("%s" % _index_register_name)
        if _scale > 1:
            _memory_formula.append("*")
            _memory_formula.append('0x%08x' % _scale)
        if _disp != 0:
            if _disp > 0:
                _memory_formula.append("+")
                _memory_formula.append(_disp)
            else:
                _memory_formula.append("-")
                _memory_formula.append(-_disp)
        _memory_formula.append(']')

        _memory_address = _base_value + (_index_value * _scale) + _disp
        return _memory_address, _memory_formula

    def is_the_operand_derived_from_me(self, operand) -> bool:
        _my_operand_name = self.get_operand_name()
        _operand_formula = operand.get_memory_formula()
        for _operand_formula_element in _operand_formula:
            if _my_operand_name == _operand_formula_element:
                return True
        return False
