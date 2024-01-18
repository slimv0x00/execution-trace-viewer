import capstone


class TmpContext:
    # capstone.Cs
    capstone_bridge = None

    x64dbg_trace = None
    current_capstone_instruction = None

    # index in register array accessible via trace['regs'] in x64dbg trace
    register_index_in_x64dbg_trace = {
        'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7, 'eip': 8, 'eflags': 9,
    }
    register_names = [
        'eax', 'ax', 'ah', 'al',
        'ebx', 'bx', 'bh', 'bl',
        'ecx', 'cx', 'ch', 'cl',
        'edx', 'dx', 'dh', 'dl',
        'esp', 'sp',
        'ebp', 'bp',
        'esi', 'si',
        'edi', 'di',
        'eip',
        'eflags',
    ]

    def __init__(self, capstone_bridge=None):
        if capstone_bridge is None:
            self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.capstone_bridge.detail = True
        else:
            self.capstone_bridge = capstone_bridge

    def get_register_names(self) -> list[str]:
        return self.register_names

    def get_upper_register_name(self, register_name: str) -> str:
        _upper_register = None
        if register_name in ['eax', 'ax', 'ah', 'al']:
            _upper_register = 'eax'
        elif register_name in ['ebx', 'bx', 'bh', 'bl']:
            _upper_register = 'ebx'
        elif register_name in ['ecx', 'cx', 'ch', 'cl']:
            _upper_register = 'ecx'
        elif register_name in ['edx', 'dx', 'dh', 'dl']:
            _upper_register = 'edx'
        elif register_name in ['esp', 'sp']:
            _upper_register = 'esp'
        elif register_name in ['ebp', 'bp']:
            _upper_register = 'ebp'
        elif register_name in ['esi', 'si']:
            _upper_register = 'esi'
        elif register_name in ['edi', 'di']:
            _upper_register = 'edi'
        elif register_name in ['eip']:
            _upper_register = 'eip'
        elif register_name in ['eflags']:
            _upper_register = 'eflags'
        else:
            raise Exception('[E] Invalid register name : %s' % register_name)
        return _upper_register

    def set_context_by_x64dbg_trace(self, x64dbg_trace):
        self.x64dbg_trace = x64dbg_trace
        _instructions = list(self.capstone_bridge.disasm(bytes.fromhex(x64dbg_trace['opcodes']), x64dbg_trace['ip']))
        if len(_instructions) > 1:
            raise Exception('[E] A length of disassembled code over 1 : %d' % len(_instructions))
        self.current_capstone_instruction = _instructions[0]

    def get_register_value_from_x64dbg_trace(self, register_name: str) -> int:
        _upper_register_name = self.get_upper_register_name(register_name)
        _register_value = self.x64dbg_trace['regs'][self.register_index_in_x64dbg_trace[_upper_register_name]]
        if register_name in ['ax', 'cx', 'dx', 'bx', 'sp', 'bp', 'si', 'di']:
            _register_value &= 0x0000FFFF
        elif register_name in ['ah', 'ch', 'dh', 'bh']:
            _register_value &= 0x0000FF00
        elif register_name in ['al', 'cl', 'dl', 'bl']:
            _register_value &= 0x000000FF
        return _register_value

    def get_register_value(self, register_name: str) -> int:
        return self.get_register_value_from_x64dbg_trace(register_name)
