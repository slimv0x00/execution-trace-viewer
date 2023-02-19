from yapsy.IPlugin import IPlugin
from operator import itemgetter
from core.api import Api
import capstone


class PluginMvAdimeht(IPlugin):
    md = None
    api = None

    tainted = []

    def get_register_value_from_trace(self, trace, reg_name):
        _reg_index = {
            'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7,
            'eip': 8, 'eflags': 9,
            'ax': 0, 'cx': 1, 'dx': 2, 'bx': 3, 'sp': 4, 'bp': 5, 'si': 6, 'di': 7,
            'ah': 0, 'ch': 1, 'dh': 2, 'bh': 3,
            'al': 0, 'cl': 1, 'dl': 2, 'bl': 3,
        }
        return trace['regs'][_reg_index[reg_name]]

    def get_operands(self, trace, instruction):
        _operands = []
        if len(instruction.operands) == 0:
            return _operands
        for _op in instruction.operands:
            # {
            #   type : 'reg' | 'imm', | 'mem' | 'fp' | 'invalid' | 'unknown',
            #   name : 'eax' | '0x100' | [0x401000] | ? | 'invalid' | 'unknown',
            #   value : 0x100 | 0x100 | 0x401000 (=addr) | ? | ? | ?,
            #   formula : None | None | ['[', 'esp', '+', 40, ']'] | None | None | None,
            # }
            # _operand = {}
            if _op.type == capstone.x86.X86_OP_REG:
                _reg_name = instruction.reg_name(_op.value.reg)
                _operand = {
                    'type': 'reg',
                    'name': _reg_name,
                    'value': self.get_register_value_from_trace(trace, _reg_name),
                    'formula': None,
                }
                _operands.append(_operand)
            elif _op.type == capstone.x86.X86_OP_IMM:
                _operand = {
                    'type': 'imm',
                    'name': '0x%x' % _op.value.imm,
                    'value': _op.value.imm,
                    'formula': None,
                }
                _operands.append(_operand)
            elif _op.type == capstone.x86.X86_OP_MEM:
                _mem_formula = []
                _mem_formula.append('[')
                _segment = _op.value.mem.segment
                _base = _op.value.mem.base
                _index = _op.value.mem.index
                _scale = _op.value.mem.scale
                _disp = _op.value.mem.disp
                _base_value = 0
                _index_value = 0
                if _segment != 0:
                    _mem_formula.append(instruction.reg_name(_segment))
                    _mem_formula.append(':')
                if _base != 0:
                    _base_reg_name = instruction.reg_name(_base)
                    _base_value = self.get_register_value_from_trace(trace, _base_reg_name)
                    _mem_formula.append(_base_reg_name)
                if _index != 0:
                    _index_reg_name = instruction.reg_name(_index)
                    _index_value = self.get_register_value_from_trace(trace, _index_reg_name)
                    _mem_formula.append("+")
                    _mem_formula.append("%s" % _index_reg_name)
                if _scale > 1:
                    _mem_formula.append("*")
                    _mem_formula.append('0x%x' % _scale)
                if _disp != 0:
                    if _disp > 0:
                        _mem_formula.append("+")
                        _mem_formula.append(_disp)
                    else:
                        _mem_formula.append("-")
                        _mem_formula.append(-_disp)
                _mem_formula.append(']')
                _mem_addr = _base_value + (_index_value * _scale) + _disp

                _operand = {
                    'type': 'mem',
                    'name': '[0x%x]' % _mem_addr,
                    'value': _mem_addr,
                    'formula': _mem_formula,
                }
                _operands.append(_operand)
            elif _op.type == capstone.x86.X86_OP_FP:
                _operand = {
                    'type': 'fp',
                    'name': '%s' % _op.value.fp,
                    'value': _op.value.fp,
                    'formula': None,
                }
                _operands.append(_operand)
            elif _op.type == capstone.x86.X86_OP_INVALID:
                _operand = {
                    'type': 'invalid',
                    'name': 'invalid',
                    'value': _op.value,
                    'formula': None,
                }
                _operands.append(_operand)
            else:
                _operand = {
                    'type': 'unknown',
                    'name': 'unknown',
                    'value': _op,
                    'formula': None,
                }
                _operands.append(_operand)

        return _operands

    def _run_taint(self, trace, instruction, dst, src):
        _is_tainted = False
        for _src in src:
            if _src['name'] in self.tainted:
                # self.api.print('[!] %s' % _src['name'])
                _is_tainted = True
                break
        if _is_tainted:
            for _dst in dst:
                if _dst['name'] not in self.tainted:
                    # self.api.print('[+] %s' % _dst['name'])
                    self.tainted.append(_dst['name'])
        else:
            for _dst in dst:
                if _dst['name'] in self.tainted:
                    # self.api.print('[-] %s' % _dst['name'])
                    self.tainted.remove(_dst['name'])

    def get_dst_src(self, trace, instruction, operands):
        _dst = []
        _src = []
        self.api.print(trace)
        self.api.print(operands)
        if len(instruction.groups) > 0:
            for _g in instruction.groups:
                if _g == capstone.x86.X86_GRP_CALL:
                    _operand_value = self.get_register_value_from_trace(trace, 'esp') - 4
                    _dst.append({
                        'type': 'mem',
                        'name': '[0x%x]' % _operand_value,
                        'value': _operand_value,
                        'formula': '[ esp - 4 ]'.split(' '),
                    })
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src.append(operands[0])
                    return _dst, _src
                elif _g == capstone.x86.X86_GRP_JUMP:
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src.append(operands[0])
                    return _dst, _src

        if instruction.id == capstone.x86.X86_INS_PUSH:
            _operand_value = self.get_register_value_from_trace(trace, 'esp') - 4
            _dst.append({
                'type': 'mem',
                'name': '[0x%x]' % _operand_value,
                'value': _operand_value,
                'formula': '[ esp - 4 ]'.split(' '),
            })
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _src.append(operands[0])
        elif instruction.id == capstone.x86.X86_INS_PUSHFD:
            _operand_value = self.get_register_value_from_trace(trace, 'esp') - 4
            _dst.append({
                'type': 'mem',
                'name': '[0x%x]' % _operand_value,
                'value': _operand_value,
                'formula': '[ esp - 4 ]'.split(' '),
            })
            _reg_name = 'eflags'
            _src.append({
                'type': 'reg',
                'name': _reg_name,
                'value': self.get_register_value_from_trace(trace, _reg_name),
                'formula': None,
            })
        elif instruction.id == capstone.x86.X86_INS_POP:
            _operand_value = self.get_register_value_from_trace(trace, 'esp')
            _src.append({
                'type': 'mem',
                'name': '[0x%x]' % _operand_value,
                'value': _operand_value,
                'formula': '[ esp ]'.split(' '),
            })
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _dst.append(operands[0])
        elif instruction.id in [capstone.x86.X86_INS_MOV, capstone.x86.X86_INS_AND, capstone.x86.X86_INS_OR]:
            if len(operands) == 0 or len(operands) > 2:
                return None, None
            _dst.append(operands[0])
            _src.append(operands[1])
        elif instruction.id in [capstone.x86.X86_INS_XOR, capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB]:
            if len(operands) != 2:
                return None, None
            if operands[0]['name'] == operands[1]['name']:
                if operands[0]['name'] in self.tainted:
                    self.tainted.remove(operands[0]['name'])
                return [], []
            _was_tainted_1 = operands[1]['name'] in self.tainted
            if _was_tainted_1:
                if operands[0]['name'] not in self.tainted:
                    self.tainted.append(operands[0]['name'])
        elif instruction.id == capstone.x86.X86_INS_XCHG:
            if len(operands) != 2:
                return None, None
            _was_tainted_0 = operands[0]['name'] in self.tainted
            _was_tainted_1 = operands[1]['name'] in self.tainted
            if _was_tainted_0:
                self.tainted.remove(operands[0]['name'])
            if _was_tainted_1:
                self.tainted.remove(operands[1]['name'])
            if _was_tainted_0:
                self.tainted.append(operands[1]['name'])
            if _was_tainted_1:
                self.tainted.append(operands[0]['name'])
            return [], []
        elif instruction.id == capstone.x86.X86_INS_CMPXCHG:
            if len(operands) != 2:
                return None, None
            _was_tainted_1 = operands[1]['name'] in self.tainted
            if _was_tainted_1 is False:
                return [], []
            for _mem in trace['mem']:
                if _mem['access'] == 'WRITE' and _mem['addr'] == operands[0]['value']:
                    if operands[0]['name'] in self.tainted:
                        self.tainted.remove(operands[0]['name'])
                        break
            return [], []
        elif instruction.id in [capstone.x86.X86_INS_INC, capstone.x86.X86_INS_DEC, capstone.x86.X86_INS_NOT,
                                capstone.x86.X86_INS_TEST, capstone.x86.X86_INS_CMP, capstone.x86.X86_INS_SHL]:
            return [], []
        else:
            self.api.print('[E] Instruction ID : %s (https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h)' % instruction.id)
            return None, None
        return _dst, _src

    def run_taint(self, trace):
        _instructions = self.md.disasm(bytes.fromhex(trace['opcodes']), trace['ip'])
        for _inst in _instructions:
            _operands = self.get_operands(trace, _inst)
            _dst, _src = self.get_dst_src(trace, _inst, _operands)
            self.api.print('%d : 0x%x : %s : %s' % (trace['id'], trace['ip'], trace['disasm'], str(_operands)))
            self.api.print(' - src: %s' % _src)
            self.api.print(' - dst: %s' % _dst)
            if _src is None:
                return None
            self._run_taint(trace, _inst, _dst, _src)
            trace['comment'] = str(self.tainted)
        return trace

    def execute(self, api: Api):
        self.tainted = []
        self.api = api
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index(#)', 'data': 0},
            {'label': 'Target operand', 'data': 'eax'},
            {'label': 'TTL (no limit, -1)', 'data': 1000},
        ]
        _options = self.api.get_values_from_user("Filter by memory address", _input_dlg_data)
        if not _options:
            return
        _str_trace_boundary_begin, _str_trace_boundary_end, _target_index, _target_operand, _ttl = _options
        _trace_boundary_begin = int(_str_trace_boundary_begin, 16)
        _trace_boundary_end = int(_str_trace_boundary_end, 16)

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Boundary : 0x%08x ~ 0x%08x' % (_trace_boundary_begin, _trace_boundary_end))
        self.api.print(' - Target : %s at %d' % (_target_operand, _target_index))

        _traces = self.api.get_full_trace()
        _traces_to_show = []

        for _trace in _traces:
            # _trace
            # {
            #   'id': 0,
            #   'ip': 4242012,
            #   'disasm': 'push 0xaa0be70a',
            #   'comment': 'push encrypted vm_eip',
            #   'regs': [3806, 309, 326, 292, 0, 20476, 360, 377, 4242012, 0],
            #   'opcodes': '680ae70baa',
            #   'mem': [{'access': 'WRITE', 'addr': 20472, 'value': 2852906762}],
            #   'regchanges': 'ebp: 0x4ff8 '
            # }
            _index = _trace['id']
            if _ttl >= 0:
                if _index > _ttl:
                    break
            _eip = _trace['ip']
            if _eip < _trace_boundary_begin or _eip >= _trace_boundary_end:
                continue
            if _index == _target_index:
                self.tainted.append(_target_operand)

            _new_trace = self.run_taint(_trace)
            if _new_trace is None:
                _traces_to_show.append(_trace.copy())
                break
            _traces_to_show.append(_new_trace.copy())

        if len(_traces_to_show) > 0:
            print(f"Length of filtered trace: {len(_traces_to_show)}")
            self.api.set_filtered_trace(_traces_to_show)
            self.api.show_filtered_trace()
