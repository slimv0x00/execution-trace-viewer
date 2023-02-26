from yapsy.IPlugin import IPlugin
from operator import itemgetter
from core.api import Api
import capstone
import traceback

class PluginMvAdimeht(IPlugin):
    md = None
    api = None

    # list of taint [
    #   {
    #     labels: ['your input', ...],
    #     name: 'eax' | '[0x401000]',
    #   }, ...
    # ]
    TAINTED = []

    # taints' type can be list of taint
    def get_aggregated_taints_names_by_labels(self, taints):
        _agg = {}
        for _taint in taints:
            _labels = _taint['labels']
            for _label in _labels:
                if _label not in _agg:
                    _agg[_label] = []
                _agg[_label].append(_taint['name'])
        return str(_agg)

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

    def are_operands_have_operand(self, operands, operand_to_find):
        for _operand in operands:
            if _operand['name'] == operand_to_find:
                return True
        return False

    # operand's type can be operand or taint
    # returns index of operand in tainted, -1 when it's not exists
    def get_taint_index(self, operand):
        for _i_tainted in range(len(self.TAINTED)):
            _tainted = self.TAINTED[_i_tainted]
            if operand['name'] == _tainted['name']:
                return _i_tainted
        return -1

    # operand's type can be operand or taint
    # returns list of label of the tainted operand
    def get_taint_labels(self, operand):
        _i_tainted = self.get_taint_index(operand)
        if _i_tainted < 0:
            return None
        return self.TAINTED[_i_tainted]['labels']

    # operands' type can be operand or taint
    # returns list of taint
    def get_tainted_operands_from_input_operands(self, operands):
        _result = []
        for _operand in operands:
            _tainted_labels = self.get_taint_labels(_operand)
            if _tainted_labels is not None:
                _result.append({
                    'labels': _tainted_labels,
                    'name': _operand['name'],
                })
        return _result

    # operand's type can be operand or taint
    # returns nothing
    def add_operand_to_tainted(self, operand, labels):
        _labels = []
        for _label in labels:
            if _label not in _labels:
                _labels.append(_label)
        _i_tainted = self.get_taint_index(operand)
        # when the input operand has not tainted yet
        if _i_tainted < 0:
            self.TAINTED.append({
                'labels': _labels,
                'name': operand['name'],
            })
        # when the input operand has tainted
        else:
            del self.TAINTED[_i_tainted]
            self.TAINTED.append({
                'labels': _labels,
                'name': operand['name'],
            })

    # operand's type can be operand or taint
    # returns nothing
    def remove_operand_from_tainted(self, operand):
        _i_tainted = self.get_taint_index(operand)
        # when the input operand has not tainted yet
        if _i_tainted < 0:
            return
        del self.TAINTED[_i_tainted]

    # taints' type can be taint
    # returns list of labels
    def get_merged_labels_from_taints(self, taints):
        _labels = []
        for _taint in taints:
            for _label in _taint['labels']:
                if _label in _labels:
                    continue
                _labels.append(_label)
        return _labels

    # dsts' type can be operand or taint
    # srcs' type can be operand or taint
    # returns list of taint
    def _run_taint(self, trace, instruction, dsts, srcs):
        _taints = self.get_tainted_operands_from_input_operands(srcs)
        # when it's tainted
        if len(_taints) > 0:
            _labels = self.get_merged_labels_from_taints(_taints)
            for _dst in dsts:
                self.add_operand_to_tainted(_dst, _labels)
        # when it's not tainted
        else:
            for _dst in dsts:
                self.remove_operand_from_tainted(_dst)
        return _taints

    def get_dst_src(self, trace, instruction, operands):
        _dst = []
        _src = []
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
                elif _g == capstone.x86.X86_GRP_RET or _g == capstone.x86.X86_GRP_IRET:
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
        elif instruction.id == capstone.x86.X86_INS_POPFD:
            _operand_value = self.get_register_value_from_trace(trace, 'esp')
            _src.append({
                'type': 'mem',
                'name': '[0x%x]' % _operand_value,
                'value': _operand_value,
                'formula': '[ esp ]'.split(' '),
            })
            _reg_name = 'eflags'
            _dst.append({
                'type': 'reg',
                'name': _reg_name,
                'value': self.get_register_value_from_trace(trace, _reg_name),
                'formula': None,
            })
        elif instruction.id in [capstone.x86.X86_INS_MOV, capstone.x86.X86_INS_MOVZX, capstone.x86.X86_INS_LEA,
                                capstone.x86.X86_INS_AND, capstone.x86.X86_INS_OR]:
            if len(operands) == 0 or len(operands) > 2:
                return None, None
            _dst.append(operands[0])
            _src.append(operands[1])
        elif instruction.id in [capstone.x86.X86_INS_XOR]:
            if len(operands) != 2:
                return None, None
            if operands[0]['name'] == operands[1]['name']:
                self.remove_operand_from_tainted(operands[0])
                return [], []
            _taint_labels_1 = self.get_taint_labels(operands[1])
            if _taint_labels_1 is not None:
                self.add_operand_to_tainted(operands[0], _taint_labels_1)
        elif instruction.id in [capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB]:
            if len(operands) != 2:
                return None, None
            _taint_labels_1 = self.get_taint_labels(operands[1])
            if _taint_labels_1 is not None:
                self.add_operand_to_tainted(operands[0], _taint_labels_1)
        elif instruction.id == capstone.x86.X86_INS_XCHG:
            if len(operands) != 2:
                return None, None
            _taint_labels_0 = self.get_taint_labels(operands[0])
            _taint_labels_1 = self.get_taint_labels(operands[1])
            if _taint_labels_0 is not None:
                self.remove_operand_from_tainted(operands[0])
            if _taint_labels_1 is not None:
                self.remove_operand_from_tainted(operands[1])
            if _taint_labels_0 is not None:
                self.add_operand_to_tainted(operands[1], _taint_labels_0)
            if _taint_labels_1 is not None:
                self.add_operand_to_tainted(operands[0], _taint_labels_1)
            return [], []
        elif instruction.id == capstone.x86.X86_INS_CMPXCHG:
            if len(operands) != 2:
                return None, None
            _taint_labels_1 = self.get_taint_labels(operands[1])
            if _taint_labels_1 is not None:
                return [], []
            for _mem in trace['mem']:
                if _mem['access'] == 'WRITE' and _mem['addr'] == operands[0]['value']:
                    _taint_labels_0 = self.get_taint_labels(operands[0])
                    if _taint_labels_0 is not None:
                        # self.api.print(trace)
                        # self.api.print(operands)
                        # self.api.print(str(self.TAINTED))
                        self.remove_operand_from_tainted(operands[0])
                        break
            return [], []
        elif instruction.id in [capstone.x86.X86_INS_INC, capstone.x86.X86_INS_DEC, capstone.x86.X86_INS_NOT,
                                capstone.x86.X86_INS_NEG, capstone.x86.X86_INS_TEST, capstone.x86.X86_INS_CMP,
                                capstone.x86.X86_INS_SHR, capstone.x86.X86_INS_SHL, capstone.x86.X86_INS_STD]:
            return [], []
        else:
            self.api.print('[E] Instruction ID : %s (https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h)' % instruction.id)
            return None, None
        return _dst, _src

    def run_taint(self, trace):
        _instructions = self.md.disasm(bytes.fromhex(trace['opcodes']), trace['ip'])
        for _inst in _instructions:
            _operands = self.get_operands(trace, _inst)
            _dsts, _srcs = self.get_dst_src(trace, _inst, _operands)
            if _srcs is None:
                self.api.print('%d : 0x%x : %s : %s' % (trace['id'], trace['ip'], trace['disasm'], str(_operands)))
                self.api.print(' - src: %s' % _srcs)
                self.api.print(' - dst: %s' % _dsts)
                self.api.print(trace)
                self.api.print('[+] Operands : ' + str(_operands))
                self.api.print('[+] Tainted : ' + str(self.TAINTED))
                return None
            _taints = self._run_taint(trace, _inst, _dsts, _srcs)
            if len(_taints) > 0:
                _names_dsts = ['(%s : %s)' % (self.get_taint_labels(_dst), _dst['name']) for _dst in _dsts]
                _names_srcs = ['(%s : %s)' % (self.get_taint_labels(_src), _src['name']) for _src in _srcs]
                self.api.print('%d : 0x%x : %s : dst: %s : src: %s' % (trace['id'], trace['ip'], trace['disasm'], str(_names_dsts), str(_names_srcs)))

            _comment = ''
            _ebp = self.get_register_value_from_trace(trace, 'ebp')
            if _ebp == 0x3d7628:
                _comment += 'VM: '
            if self.are_operands_have_operand(_operands, 'ebp'):
                _comment += 'EBP: '
            if len(_taints) > 0:
                _comment += 'Taint: '
                _comment += str(self.get_merged_labels_from_taints(_taints))
            # if self.are_operands_have_operand(_operands, '[0x3d764e]'):
            #     _comment += 'VAX: '
            # if self.are_operands_have_operand(_operands, '[0x3d76dd]'):
            #     _comment += 'VCX: '
            # if self.are_operands_have_operand(_operands, '[0x3d7686]'):
            #     _comment += 'VDX: '
            # if self.are_operands_have_operand(_operands, '[0x3d7661]'):
            #     _comment += 'VBX: '
            # if self.are_operands_have_operand(_operands, '[0x3d76bd]'):
            #     _comment += 'VEBP: '
            # if self.are_operands_have_operand(_operands, '[0x3d7692]'):
            #     _comment += 'VSI: '
            # if self.are_operands_have_operand(_operands, '[0x3d76c1]'):
            #     _comment += 'VDI: '
            _comment += self.get_aggregated_taints_names_by_labels(self.TAINTED)

            trace['comment'] = _comment
        return trace

    def execute(self, api: Api):
        self.TAINTED = []
        self.api = api
        self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.md.detail = True
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index(#)', 'data': 0},
            {'label': 'Target operand (reg or preset)', 'data': 'preset'},
            {'label': 'Target desc (when it\'s reg)', 'data': 'preset'},
            {'label': 'TTL (no limit, -1)', 'data': -1},
        ]
        _options = self.api.get_values_from_user("Filter by memory address", _input_dlg_data)
        if not _options:
            return
        _str_trace_boundary_begin, _str_trace_boundary_end, _target_index, _target_operand, _target_description, _ttl = _options
        _trace_boundary_begin = int(_str_trace_boundary_begin, 16)
        _trace_boundary_end = int(_str_trace_boundary_end, 16)

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Boundary : 0x%08x ~ 0x%08x' % (_trace_boundary_begin, _trace_boundary_end))
        self.api.print(' - Target : %s at %d' % (_target_operand, _target_index))

        _traces = self.api.get_full_trace()
        _traces_to_show = []

        try:
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
                    # self.TAINTED.append(_target_operand)
                    if _target_operand == 'preset':
                        self.TAINTED.append({
                            'labels': ['eax'],
                            'name': 'eax',
                        })
                        self.TAINTED.append({
                            'labels': ['ebx'],
                            'name': 'ebx',
                        })
                        self.TAINTED.append({
                            'labels': ['ecx'],
                            'name': 'ecx',
                        })
                        self.TAINTED.append({
                            'labels': ['edx'],
                            'name': 'edx',
                        })
                        self.TAINTED.append({
                            'labels': ['esi'],
                            'name': 'esi',
                        })
                        self.TAINTED.append({
                            'labels': ['edi'],
                            'name': 'edi',
                        })

                        self.TAINTED.append({
                            'labels': ['arg_A'],
                            'name': '[0xcff9c8]',
                        })
                        self.TAINTED.append({
                            'labels': ['arg_B'],
                            'name': '[0xcff9cc]',
                        })
                        self.TAINTED.append({
                            'labels': ['arg_C'],
                            'name': '[0xcff9d0]',
                        })
                    else:
                        self.TAINTED.append({
                            'labels': [_target_description],
                            'name': _target_operand,
                        })

                _new_trace = self.run_taint(_trace)
                if _new_trace is None:
                    _traces_to_show.append(_trace.copy())
                    break
                _traces_to_show.append(_new_trace.copy())
        except Exception as e:
            print(traceback.format_exc())
            print(e)

        if len(_traces_to_show) > 0:
            print('Length of filtered trace: %d' % len(_traces_to_show))
            self.api.set_filtered_trace(_traces_to_show)
            self.api.show_filtered_trace()
