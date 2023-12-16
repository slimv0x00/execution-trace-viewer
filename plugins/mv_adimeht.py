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

    def get_upper_register(self, reg_name):
        _upper_register = None
        if reg_name in ['eax', 'ax', 'ah', 'al']:
            _upper_register = 'eax'
        elif reg_name in ['ebx', 'bx', 'bh', 'bl']:
            _upper_register = 'ebx'
        elif reg_name in ['ecx', 'cx', 'ch', 'cl']:
            _upper_register = 'ecx'
        elif reg_name in ['edx', 'dx', 'dh', 'dl']:
            _upper_register = 'edx'
        elif reg_name in ['esp', 'sp']:
            _upper_register = 'esp'
        elif reg_name in ['ebp', 'bp']:
            _upper_register = 'ebp'
        elif reg_name in ['esi', 'si']:
            _upper_register = 'esi'
        elif reg_name in ['edi', 'di']:
            _upper_register = 'edi'
        elif reg_name in ['eip']:
            _upper_register = 'eip'
        elif reg_name in ['eflags']:
            _upper_register = 'eflags'
        return _upper_register

    # returns list of operand [{
    #   type : 'reg' | 'imm', | 'mem' | 'fp' | 'invalid' | 'unknown',
    #   name : 'eax' | '0x100' | [0x401000] | ? | 'invalid' | 'unknown',
    #   value : 0x100 | 0x100 | 0x401000 (=addr) | ? | ? | ?,
    #   formula : None | None | ['[', 'esp', '+', 40, ']'] | None | None | None,
    # }, ...]
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
                _reg_name = self.get_upper_register(instruction.reg_name(_op.value.reg))
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
                    _mem_formula.append(self.get_upper_register(instruction.reg_name(_segment)))
                    _mem_formula.append(':')
                if _base != 0:
                    _base_reg_name = self.get_upper_register(instruction.reg_name(_base))
                    _base_value = self.get_register_value_from_trace(trace, _base_reg_name)
                    _mem_formula.append(_base_reg_name)
                if _index != 0:
                    _index_reg_name = self.get_upper_register(instruction.reg_name(_index))
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

    # operand's type can be operand or taint
    # returns true when operands have the operand to find
    def are_operands_have_operand(self, operands, operand_to_find):
        for _operand in operands:
            if _operand['name'] == operand_to_find:
                return True
        return False

    # operand's type can be operand or taint
    # taints' type can be taint
    # when deep_search is true, searching operand from memory formulas
    # returns index of operand in tainted, -1 when it's not exists
    def get_taint_index(self, operand, taints, deep_search=False):
        for _i_tainted in range(len(taints)):
            _tainted = taints[_i_tainted]
            if operand['name'] == _tainted['name']:
                return _i_tainted

        # deep search, searching from memory formula
        if deep_search is True and 'type' in operand:
            if operand['type'] == 'mem':
                for _form in operand['formula']:
                    for _i_tainted in range(len(taints)):
                        _tainted = taints[_i_tainted]
                        if _form == _tainted['name']:
                            return _i_tainted
        return -1

    # operand's type can be operand or taint
    # taints' type can be taint
    # when deep_search is true, searching operand from memory formulas
    # returns list of label of the tainted operand
    def get_taint_labels(self, operand, taints, deep_search=False):
        _i_tainted = self.get_taint_index(operand, taints, deep_search=deep_search)
        if _i_tainted < 0:
            return None
        return taints[_i_tainted]['labels']

    # operands' type can be operand or taint
    # taints' type can be taint
    # when deep_search is true, searching operand from memory formulas
    # returns list of taint
    def get_tainted_operands_from_input_operands(self, operands, taints, deep_search=False):
        _result = []
        for _operand in operands:
            _tainted_labels = self.get_taint_labels(_operand, taints, deep_search=deep_search)
            if _tainted_labels is not None:
                _result.append({
                    'labels': _tainted_labels,
                    'name': _operand['name'],
                })
        return _result

    # operand's type can be operand or taint
    # taints' type can be taint
    # returns nothing
    def add_operand_to_tainted(self, operand, labels, taints):
        _labels = []
        for _label in labels:
            if _label not in _labels:
                _labels.append(_label)
        _i_tainted = self.get_taint_index(operand, taints)
        # when the input operand has not tainted yet
        if _i_tainted < 0:
            taints.append({
                'labels': _labels,
                'name': operand['name'],
            })
        # when the input operand has tainted
        else:
            del taints[_i_tainted]
            taints.append({
                'labels': _labels,
                'name': operand['name'],
            })

    # operand's type can be operand or taint
    # taints' type can be taint
    # returns list of taint
    def remove_operand_from_tainted(self, operand, taints):
        _i_tainted = self.get_taint_index(operand, taints)
        # when the input operand has not tainted yet
        if _i_tainted < 0:
            return []
        _tainted = [taints[_i_tainted]]
        del taints[_i_tainted]
        return _tainted

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
    # taints' type can be taint
    # returns previous tainted status of dsts, srcs as taint list
    def get_tainted_status(self, trace, instruction, dsts, srcs, taints, deep_search=False):
        _taints_dst = self.get_tainted_operands_from_input_operands(dsts, taints, deep_search=deep_search)
        _taints_src = self.get_tainted_operands_from_input_operands(srcs, taints, deep_search=deep_search)
        return _taints_dst, _taints_src

    # dsts' type can be operand or taint
    # srcs' type can be operand or taint
    # taints' type can be taint
    # returns previous tainted status of dsts, srcs as taint list
    def _run_taint(self, trace, instruction, dsts, srcs, taints, deep_search=False):
        _taints_dst = self.get_tainted_operands_from_input_operands(dsts, taints, deep_search=False)
        _taints_src = self.get_tainted_operands_from_input_operands(srcs, taints, deep_search=deep_search)
        if instruction.id in [capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB, capstone.x86.X86_INS_XOR]:
            if instruction.id in [capstone.x86.X86_INS_XOR]:
                if dsts[0]['name'] == srcs[0]['name']:
                    self.remove_operand_from_tainted(dsts[0], taints)
                    return [], []
            # when it's tainted
            if len(_taints_src) > 0:
                _labels_duplicates = []
                _taints = _taints_src
                # when dst is already tainted
                if len(_taints_dst) > 0:
                    _taints += _taints_dst
                    _labels_dst = self.get_merged_labels_from_taints(_taints_dst)
                    _labels_src = self.get_merged_labels_from_taints(_taints_src)
                    _labels_duplicates = list(set(_labels_dst) & set(_labels_src))
                _labels = self.get_merged_labels_from_taints(_taints)
                if instruction.id in [capstone.x86.X86_INS_XOR]:
                    # when taints have duplicates, remove it from labels
                    if len(_labels_duplicates) > 0:
                        for _label_dup in _labels_duplicates:
                            _labels.remove(_label_dup)
                # when the _labels is empty, you should remove the _dst from taints
                if len(_labels) > 0:
                    for _dst in dsts:
                        # print('[+] %s : %s : %s ( %s ) <- %s' % (trace['id'], trace['disasm'], _dst, _labels, srcs))
                        self.add_operand_to_tainted(_dst, _labels, taints)
                else:
                    for _dst in dsts:
                        # print('[-] %s : %s : %s ( %s )' % (trace['id'], trace['disasm'], _dst, _labels))
                        self.remove_operand_from_tainted(_dst, taints)
        elif instruction.id in [capstone.x86.X86_INS_XCHG, capstone.x86.X86_INS_CMPXCHG]:
            if instruction.id in [capstone.x86.X86_INS_CMPXCHG]:
                _is_changed = False
                for _mem in trace['mem']:
                    if _mem['access'] == 'WRITE' and _mem['addr'] == dsts[0]['value']:
                        _is_changed = True
                        break
                # when nothing changed
                if _is_changed is False:
                    return [], []
            if len(_taints_dst) > 0:
                self.remove_operand_from_tainted(dsts[0], taints)
            if len(_taints_src) > 0:
                self.remove_operand_from_tainted(srcs[0], taints)
            if len(_taints_dst) > 0:
                _labels_dst = self.get_merged_labels_from_taints(_taints_dst)
                self.add_operand_to_tainted(srcs[0], _labels_dst, taints)
            if len(_taints_src) > 0:
                _labels_src = self.get_merged_labels_from_taints(_taints_src)
                self.add_operand_to_tainted(dsts[0], _labels_src, taints)
        else:
            # when it's tainted
            if len(_taints_src) > 0:
                _labels = self.get_merged_labels_from_taints(_taints_src)
                for _dst in dsts:
                    self.add_operand_to_tainted(_dst, _labels, taints)
            # when it's not tainted
            else:
                for _dst in dsts:
                    self.remove_operand_from_tainted(_dst, taints)
        return _taints_dst, _taints_src

    # returns dsts, srcs as operand list
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
                    _operand_value = self.get_register_value_from_trace(trace, 'esp')
                    _src.append({
                        'type': 'mem',
                        'name': '[0x%x]' % _operand_value,
                        'value': _operand_value,
                        'formula': '[ esp ]'.split(' '),
                    })
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
            _dst.append(operands[0])
            _src.append(operands[1])
        elif instruction.id in [capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB]:
            if len(operands) != 2:
                return None, None
            _dst.append(operands[0])
            _src.append(operands[1])
            # print('%s : %s : ( dst: %s )( src: %s )' % (trace['id'], trace['disasm'], _dst, _src))
        elif instruction.id == capstone.x86.X86_INS_XCHG:
            if len(operands) != 2:
                return None, None
            _dst.append(operands[0])
            _src.append(operands[1])
        elif instruction.id == capstone.x86.X86_INS_CMPXCHG:
            if len(operands) != 2:
                return None, None
            _dst.append(operands[0])
            _src.append(operands[1])
        elif instruction.id in [capstone.x86.X86_INS_INC, capstone.x86.X86_INS_DEC, capstone.x86.X86_INS_NOT,
                                capstone.x86.X86_INS_NEG, capstone.x86.X86_INS_TEST, capstone.x86.X86_INS_CMP,
                                capstone.x86.X86_INS_SHR, capstone.x86.X86_INS_SHL]:
            _dst.append(operands[0])
        elif instruction.id in [capstone.x86.X86_INS_STD]:
            pass
        else:
            self.api.print('[E] Instruction ID : %s (https://github.com/capstone-engine/capstone/blob/master/include/capstone/x86.h)' % instruction.id)
            return None, None
        return _dst, _src

    # list of taint [
    #   {
    #     labels: ['your input', ...],
    #     name: 'eax' | '[0x401000]',
    #   }, ...
    # ]
    VBR_RELATED = []
    # list of string, contains VR names
    VR_NAMES = []
    # VR labels {
    #   vr_name (like 'VR02'): vr_label (like 'VBP'),
    # }
    VR_LABELS = {
        'VR00': 'VRP',  # [0x3d764a], stores VR info?
        'VR01': 'VIP',  # [0x3d76a3]
        'VR15': 'VOP2',  # [0x3d7696]
        'VR19': 'VSP',  # [0x3d768e]
        'VR21': 'VOP1',  # [0x3d76d5]
        'VR23': 'VBP',  # [0x3d76bd]
    }

    # operands' type can be operand or taint
    # returns VR name when it's VR, or returns None
    def get_vr_name(self, operand):
        if operand['name'] not in self.VR_NAMES:
            return None
        return 'VR%02d' % self.VR_NAMES.index(operand['name'])

    # vr_name is name of VR like 'VR02'
    # returns VR label when it's VR, or returns None
    def get_vr_label(self, vr_name):
        if vr_name in self.VR_LABELS:
            return self.VR_LABELS[vr_name]
        return vr_name

    # operands' type can be operand or taint
    # returns VR name
    def add_vr_name(self, operand):
        if operand['name'] not in self.VR_NAMES:
            self.VR_NAMES.append(operand['name'])
            self.api.print('[+] New VR : %s (%s)' % ('VR%02d' % self.VR_NAMES.index(operand['name']), operand['name']))
        return 'VR%02d' % self.VR_NAMES.index(operand['name'])

    def get_tainted_operands_string(self, operands, taints):
        _result = ''
        for _op in operands:
            _result += '('
            _vr_name = self.get_vr_name(_op)
            if _vr_name is not None:
                _vr_label = self.get_vr_label(_vr_name)
                _result += '%s : ' % _vr_label
            _result += '%s : ' % self.get_taint_labels(_op, taints)
            _result += '%s)' % _op['name']
        return _result

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

            _comment = ''

            # taint VBR related operands
            _ebp = self.get_register_value_from_trace(trace, 'ebp')
            if _ebp == 0x3d7628:
                # should add vbr into tainted
                _comment += 'VM: '
                if self.are_operands_have_operand(_srcs, 'ebp'):
                    _comment += 'VBR: '
                    self.add_operand_to_tainted({
                        'labels': ['vbr'],
                        'name': 'ebp',
                    }, ['vbr'], self.VBR_RELATED)

                # everything in vbr related is labeled as 'vbr', vr kinds will be added to the tainted
                _vbr_tainted_dst, _vbr_tainted_src = self.get_tainted_status(trace, _inst, _dsts, _srcs, self.VBR_RELATED, deep_search=True)
                if len(_vbr_tainted_dst) > 0 or len(_vbr_tainted_src) > 0:
                    _vbr_taints = _vbr_tainted_dst + _vbr_tainted_src
                    for _vbr_taint in _vbr_taints:
                        if _vbr_taint['name'].find('[0x') == 0:

                            _vr_addr = int(_vbr_taint['name'][3:-1], 16)

                            # when the address is in stack area
                            if _vr_addr >= 0xc00000: ################# would be work on the sample, should be changed #################
                                continue

                            # accessing to VR found
                            _vr_name = self.add_vr_name(_vbr_taint)

                            # when VR is already tainted
                            if self.get_taint_index(_vbr_taint, self.TAINTED) > 0:
                                continue

                            # this should be changed, see index 13059 and 13308
                            # labels shouldn't be changed when the operand is already tainted
                            self.add_operand_to_tainted({
                                'labels': [_vr_name],
                                'name': _vbr_taint['name'],
                            }, [_vr_name], self.TAINTED)

                _vbr_tainted_dst, _vbr_tainted_src = self._run_taint(trace, _inst, _dsts, _srcs, self.VBR_RELATED)
                # if len(_vbr_tainted_dst) > 0 or len(_vbr_tainted_src) > 0:
                #
                #     # print tainted operation
                #     _names_dsts = self.get_tainted_operands_string(_dsts, _vbr_tainted_dst)
                #     _names_srcs = self.get_tainted_operands_string(_srcs, _vbr_tainted_src)
                #     self.api.print('%d : 0x%x : %s ( dst: %s )( src: %s )' % (trace['id'], trace['ip'], trace['disasm'], str(_names_dsts), str(_names_srcs)))
            else:
                # remove vbr from tainted
                self.VBR_RELATED = []

            # run taint
            # _taints_dst, _taints_src = self._run_taint(trace, _inst, _dsts, _srcs, self.TAINTED)
            _taints_dst, _taints_src = self._run_taint(trace, _inst, _dsts, _srcs, self.TAINTED, deep_search=True)
            if len(_taints_dst) > 0 or len(_taints_src) > 0:

                # print tainted operation
                _names_dsts = self.get_tainted_operands_string(_dsts, _taints_dst)
                _names_srcs = self.get_tainted_operands_string(_srcs, _taints_src)
                _str_taints = 'dst: %s src: %s ' % (str(_names_dsts), str(_names_srcs))
                _comment += _str_taints
                # if _str_taints.find('(VR') >= 0:
                #     self.api.print('%d : 0x%x : %s ( dst: %s )( src: %s )' % (trace['id'], trace['ip'], trace['disasm'], str(_names_dsts), str(_names_srcs)))

            trace['comment'] = _comment
        return trace

    def set_tainted_as_preset(self):
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
            'labels': ['ebp'],
            'name': 'ebp',
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

        for _trace in _traces:
            try:
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
                        self.set_tainted_as_preset()
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
                print(_trace)
                break

        if len(_traces_to_show) > 0:
            print('Length of filtered trace: %d' % len(_traces_to_show))
            self.api.set_filtered_trace(_traces_to_show)
            self.api.show_filtered_trace()
