from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.tmpTaintModule import TmpTaintModule
from plugins.tmpContext import TmpContext
from plugins.tmpTaintedOperand import TmpTaintedOperandForX64DbgTrace
import capstone

import traceback


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None
    # capstone.Cs
    capstone_bridge = None
    # context
    context: TmpContext = None

    taintModule = None

    def set_preset_of_tainted_operands_for_sample_2(self, trace):
        self.context.set_context_by_x64dbg_trace(trace)
        _new_tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = []
        
        # register EAX
        _reg_eax = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_eax.force_set_tainted_operand_as_register('eax', ['eax'], [])
        _new_tainted_operands.append(_reg_eax)
        # register EBX
        _reg_ebx = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_ebx.force_set_tainted_operand_as_register('ebx', ['ebx'], [])
        _new_tainted_operands.append(_reg_ebx)
        # register ECX
        _reg_ecx = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_ecx.force_set_tainted_operand_as_register('ecx', ['ecx'], [])
        _new_tainted_operands.append(_reg_ecx)
        # register EDX
        _reg_edx = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_edx.force_set_tainted_operand_as_register('edx', ['edx'], [])
        _new_tainted_operands.append(_reg_edx)
        # register ESI
        _reg_esi = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_esi.force_set_tainted_operand_as_register('esi', ['esi'], [])
        _new_tainted_operands.append(_reg_esi)
        # register EDI
        _reg_edi = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_edi.force_set_tainted_operand_as_register('edi', ['edi'], [])
        _new_tainted_operands.append(_reg_edi)
        # register EBP
        _reg_ebp = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _reg_ebp.force_set_tainted_operand_as_register('ebp', ['ebp'], [])
        _new_tainted_operands.append(_reg_ebp)

        # argument 1
        _arg_1 = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xcff9c8
        _arg_1.force_set_tainted_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['[0x%08x]' % _mem_addr],
            ['arg_1'],
        )
        _new_tainted_operands.append(_arg_1)
        # argument 2
        _arg_2 = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xcff9cc
        _arg_2.force_set_tainted_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['[0x%08x]' % _mem_addr],
            ['arg_2'],
        )
        _new_tainted_operands.append(_arg_2)
        # argument 3
        _arg_3 = TmpTaintedOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xcff9d0
        _arg_3.force_set_tainted_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['[0x%08x]' % _mem_addr],
            ['arg_3'],
        )
        _new_tainted_operands.append(_arg_3)
        
        self.taintModule.set_tainted_operands(_new_tainted_operands)

    def execute(self, api: Api):
        self.api = api
        self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.capstone_bridge.detail = True
        self.context = TmpContext(capstone_bridge=self.capstone_bridge)
        self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, 0x55568a)  # sample1_vm_addTwo
        # self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, 0x3d7628)  # sample2_vm_addTwo
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
        _str_address_boundary_to_trace_begin,\
            _str_address_boundary_to_trace_end,\
            _target_index,\
            _target_operand,\
            _target_description,\
            _ttl = _options
        _address_boundary_to_trace_begin = int(_str_address_boundary_to_trace_begin, 16)
        _address_boundary_to_trace_end = int(_str_address_boundary_to_trace_end, 16)

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Address boundary to trace : 0x%08x ~ 0x%08x'
                       % (_address_boundary_to_trace_begin, _address_boundary_to_trace_end))
        self.api.print(' - Initial target to trace : %s at %d' % (_target_operand, _target_index))

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
                # skip tracing when EIP is outside the boundary to trace
                if _eip < _address_boundary_to_trace_begin or _eip >= _address_boundary_to_trace_end:
                    continue

                if _index == _target_index:
                    if _target_operand == 'preset':
                        self.set_preset_of_tainted_operands_for_sample_2(_trace)
                    else:
                        pass
                    self.api.print('[+] Initial tainted operands are set : ')
                    [self.api.print(str(_op)) for _op in self.taintModule.tainted_operands]

                _new_trace = self.taintModule.run_taint_single_line_by_x64dbg_trace(_trace, show_log=True)
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
