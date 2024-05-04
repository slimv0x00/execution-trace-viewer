from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.TraceContext import TraceContext
from plugins.TraceAdimehtOperand import TraceAdimehtOperandForX64DbgTrace
from plugins.TraceAdimeht import TraceAdimeht

import capstone
import traceback


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None
    # capstone.Cs
    capstone_bridge = None
    # context
    context: TraceContext = None

    taintModule = None

    def get_registers_as_tainted_operand_list(self, trace) -> list[TraceAdimehtOperandForX64DbgTrace]:
        self.context.set_context_by_x64dbg_trace(trace)
        _result: list[TraceAdimehtOperandForX64DbgTrace] = []

        # register EAX
        _reg_eax = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_eax.force_set_adimeht_operand_as_register('eax', ['eax'], 'IMM')
        _result.append(_reg_eax)
        # register EBX
        _reg_ebx = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_ebx.force_set_adimeht_operand_as_register('ebx', ['ebx'], 'IMM')
        _result.append(_reg_ebx)
        # register ECX
        _reg_ecx = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_ecx.force_set_adimeht_operand_as_register('ecx', ['ecx'], 'IMM')
        _result.append(_reg_ecx)
        # register EDX
        _reg_edx = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_edx.force_set_adimeht_operand_as_register('edx', ['edx'], 'IMM')
        _result.append(_reg_edx)
        # register ESI
        _reg_esi = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_esi.force_set_adimeht_operand_as_register('esi', ['esi'], 'IMM')
        _result.append(_reg_esi)
        # register EDI
        _reg_edi = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_edi.force_set_adimeht_operand_as_register('edi', ['edi'], 'IMM')
        _result.append(_reg_edi)
        # register EBP
        _reg_ebp = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _reg_ebp.force_set_adimeht_operand_as_register('ebp', ['ebp'], 'IMM')
        _result.append(_reg_ebp)

        return _result

    def set_preset_of_tainted_operands_for_sample_1(self, trace):
        _result = self.get_registers_as_tainted_operand_list(trace)
        # argument 1
        _arg_1 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xd3f9f4
        _arg_1.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_1'],
            'IMM',
        )
        _result.append(_arg_1)
        # argument 2
        _arg_2 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xd3f9f8
        _arg_2.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_2'],
            'IMM',
        )
        _result.append(_arg_2)
        self.taintModule.set_tainted_operands(_result)

    def execute(self, api: Api):
        self.api = api
        self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.capstone_bridge.detail = True
        self.context = TraceContext(capstone_bridge=self.capstone_bridge)
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index(#)', 'data': 0},
            {'label': 'Target operand (reg or preset)', 'data': 'preset1'},
            {'label': 'Target desc (when it\'s reg)', 'data': 'preset1'},
            {'label': 'VBR (Virtual Base Register)', 'data': 'preset1'},
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
            _str_vbr, \
            _ttl = _options
        _address_boundary_to_trace_begin = int(_str_address_boundary_to_trace_begin, 16)
        _address_boundary_to_trace_end = int(_str_address_boundary_to_trace_end, 16)

        if _str_vbr == 'preset1':
            # sample1_vm_addTwo
            self.taintModule = TraceAdimeht(api, self.capstone_bridge, self.context, 0x55568a)
        # elif _str_vbr == 'preset2':
        #     # sample2_vm_addTwo
        #     self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, 0x3d7628)
        # elif _str_vbr == 'preset3':
        #     # sample1_vm_addTwo_3.1.8
        #     self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, 0x462f0c)
        # elif _str_vbr == 'preset4':
        #     # sample2_vm_addTwo_3.1.8
        #     self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, 0x4543ea)
        # else:
        #     _vbr = int(_str_vbr, 16)
        #     self.taintModule = TmpTaintModule(api, self.capstone_bridge, self.context, _vbr)

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Address boundary to trace : 0x%08x ~ 0x%08x'
                       % (_address_boundary_to_trace_begin, _address_boundary_to_trace_end))
        self.api.print(' - Initial target to trace : %s at %d' % (_target_operand, _target_index))

        _x64dbg_traces = self.api.get_full_trace()
        _traces_to_show = []

        for _x64dbg_trace in _x64dbg_traces:
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
                _index = _x64dbg_trace['id']
                if _ttl >= 0:
                    if _index > _ttl:
                        break
                _eip = _x64dbg_trace['ip']
                # skip tracing when EIP is outside the boundary to trace
                if _eip < _address_boundary_to_trace_begin or _eip >= _address_boundary_to_trace_end:
                    continue

                if _index == _target_index:
                    if _target_operand == 'preset1':
                        self.set_preset_of_tainted_operands_for_sample_1(_x64dbg_trace)
                    # elif _target_operand == 'preset2':
                    #     self.set_preset_of_tainted_operands_for_sample_2(_trace)
                    # elif _target_operand == 'preset3':
                    #     self.set_preset_of_tainted_operands_for_sample_3(_trace)
                    # elif _target_operand == 'preset4':
                    #     self.set_preset_of_tainted_operands_for_sample_4(_trace)
                    else:
                        pass
                    self.api.print('[+] Initial tainted operands are set : ')
                    [self.api.print(str(_op)) for _op in self.taintModule.tainted_operands]

                _new_trace = self.taintModule.run_adimeht_single_line_by_x64dbg_trace(_x64dbg_trace)
                if _new_trace is None:
                    _traces_to_show.append(_x64dbg_trace.copy())
                    break
                _traces_to_show.append(_new_trace.copy())
            except Exception as e:
                _traces_to_show.append(_x64dbg_trace.copy())
                print(traceback.format_exc())
                print(e)
                print(_x64dbg_trace)
                break

        if len(_traces_to_show) > 0:
            print('Length of filtered trace: %d' % len(_traces_to_show))
            self.api.set_filtered_trace(_traces_to_show)
            self.api.show_filtered_trace()
