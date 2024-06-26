from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.TraceContext import TraceContext
from plugins.TraceAdimehtOperand import TraceAdimehtOperandForX64DbgTrace
from plugins.TraceAdimeht import TraceAdimeht
from plugins.TraceTaint import TraceTaint

import capstone
import traceback


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None
    # capstone.Cs
    capstone_bridge = None
    # context
    context: TraceContext = None

    adimehtModule: TraceAdimeht = None
    adimeht_logging_every_tainted_operands: bool = False
    adimeht_logging_operands_for_instruction: bool = False
    adimeht_logging_on_adding_and_removing_tainted_operand: bool = False
    adimeht_logging_detail_of_tainted_operand_on_adding: bool = True

    taintModule: TraceTaint = None
    taint_logging_every_tainted_operands: bool = False
    taint_logging_operands_for_instruction: bool = False
    taint_logging_on_adding_and_removing_tainted_operand: bool = True
    taint_logging_detail_of_tainted_operand_on_adding: bool = False

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

    def get_preset_of_tainted_operands_for_sample_1(self, trace):
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
        return _result

    def get_preset_of_tainted_operands_for_sample_2(self, trace):
        _result = self.get_registers_as_tainted_operand_list(trace)
        # argument 1
        _arg_1 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xcff9c8
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
        _mem_addr = 0xcff9cc
        _arg_2.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_2'],
            'IMM',
        )
        _result.append(_arg_2)
        # argument 3
        _arg_3 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0xcff9d0
        _arg_3.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_3'],
            'IMM',
        )
        _result.append(_arg_3)
        return _result

    def get_preset_of_tainted_operands_for_sample_3(self, trace):
        _result = self.get_registers_as_tainted_operand_list(trace)
        # argument 1
        _arg_1 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0x19ff0c
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
        _mem_addr = 0x19ff10
        _arg_2.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_2'],
            'IMM',
        )
        _result.append(_arg_2)
        return _result

    def get_preset_of_tainted_operands_for_sample_4(self, trace):
        _result = self.get_registers_as_tainted_operand_list(trace)
        # argument 1
        _arg_1 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0x19ff04
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
        _mem_addr = 0x19ff08
        _arg_2.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_2'],
            'IMM',
        )
        _result.append(_arg_2)
        # argument 3
        _arg_3 = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        _mem_addr = 0x19ff0c
        _arg_3.force_set_adimeht_operand(
            'mem',
            '[0x%08x]' % _mem_addr,
            _mem_addr,
            ('[ 0x%08x ]' % _mem_addr).split(' '),
            ['arg_3'],
            'IMM',
        )
        _result.append(_arg_3)
        return _result

    def execute(self, api: Api):
        self.api = api
        self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.capstone_bridge.detail = True
        self.context = TraceContext(capstone_bridge=self.capstone_bridge)
        _preset_id = 1
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index(#)', 'data': 0},
            {'label': 'Target operand (reg or preset)', 'data': 'preset%d' % _preset_id},
            {'label': 'Target desc (when it\'s reg)', 'data': 'preset%d' % _preset_id},
            {'label': 'VBR (Virtual Base Register)', 'data': 'preset%d' % _preset_id},
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

        _vbr: int | None = None
        if _str_vbr == 'preset1':
            # sample1_vm_addTwo
            _vbr = 0x55568a
        elif _str_vbr == 'preset2':
            # sample2_vm_addTwo
            _vbr = 0x3d7628
        elif _str_vbr == 'preset3':
            # sample1_vm_addTwo_3.1.8
            _vbr = 0x462f0c
        elif _str_vbr == 'preset4':
            # sample2_vm_addTwo_3.1.8
            _vbr = 0x4543ea
        # else:
        #     _vbr = int(_str_vbr, 16)

        self.adimehtModule = TraceAdimeht(
            api,
            self.capstone_bridge,
            self.context,
            _vbr,
            logging_every_tainted_operands=self.adimeht_logging_every_tainted_operands,
            logging_operands_for_instruction=self.adimeht_logging_operands_for_instruction,
            logging_on_adding_and_removing_tainted_operand=self.adimeht_logging_on_adding_and_removing_tainted_operand,
            logging_detail_of_tainted_operand_on_adding=self.adimeht_logging_detail_of_tainted_operand_on_adding,
        )
        self.taintModule = TraceTaint(
            api,
            self.capstone_bridge,
            self.context,
            logging_every_tainted_operands=self.taint_logging_every_tainted_operands,
            logging_operands_for_instruction=self.taint_logging_operands_for_instruction,
            logging_on_adding_and_removing_tainted_operand=self.taint_logging_on_adding_and_removing_tainted_operand,
            logging_detail_of_tainted_operand_on_adding=self.taint_logging_detail_of_tainted_operand_on_adding,
        )

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
                    _preset = []
                    if _target_operand == 'preset1':
                        _preset = self.get_preset_of_tainted_operands_for_sample_1(_x64dbg_trace)
                    elif _target_operand == 'preset2':
                        _preset = self.get_preset_of_tainted_operands_for_sample_2(_x64dbg_trace)
                    elif _target_operand == 'preset3':
                        _preset = self.get_preset_of_tainted_operands_for_sample_3(_x64dbg_trace)
                    elif _target_operand == 'preset4':
                        _preset = self.get_preset_of_tainted_operands_for_sample_4(_x64dbg_trace)
                    self.adimehtModule.set_tainted_operands(_preset[:])
                    self.taintModule.set_tainted_operands(_preset[:])
                    self.api.print('[+] Initial tainted operands are set : ')
                    [self.api.print(str(_op)) for _op in self.adimehtModule.tainted_operands]

                # todo: for debugging begin ##################################
                if self.context.x64dbg_trace['id'] == 9933:
                    self.api.print(self.context.x64dbg_trace['id'])
                # todo: for debugging end ##################################

                _new_trace_taint = self.taintModule.run_taint_single_line_by_x64dbg_trace(_x64dbg_trace.copy())
                if _new_trace_taint is None:
                    _traces_to_show.append(_x64dbg_trace.copy())
                    break
                _new_trace_adimeht = self.adimehtModule.run_adimeht_single_line_by_x64dbg_trace(_x64dbg_trace.copy())
                if _new_trace_adimeht is None:
                    _traces_to_show.append(_x64dbg_trace.copy())
                    break
                _comments = []
                if _new_trace_adimeht['comment'] != '':
                    _comments.append(_new_trace_adimeht['comment'])
                if _new_trace_taint['comment'] != '':
                    _comments.append(_new_trace_taint['comment'])
                _x64dbg_trace['comment'] = ' | '.join(_comments)
                _x64dbg_trace['taints'] = _new_trace_taint['taints']
                _traces_to_show.append(_x64dbg_trace)
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
