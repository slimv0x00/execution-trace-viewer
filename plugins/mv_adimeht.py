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

    def get_registers_as_tainted_operand_list(self, x64dbg_trace) -> list[TraceAdimehtOperandForX64DbgTrace]:
        self.context.set_context_by_x64dbg_trace(x64dbg_trace)
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

    def recognize_arg_and_vbr(
            self,
            x64dbg_traces,
            address_boundary_to_trace_begin,
            address_boundary_to_trace_end,
            target_index,
            vbr,
            number_of_arg,
            int_size=4,
    ):
        _vbr_canditates = {}
        _args = []
        for _x64dbg_trace in x64dbg_traces:
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
                _eip = _x64dbg_trace['ip']
                # skip tracing when EIP is outside the boundary to trace
                if _eip < address_boundary_to_trace_begin or _eip >= address_boundary_to_trace_end:
                    continue
                self.context.set_context_by_x64dbg_trace(_x64dbg_trace)
                if _index == target_index:
                    _esp = self.context.get_register_value('esp')
                    for _i_arg in range(number_of_arg):
                        _args.append({
                            'arg_id': 'arg_%d' % (_i_arg + 1),
                            'arg_addr': _esp + (_i_arg * int_size),
                        })
                _ebp = self.context.get_register_value('ebp')
                if _ebp not in _vbr_canditates:
                    _vbr_canditates[_ebp] = 0
                _vbr_canditates[_ebp] += 1
            except Exception as e:
                print(traceback.format_exc())
                print(e)
                print(_x64dbg_trace)
                break
        _vbr = vbr
        _sorted_vbr_candidates = sorted(_vbr_canditates, key=lambda x: _vbr_canditates[x], reverse=True)
        if _vbr < 0:
            if len(_sorted_vbr_candidates) <= 0:
                print('[E] Cannot find any candidates for vbr')
            _vbr = _sorted_vbr_candidates[0]
        self.api.print('[+] VBR : 0x%x' % _vbr)
        _len_vbr_candidates = 3 if len(_sorted_vbr_candidates) > 3 else len(_sorted_vbr_candidates)
        for _i_vbr_canditate in range(_len_vbr_candidates):
            self.api.print(' - VBR canditate %d : 0x%x (%d-hit)' % (
                _i_vbr_canditate + 1,
                _sorted_vbr_candidates[_i_vbr_canditate],
                _vbr_canditates[_sorted_vbr_candidates[_i_vbr_canditate]]
            ))
        if len(_args) > 0:
            self.api.print('[+] Arguments')
            for _arg in _args:
                self.api.print(' - %s : 0x%x' % (_arg['arg_id'], _arg['arg_addr']))
        # {
        #    'args': [
        #        { 'arg_id': 'arg_1', 'arg_addr': 0x19ff00 },
        #        { 'arg_id': 'arg_2', 'arg_addr': 0x19ff04 },
        #        ...,
        #    ],
        #    'vbr': 0xc5fb90,
        #    'vbr_candidates': {
        #        0xc5fb90: 1000,
        #        0xc5ee80: 10,
        #        ...,
        #    }
        # }
        return {
            'args': _args,
            'vbr': _vbr,
            'vbr_candidates': _vbr_canditates,
        }

    def get_initial_tainted_operands(self, x64dbg_trace, args):
        _result = self.get_registers_as_tainted_operand_list(x64dbg_trace)
        for _arg in args:
            _arg_id = _arg['arg_id']
            _arg_addr = _arg['arg_addr']
            _trace_adimeht_arg = TraceAdimehtOperandForX64DbgTrace(self.context, None)
            _trace_adimeht_arg.force_set_adimeht_operand(
                'mem',
                '[0x%08x]' % _arg_addr,
                _arg_addr,
                ('[ 0x%08x ]' % _arg_addr).split(' '),
                [_arg_id],
                'IMM',
            )
            _result.append(_trace_adimeht_arg)
        return _result

    def execute(self, api: Api):
        self.api = api
        self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        self.capstone_bridge.detail = True
        self.context = TraceContext(capstone_bridge=self.capstone_bridge)
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index (where you want to pick arg)', 'data': 0},
            {'label': 'VBR (Virtual Base Register, -1 when you have no idea)', 'data': -1},
            {'label': 'Number of argument', 'data': 2},
            {'label': 'TTL (no limit, -1)', 'data': -1},
        ]
        _options = self.api.get_values_from_user("Filter by memory address", _input_dlg_data)
        if not _options:
            return
        _str_address_boundary_to_trace_begin,\
            _str_address_boundary_to_trace_end,\
            _target_index,\
            _vbr, \
            _number_of_arg, \
            _ttl = _options
        _address_boundary_to_trace_begin = int(_str_address_boundary_to_trace_begin, 16)
        _address_boundary_to_trace_end = int(_str_address_boundary_to_trace_end, 16)

        self.api.print('[+] Recognizing %d-arguments and VBR' % _number_of_arg)
        _x64dbg_traces = self.api.get_full_trace()
        _arg_and_vbr = self.recognize_arg_and_vbr(
            _x64dbg_traces,
            _address_boundary_to_trace_begin,
            _address_boundary_to_trace_end,
            _target_index,
            _vbr,
            _number_of_arg,
        )
        _vbr = _arg_and_vbr['vbr']
        _args = _arg_and_vbr['args']

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
                    _initial_tainted_operands = self.get_initial_tainted_operands(_x64dbg_trace, _args)
                    self.adimehtModule.set_tainted_operands(_initial_tainted_operands[:])
                    self.taintModule.set_tainted_operands(_initial_tainted_operands[:])
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
