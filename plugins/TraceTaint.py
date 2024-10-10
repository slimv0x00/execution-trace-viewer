from core.api import Api
from plugins.TraceContext import TraceContext
from plugins.TraceOperand import TraceOperandForX64DbgTrace
from plugins.TraceTaintedOperand import TraceTaintedOperandForX64DbgTrace

import capstone


class TraceTaint:
    # core.Api
    api = None
    # capstone.Cs
    capstone_bridge = None
    # context
    context: TraceContext = None

    # list of taint [
    #   {
    #     labels: ['your input', ...],
    #     name: 'eax' | '[0x401000]',
    #   }, ...
    # ]
    tainted_operands: list[TraceTaintedOperandForX64DbgTrace] = []

    logs_to_show_in_comment: list[str] = []
    logging_every_tainted_operands: bool = False
    logging_operands_for_instruction: bool = False
    logging_on_adding_and_removing_tainted_operand: bool = False
    logging_detail_of_tainted_operand_on_adding: bool = False
    logging_on_moving_bbl: bool = True

    def __init__(
            self,
            api: Api,
            capstone_bridge,
            context: TraceContext,
            logging_every_tainted_operands: bool = False,
            logging_operands_for_instruction: bool = False,
            logging_on_adding_and_removing_tainted_operand: bool = False,
            logging_detail_of_tainted_operand_on_adding: bool = False,
    ):
        self.api = api
        if capstone_bridge is None:
            self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.capstone_bridge.detail = True
        else:
            self.capstone_bridge = capstone_bridge
        if context is None:
            self.context = TraceContext(capstone_bridge=self.capstone_bridge)
        else:
            self.context = context

        self.logging_every_tainted_operands = logging_every_tainted_operands
        self.logging_operands_for_instruction = logging_operands_for_instruction
        self.logging_on_adding_and_removing_tainted_operand = logging_on_adding_and_removing_tainted_operand
        self.logging_detail_of_tainted_operand_on_adding = logging_detail_of_tainted_operand_on_adding

    def get_tainted_operands(self) -> list[TraceTaintedOperandForX64DbgTrace]:
        return self.tainted_operands

    def set_tainted_operands(self, tainted_operands: list[TraceTaintedOperandForX64DbgTrace]):
        self.tainted_operands = tainted_operands

    def add_tainted_operand_to_tainted_operands(
            self,
            operand: TraceTaintedOperandForX64DbgTrace,
    ):
        # when the entered operand already has been tainted,
        # the tainted operand's tainted_by should be changed (It seems like it is already doing that)
        self.remove_tainted_operand_from_tainted_operands(operand)
        _tainted_operands = self.get_tainted_operands()
        _tainted_operands.append(operand)
        self.set_tainted_operands(_tainted_operands)
        if self.logging_on_adding_and_removing_tainted_operand:
            if self.logging_detail_of_tainted_operand_on_adding:
                self.logs_to_show_in_comment.append('[+: %s from %s (%s)]'
                                                    % (
                                                        operand.get_operand_name(),
                                                        operand.get_tainted_by(),
                                                        operand.get_derived_from(),
                                                    ))
            else:
                self.logs_to_show_in_comment.append('[+: %s from %s]'
                                                    % (operand.get_operand_name(), operand.get_tainted_by()))

    def remove_tainted_operand_from_tainted_operands(
            self,
            operand: TraceTaintedOperandForX64DbgTrace,
    ) -> bool:
        _result = False
        _tainted_operands = self.get_tainted_operands()
        for _i_tainted_operand in range(len(_tainted_operands)):
            _tainted_operand = _tainted_operands[_i_tainted_operand]
            _is_same_operand = _tainted_operand.is_same_operand(operand)
            # when the operand has already been tainted
            if _is_same_operand is True:
                del _tainted_operands[_i_tainted_operand]
                if self.logging_on_adding_and_removing_tainted_operand:
                    self.logs_to_show_in_comment.append('[-: %s]' % operand.get_operand_name())
                _result = True
                break
        self.set_tainted_operands(_tainted_operands)
        return _result

    def retrieve_operands_from_context(self) -> list[TraceOperandForX64DbgTrace]:
        _result: list[TraceOperandForX64DbgTrace] = []
        if len(self.context.current_capstone_instruction.operands) == 0:
            return _result
        for _capstone_operand in self.context.current_capstone_instruction.operands:
            _extracted_operand = TraceOperandForX64DbgTrace(self.context, _capstone_operand)
            _result.append(_extracted_operand)
        return _result

    # returns dsts, srcs as operand list
    # returns None, None when something goes wrong
    def retrieve_dst_and_src_operands_internal(
            self,
            operands: list[TraceOperandForX64DbgTrace]
    ) -> (
            list[TraceOperandForX64DbgTrace] | None,
            list[TraceOperandForX64DbgTrace] | None,
    ):
        _dst_operands: list[TraceOperandForX64DbgTrace] = []
        _src_operands: list[TraceOperandForX64DbgTrace] = []
        if len(self.context.current_capstone_instruction.groups) > 0:
            for _g in self.context.current_capstone_instruction.groups:

                # todo list begin ##########################
                # add EIP as operand
                # todo list end ##########################

                if _g == capstone.x86.X86_GRP_CALL:
                    if self.logging_on_moving_bbl:
                        self.logs_to_show_in_comment.append('[Moving BBL]')
                    _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
                    _operand_esp_value = self.context.get_register_value('esp') - 4
                    _operand_esp.force_set_operand(
                        'mem',
                        '[0x%08x]' % _operand_esp_value,
                        _operand_esp_value,
                        '[ esp - 4 ]'.split(' '),
                    )
                    _dst_operands.append(_operand_esp)
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src_operands.append(operands[0])
                    return _dst_operands, _src_operands
                elif _g == capstone.x86.X86_GRP_JUMP:
                    if self.logging_on_moving_bbl:
                        self.logs_to_show_in_comment.append('[Moving BBL]')
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src_operands.append(operands[0])
                    return _dst_operands, _src_operands
                elif _g == capstone.x86.X86_GRP_RET or _g == capstone.x86.X86_GRP_IRET:
                    if self.logging_on_moving_bbl:
                        self.logs_to_show_in_comment.append('[Moving BBL]')
                    _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
                    _operand_esp_value = self.context.get_register_value('esp')
                    _operand_esp.force_set_operand(
                        'mem',
                        '[0x%08x]' % _operand_esp_value,
                        _operand_esp_value,
                        '[ esp ]'.split(' '),
                    )
                    _src_operands.append(_operand_esp)
                    return _dst_operands, _src_operands

        if self.context.current_capstone_instruction.id == capstone.x86.X86_INS_PUSH:
            _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp') - 4
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp - 4 ]'.split(' '),
            )
            _dst_operands.append(_operand_esp)
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _src_operands.append(operands[0])
        elif self.context.current_capstone_instruction.id == capstone.x86.X86_INS_PUSHFD:
            _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp') - 4
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp - 4 ]'.split(' '),
            )
            _dst_operands.append(_operand_esp)
            _operand_eflags = TraceOperandForX64DbgTrace(self.context, None)
            _register_name_eflags = 'eflags'
            _operand_eflags_value = self.context.get_register_value(_register_name_eflags)
            _operand_eflags.force_set_operand(
                'reg',
                _register_name_eflags,
                _operand_eflags_value,
                [],
            )
            _src_operands.append(_operand_eflags)
        elif self.context.current_capstone_instruction.id == capstone.x86.X86_INS_POP:
            _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp')
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp ]'.split(' '),
            )
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _src_operands.append(_operand_esp)
            _dst_operands.append(operands[0])
        elif self.context.current_capstone_instruction.id == capstone.x86.X86_INS_POPFD:
            _operand_esp = TraceOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp')
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp ]'.split(' '),
            )
            _src_operands.append(_operand_esp)
            _operand_eflags = TraceOperandForX64DbgTrace(self.context, None)
            _register_name_eflags = 'eflags'
            _operand_eflags_value = self.context.get_register_value(_register_name_eflags)
            _operand_eflags.force_set_operand(
                'reg',
                _register_name_eflags,
                _operand_eflags_value,
                [],
            )
            _dst_operands.append(_operand_eflags)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_MOV, capstone.x86.X86_INS_MOVZX, capstone.x86.X86_INS_LEA,
            capstone.x86.X86_INS_AND, capstone.x86.X86_INS_OR, capstone.x86.X86_INS_XOR,
            capstone.x86.X86_INS_ADD, capstone.x86.X86_INS_SUB, capstone.x86.X86_INS_XCHG,
            capstone.x86.X86_INS_CMPXCHG, capstone.x86.X86_INS_IMUL,
        ]:
            if len(operands) == 0 or len(operands) > 2:
                return None, None
            _dst_operands.append(operands[0])
            _src_operands.append(operands[1])
        elif self.context.current_capstone_instruction.id in [capstone.x86.X86_INS_INC, capstone.x86.X86_INS_DEC,
                                                              capstone.x86.X86_INS_NOT,
                                                              capstone.x86.X86_INS_NEG, capstone.x86.X86_INS_TEST,
                                                              capstone.x86.X86_INS_CMP,
                                                              capstone.x86.X86_INS_SHR, capstone.x86.X86_INS_SHL]:
            _dst_operands.append(operands[0])
        elif self.context.current_capstone_instruction.id in [capstone.x86.X86_INS_STD, capstone.x86.X86_INS_RDTSC,
                                                              capstone.x86.X86_INS_CDQ,
                                                              capstone.x86.X86_INS_PUSHAL, capstone.x86.X86_INS_POPAL]:
            # todo: PUSHAL and POPAL SHOULD BE HANDLED ANOTHER WAY !!!!!!!!!!!!!!!!!!!!!!!!
            pass
        else:
            raise Exception(
                '[E] Unhandled instruction ID : %s (https://github.com/capstone-engine/capstone/blob/master/include'
                '/capstone/x86.h)\n - Operands : %s' % (
                    self.context.current_capstone_instruction.id,
                    [_operand.get_operand_name() for _operand in operands],
                ))
        return _dst_operands, _src_operands

    def retrieve_dst_and_src_operands(self, x64dbg_trace) -> (
        list[TraceOperandForX64DbgTrace],
        list[TraceOperandForX64DbgTrace],
    ):
        _operands: list[TraceOperandForX64DbgTrace] = self.retrieve_operands_from_context()
        _dst_operands: list[TraceOperandForX64DbgTrace] | None = None
        _src_operands: list[TraceOperandForX64DbgTrace] | None = None
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands_internal(_operands)
        if _src_operands is None:
            self.api.print('%d : 0x%x : %s : %s'
                           % (x64dbg_trace['id'], x64dbg_trace['ip'], x64dbg_trace['disasm'], str(_operands)))
            self.api.print(x64dbg_trace)
            self.api.print('[+] Operands : %s' + str([str(_operand) for _operand in _operands]))
            self.api.print('[+] Tainted : ' + str(self.tainted_operands))
            raise Exception('[E] Something goes wrong')
        elif len(_dst_operands) >= 2 or len(_src_operands) >= 2:
            self.api.print('%d : 0x%x : %s : %s'
                           % (x64dbg_trace['id'], x64dbg_trace['ip'], x64dbg_trace['disasm'], str(_operands)))
            self.api.print(x64dbg_trace)
            self.api.print('[+] Operands : %s' + str([str(_operand) for _operand in _operands]))
            self.api.print('[+] Tainted : ' + str(self.tainted_operands))
            raise Exception('[E] Too many operands are found\n- dst : %s\n- src : %s' % (
                str([str(_operand) for _operand in _dst_operands]),
                str([str(_operand) for _operand in _src_operands])),
            )
        return _dst_operands, _src_operands

    def retrieve_same_operand_from_tainted_operands(
            self,
            operand: TraceOperandForX64DbgTrace,
    ) -> TraceTaintedOperandForX64DbgTrace | None:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        _operand_type = operand.get_operand_type()
        _operand_name = operand.get_operand_name()

        # to handle of 8-bit and 16-bit registers
        if _operand_type == 'reg':
            _operand_name = operand.get_upper_register()

        _operand = TraceOperandForX64DbgTrace(self.context, None)
        _operand.force_set_operand(
            _operand_type,
            _operand_name,
            operand.get_operand_value(),
            operand.get_memory_formula(),
        )
        _tainted_operands = self.get_tainted_operands()
        for _tainted_operand in _tainted_operands:
            if _tainted_operand.is_same_operand(_operand):
                _result.append(_tainted_operand)
        if len(_result) > 1:
            raise Exception('[E] Detected more than one tainted operand for %s\n- %s'
                            % (_operand_name, str([_op.get_operand_name() for _op in _result])))
        elif len(_result) == 0:
            return None
        return _result[0]

    def retrieve_same_operand_from_operands(
            self,
            operand: TraceOperandForX64DbgTrace | TraceTaintedOperandForX64DbgTrace,
            operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> TraceTaintedOperandForX64DbgTrace | None:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        _operand_type = operand.get_operand_type()
        _operand_name = operand.get_operand_name()

        # to handle of 8-bit and 16-bit registers
        if _operand_type == 'reg':
            _operand_name = operand.get_upper_register()

        _operand = TraceOperandForX64DbgTrace(self.context, None)
        _operand.force_set_operand(
            _operand_type,
            _operand_name,
            operand.get_operand_value(),
            operand.get_memory_formula(),
        )
        for _input_operand in operands:
            if _input_operand.is_same_operand(_operand):
                _result.append(_input_operand)
        if len(_result) > 1:
            raise Exception('[E] Detected more than one tainted operand for %s\n- %s'
                            % (_operand_name, str([_op.get_operand_name() for _op in _result])))
        elif len(_result) == 0:
            return None
        return _result[0]

    def retrieve_operands_from_input_operand_memory_formulas(
            self,
            operand: TraceOperandForX64DbgTrace
    ) -> list[TraceOperandForX64DbgTrace]:
        _result: list[TraceOperandForX64DbgTrace] = []
        _memory_formula = operand.get_memory_formula()
        for _memory_variable in _memory_formula:
            # is register
            if _memory_variable in self.context.register_names:
                _operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
                _operand.force_set_operand_as_register(_memory_variable)
                _result.append(_operand)
        return _result

    def retrieve_derived_tainted_operands_from_input_operand_memory_formulas(
            self,
            operand: TraceOperandForX64DbgTrace,
    ) -> list[TraceTaintedOperandForX64DbgTrace]:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        _tainted_operands = self.get_tainted_operands()
        for _tainted_operand in _tainted_operands:
            if _tainted_operand.is_the_operand_derived_from_me(operand):
                _result.append(_tainted_operand)
        return _result

    def retrieve_derived_from_string_from_input_operand_memory_formulas(
        self,
        operand: TraceOperandForX64DbgTrace,
    ) -> list[str]:
        _result: list[str] = []
        _derived_tainted_operands = self.retrieve_derived_tainted_operands_from_input_operand_memory_formulas(operand)
        for _derived_tainted_operand in _derived_tainted_operands:
            _result.extend(_derived_tainted_operand.get_tainted_by())
        _result = list(set(_result))
        return _result

    def retrieve_tainted_operands_from_input_operands(
            self,
            operands: list[TraceOperandForX64DbgTrace],
    ) -> list[TraceTaintedOperandForX64DbgTrace]:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        for _operand in operands:
            _tainted_operand_same_as_operand = self.retrieve_same_operand_from_tainted_operands(_operand)
            # when _tainted_operand_same_as_operand is None,
            # the operand is tainted by any other tainted operands
            if _tainted_operand_same_as_operand is None:
                continue
            _new_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
            _new_tainted_operand.force_set_tainted_operand(
                _operand.get_operand_type(),
                _operand.get_operand_name(),
                _operand.get_operand_value(),
                _operand.get_memory_formula(),
                _tainted_operand_same_as_operand.get_tainted_by(),
            )
            _derived_from: list[str] = self.retrieve_derived_from_string_from_input_operand_memory_formulas(_operand)
            _new_tainted_operand.set_derived_from(_derived_from)
            _result.append(_new_tainted_operand)
        return _result

    @staticmethod
    def retrieve_intersection_operands_from_two_operands(
            operands_1: list[TraceTaintedOperandForX64DbgTrace],
            operands_2: list[TraceTaintedOperandForX64DbgTrace],
    ) -> list[TraceTaintedOperandForX64DbgTrace]:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        for _operand_1 in operands_1:
            for _operand_2 in operands_2:
                if _operand_1.is_same_operand(_operand_2):
                    _result.append(_operand_1)
        return _result

    @staticmethod
    def retrieve_difference_of_operands_from_two_operands(
            operands_1: list[TraceTaintedOperandForX64DbgTrace],
            operands_2: list[TraceTaintedOperandForX64DbgTrace],
    ) -> list[TraceTaintedOperandForX64DbgTrace]:
        _result: list[TraceTaintedOperandForX64DbgTrace] = []
        _intersection_operands = TraceTaint.retrieve_intersection_operands_from_two_operands(operands_1, operands_2)
        for _operand_1 in operands_1:
            _is_in_intersection = False
            for _intersection_operand in _intersection_operands:
                if _operand_1.is_same_operand(_intersection_operand):
                    _is_in_intersection = True
            if _is_in_intersection is False:
                _result.append(_operand_1)
        for _operand_2 in operands_2:
            _is_in_intersection = False
            for _intersection_operand in _intersection_operands:
                if _operand_2.is_same_operand(_intersection_operand):
                    _is_in_intersection = True
            if _is_in_intersection is False:
                _result.append(_operand_2)
        return _result

    @staticmethod
    def get_merged_tainted_by_from_tainted_operands(
            tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> list[str]:
        _result: list[str] = []
        for _tainted_operand in tainted_operands:
            _tainted_by = _tainted_operand.get_tainted_by()
            _result.extend(_tainted_by)
        _result = list(set(_result))
        return _result

    # instruction handler for ADD, SUB
    def instruction_handler_1(
        self,
        dst_operands: list[TraceOperandForX64DbgTrace],
        src_operands: list[TraceOperandForX64DbgTrace],
        dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
        src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):
        _result_to_add: list[TraceTaintedOperandForX64DbgTrace] = []
        _result_to_remove: list[TraceOperandForX64DbgTrace] = []

        # when the source operand has been tainted,
        # it taints the destination operand,
        # but the origin one still remains
        if len(src_tainted_operands) > 0:
            _dst_operand = dst_operands[0]
            _src_operand = src_operands[0]
            _dst_tainted_by = self.get_merged_tainted_by_from_tainted_operands(dst_tainted_operands)
            _src_tainted_by = self.get_merged_tainted_by_from_tainted_operands(src_tainted_operands)
            _tainted_by = list(set(_dst_tainted_by + _src_tainted_by))
            _result_to_remove.append(_dst_operand)
            _dst_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
            _dst_tainted_operand.force_set_tainted_operand(
                _dst_operand.get_operand_type(),
                _dst_operand.get_operand_name(),
                _dst_operand.get_operand_value(),
                _dst_operand.get_memory_formula(),
                _tainted_by,
            )
            _result_to_add.append(_dst_tainted_operand)

        return _result_to_add, _result_to_remove

    # instruction handler for XOR
    def instruction_handler_2(
        self,
        dst_operands: list[TraceOperandForX64DbgTrace],
        src_operands: list[TraceOperandForX64DbgTrace],
        dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
        src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):
        _result_to_add: list[TraceTaintedOperandForX64DbgTrace] = []
        _result_to_remove: list[TraceOperandForX64DbgTrace] = []

        _dst_operand = dst_operands[0]
        _src_operand = src_operands[0]
        # on XOR, remove destination when destination and source are same
        if _dst_operand.is_same_operand(_src_operand) or _dst_operand.has_same_value(_src_operand):
            _result_to_remove.append(_dst_operand)
        # on XOR, extend tainted_by for destination when destination and source are different
        else:
            # on XOR, when the source operand has been tainted,
            # it extends taint the destination operand
            if len(src_tainted_operands) > 0:
                _dst_tainted_by = self.get_merged_tainted_by_from_tainted_operands(dst_tainted_operands)
                _src_tainted_by = self.get_merged_tainted_by_from_tainted_operands(src_tainted_operands)
                _tainted_by = list(
                    set(_dst_tainted_by + _src_tainted_by)
                    - (set(_dst_tainted_by) & set(_src_tainted_by))
                )
                if len(_tainted_by) > 0:
                    _dst_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
                    _dst_tainted_operand.force_set_tainted_operand(
                        _dst_operand.get_operand_type(),
                        _dst_operand.get_operand_name(),
                        _dst_operand.get_operand_value(),
                        _dst_operand.get_memory_formula(),
                        _tainted_by,
                    )
                    _result_to_add.append(_dst_tainted_operand)
                else:
                    _result_to_remove.append(_dst_operand)

        return _result_to_add, _result_to_remove

    # instruction handler for XCHG, CMPXCHG
    def instruction_handler_3(
        self,
        dst_operands: list[TraceOperandForX64DbgTrace],
        src_operands: list[TraceOperandForX64DbgTrace],
        dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
        src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):
        _result_to_add: list[TraceTaintedOperandForX64DbgTrace] = []
        _result_to_remove: list[TraceOperandForX64DbgTrace] = []

        _dst_operand = dst_operands[0]
        _src_operand = src_operands[0]
        if self.context.current_capstone_instruction.id in [capstone.x86.X86_INS_CMPXCHG]:
            _value_has_swapped = False
            _dst_operand_value = _dst_operand.get_operand_value()
            for _memory_rw in self.context.x64dbg_trace['mem']:
                if _memory_rw['access'] == 'WRITE' and _memory_rw['addr'] == _dst_operand_value:
                    _value_has_swapped = True
                    break
            # when nothing has changed
            if _value_has_swapped is False:
                return _result_to_add, _result_to_remove
        if len(dst_tainted_operands) > 0:
            _result_to_remove.append(_dst_operand)
        if len(src_tainted_operands) > 0:
            _result_to_remove.append(_src_operand)
        if len(dst_tainted_operands) > 0:
            _dst_tainted_by = self.get_merged_tainted_by_from_tainted_operands(dst_tainted_operands)
            _src_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
            _src_tainted_operand.force_set_tainted_operand(
                _src_operand.get_operand_type(),
                _src_operand.get_operand_name(),
                _src_operand.get_operand_value(),
                _src_operand.get_memory_formula(),
                _dst_tainted_by,
            )
            _result_to_add.append(_src_tainted_operand)
        if len(src_tainted_operands) > 0:
            _src_tainted_by = self.get_merged_tainted_by_from_tainted_operands(src_tainted_operands)
            _dst_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
            _dst_tainted_operand.force_set_tainted_operand(
                _dst_operand.get_operand_type(),
                _dst_operand.get_operand_name(),
                _dst_operand.get_operand_value(),
                _dst_operand.get_memory_formula(),
                _src_tainted_by,
            )
            _result_to_add.append(_dst_tainted_operand)

        return _result_to_add, _result_to_remove

    # instruction handler for normal case
    def instruction_handler_n(
        self,
        dst_operands: list[TraceOperandForX64DbgTrace],
        src_operands: list[TraceOperandForX64DbgTrace],
        dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
        src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):
        _result_to_add: list[TraceTaintedOperandForX64DbgTrace] = []
        _result_to_remove: list[TraceOperandForX64DbgTrace] = []

        # when the source operand has been tainted,
        # it taints the destination operand
        if len(src_tainted_operands) > 0:
            _src_tainted_by = self.get_merged_tainted_by_from_tainted_operands(src_tainted_operands)
            for _dst_operand in dst_operands:
                _dst_tainted_operand = TraceTaintedOperandForX64DbgTrace(self.context, None)
                _dst_tainted_operand.force_set_tainted_operand(
                    _dst_operand.get_operand_type(),
                    _dst_operand.get_operand_name(),
                    _dst_operand.get_operand_value(),
                    _dst_operand.get_memory_formula(),
                    _src_tainted_by,
                )
                _result_to_add.append(_dst_tainted_operand)
        # when the source operand hasn't been tainted,
        # the destination operands would be removed from tainted operand list
        else:
            for _dst_operand in dst_operands:
                _result_to_remove.append(_dst_operand)

        return _result_to_add, _result_to_remove

    def run_taint_based_on_instruction(
        self,
        dst_operands: list[TraceOperandForX64DbgTrace],
        src_operands: list[TraceOperandForX64DbgTrace],
        dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
        src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):

        # todo list begin ##########################
        # LEA handler should be added, probably?
        # AND handler should be added, probably?
        # OR handler should be added, probably?
        # POP handler should be added, access VB memory via operands in memory formula
        # -> see 313, maybe it should be added to VB related function
        # todo list end ##########################

        _result_to_add: list[TraceTaintedOperandForX64DbgTrace] = []
        _result_to_remove: list[TraceOperandForX64DbgTrace] = []

        if self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_ADD,
            capstone.x86.X86_INS_SUB,
        ]:
            _result_to_add, _result_to_remove = self.instruction_handler_1(
                dst_operands,
                src_operands,
                dst_tainted_operands,
                src_tainted_operands,
            )
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XOR,
        ]:
            _result_to_add, _result_to_remove = self.instruction_handler_2(
                dst_operands,
                src_operands,
                dst_tainted_operands,
                src_tainted_operands,
            )
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XCHG,
            capstone.x86.X86_INS_CMPXCHG,
        ]:
            _result_to_add, _result_to_remove = self.instruction_handler_3(
                dst_operands,
                src_operands,
                dst_tainted_operands,
                src_tainted_operands,
            )
        else:
            _result_to_add, _result_to_remove = self.instruction_handler_n(
                dst_operands,
                src_operands,
                dst_tainted_operands,
                src_tainted_operands,
            )
        return _result_to_add, _result_to_remove

    def run_taint_with_dst_and_src_operands(
            self,
            dst_operands: list[TraceOperandForX64DbgTrace],
            src_operands: list[TraceOperandForX64DbgTrace],
    ) -> (list[TraceTaintedOperandForX64DbgTrace], list[TraceOperandForX64DbgTrace]):
        _dst_tainted_operands: list[TraceTaintedOperandForX64DbgTrace] = \
            self.retrieve_tainted_operands_from_input_operands(dst_operands)
        _src_tainted_operands: list[TraceTaintedOperandForX64DbgTrace] = \
            self.retrieve_tainted_operands_from_input_operands(src_operands)
        _tainted_operands_to_add: list[TraceTaintedOperandForX64DbgTrace] | None = None
        _tainted_operands_to_remove: list[TraceOperandForX64DbgTrace] | None = None
        _tainted_operands_to_add, _tainted_operands_to_remove = \
            self.run_taint_based_on_instruction(
                dst_operands,
                src_operands,
                _dst_tainted_operands,
                _src_tainted_operands,
            )
        for _tainted_operand_to_remove in _tainted_operands_to_remove:
            self.remove_tainted_operand_from_tainted_operands(_tainted_operand_to_remove)
        for _tainted_operand_to_add in _tainted_operands_to_add:
            self.add_tainted_operand_to_tainted_operands(_tainted_operand_to_add)

        return _tainted_operands_to_add, _tainted_operands_to_remove

    # x64dbg_trace
    # {
    #   'id': 0,
    #   'ip': 4242012,
    #   'disasm': 'push 0xaa0be70a',
    #   'comment': 'push encrypted vm_eip',
    #   'regs': [3806, 309, 326, 292, 0, 20476, 360, 377, 4242012, 0],
    #   'opcodes': '680ae70baa',
    #   'mem': [{'access': 'WRITE', 'addr': 20472, 'value': 2852906762}],
    #   'regchanges': 'ebp: 0x4ff8 '
    #   'taints': [] # list of taints
    # }
    def run_taint_single_line_by_x64dbg_trace(self, x64dbg_trace):
        self.logs_to_show_in_comment = []

        # # todo: for debugging begin ##################################
        if self.context.x64dbg_trace['id'] == 218:
            self.api.print(self.context.x64dbg_trace['id'])
        # # todo: for debugging end ##################################

        self.context.set_context_by_x64dbg_trace(x64dbg_trace)
        _dst_operands: list[TraceOperandForX64DbgTrace] | None = None
        _src_operands: list[TraceOperandForX64DbgTrace] | None = None
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands(x64dbg_trace)
        _tainted_operands_to_add: list[TraceTaintedOperandForX64DbgTrace] | None = None
        _tainted_operands_to_remove: list[TraceOperandForX64DbgTrace] | None = None
        _tainted_operands_to_add, _tainted_operands_to_remove = \
            self.run_taint_with_dst_and_src_operands(_dst_operands, _src_operands)

        if self.logging_operands_for_instruction:
            _str_dst_operands = '[Dst] ' + str([_op.get_operand_name() for _op in _dst_operands])
            self.logs_to_show_in_comment.append(_str_dst_operands)
            _str_src_operands = '[Src] ' + str([_op.get_operand_name() for _op in _src_operands])
            self.logs_to_show_in_comment.append(_str_src_operands)
        if self.logging_every_tainted_operands:
            _str_every_tainted_operands = '[T] ' + str([_op.get_operand_name() for _op in self.get_tainted_operands()])
            self.logs_to_show_in_comment.append(_str_every_tainted_operands)

        x64dbg_trace['comment'] = ' | '.join(self.logs_to_show_in_comment)
        x64dbg_trace['taints'] = self.get_tainted_operands()[:]
        x64dbg_trace['dst'] = _dst_operands[:]
        x64dbg_trace['src'] = _src_operands[:]
        return x64dbg_trace
