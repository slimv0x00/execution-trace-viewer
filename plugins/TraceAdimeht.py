from core.api import Api
from plugins.TraceContext import TraceContext
from plugins.TraceOperand import TraceOperandForX64DbgTrace
from plugins.TraceAdimehtOperand import TraceAdimehtOperandForX64DbgTrace
from plugins.TraceTaint import TraceTaint


class TraceAdimeht(TraceTaint):
    you_are_in_vm: bool = False

    reg_vbr: TraceAdimehtOperandForX64DbgTrace = None
    reg_vbr_value: int = 0
    reg_vbr_name_for_tainted_by: str = 'vbr'
    reg_vbr_role_name: str = 'VBR'

    # list of taint [
    #   {
    #     labels: ['your input', ...],
    #     name: 'eax' | '[0x401000]',
    #   }, ...
    # ]
    tainted_operands: list[TraceAdimehtOperandForX64DbgTrace] = []

    logging_you_are_in_vm: bool = True
    logging_on_vm_role_identified: bool = False
    logging_on_use_vr: bool = True

    def __init__(self, api: Api, capstone_bridge, context: TraceContext, vbr_value: int):
        super().__init__(api, capstone_bridge, context)

        # set VBR (Virtual machine Base Register)
        self.reg_vbr = TraceAdimehtOperandForX64DbgTrace(self.context, None)
        # context hasn't been initialized, so you cannot use force_set_adimeht_operand_as_register
        self.reg_vbr.force_set_adimeht_operand(
            'reg',
            'ebp',
            vbr_value,
            [],
            [self.get_reg_vbr_name_for_tainted_by()],
            self.get_reg_vbr_role_name(),
        )
        self.set_reg_vbr_value(vbr_value)

    def get_you_are_in_vm(self) -> bool:
        return self.you_are_in_vm

    def get_reg_vbr_value(self) -> int:
        return self.reg_vbr_value

    def get_reg_vbr_name_for_tainted_by(self) -> str:
        return self.reg_vbr_name_for_tainted_by

    def get_reg_vbr_role_name(self) -> str:
        return self.reg_vbr_role_name

    def set_you_are_in_vm(self, you_are_in_vm: bool):
        self.you_are_in_vm = you_are_in_vm

    def set_reg_vbr_value(self, reg_vbr_value: int):
        self.reg_vbr_value = reg_vbr_value

    def check_you_are_in_vm(self) -> bool:
        _reg_vbr_value: int = self.get_reg_vbr_value()
        _ebp_value: int = self.context.get_register_value('ebp')
        _you_are_in_vm: bool = self.get_you_are_in_vm()
        _result = False
        # if EBP value is same as VBR, you are in VM
        if _ebp_value == _reg_vbr_value:
            if _you_are_in_vm is False:
                # add EBP as VBR (Virtual machine Base Register) to tainted_operands
                self.add_tainted_operand_to_tainted_operands(self.reg_vbr)
            _result = True
        else:
            if _you_are_in_vm is True:
                # remove VBR from tainted_operands
                self.remove_tainted_operand_from_tainted_operands(self.reg_vbr)
        self.set_you_are_in_vm(_result)
        return _result

    @staticmethod
    # vm_part_you_looking_for : should be one of ['VB', 'VR']
    def get_vm_part_from_tainted_by(tainted_by: list[str], vm_part_you_looking_for: str):
        _result = []
        _vm_part_types = ['VB', 'VR']
        if vm_part_you_looking_for not in _vm_part_types:
            raise Exception('[E] Invalid VM part type you looking for, it should be one of %s : %s'
                            % (_vm_part_types, vm_part_you_looking_for))
        _vm_part_form_you_looking_for = '%s_0x' % vm_part_you_looking_for
        for _tainted_by in tainted_by:
            if _tainted_by.find(_vm_part_form_you_looking_for) == 0:
                _result.append(_tainted_by)
        return _result

    def identify_the_role_of_vm_part_for_operand(self, operand: TraceOperandForX64DbgTrace):
        _tainted_operands: list[TraceAdimehtOperandForX64DbgTrace] = self.get_tainted_operands()
        for _tainted_operand in _tainted_operands:
            if _tainted_operand.is_the_operand_derived_from_me(operand) is False:
                continue
            _tainted_by_for_tainted_operand = _tainted_operand.get_tainted_by()
            if self.reg_vbr_name_for_tainted_by not in _tainted_by_for_tainted_operand:
                # if the operand is not related to VBR, it is not part of VM
                continue

            _vb_list = self.get_vm_part_from_tainted_by(_tainted_by_for_tainted_operand, 'VB')
            _vr_list = self.get_vm_part_from_tainted_by(_tainted_by_for_tainted_operand, 'VR')

            _identified_role = None
            if len(_vb_list) > 0:
                # on VR(Virtual Register)
                _identified_role = 'VR'
            elif len(_vb_list) == 0 and len(_vr_list) == 0:
                # on VB(Virtual Bridge)
                _identified_role = 'VB'
            else:
                continue

            _vb_operand = TraceAdimehtOperandForX64DbgTrace(self.context, None)
            _operand_from_tainted_operands = self.retrieve_same_operand_from_tainted_operands(operand)
            if _operand_from_tainted_operands is not None:
                _vb_operand.force_set_adimeht_operand(
                    _operand_from_tainted_operands.get_operand_type(),
                    _operand_from_tainted_operands.get_operand_name(),
                    _operand_from_tainted_operands.get_operand_value(),
                    _operand_from_tainted_operands.get_memory_formula(),
                    _operand_from_tainted_operands.get_tainted_by(),
                    _identified_role,
                )
            else:
                _vb_operand.force_set_adimeht_operand(
                    operand.get_operand_type(),
                    operand.get_operand_name(),
                    operand.get_operand_value(),
                    operand.get_memory_formula(),
                    [],
                    _identified_role,
                )
            _vb_operand.set_derived_from(_tainted_by_for_tainted_operand)
            _vb_operand.set_vm_part_by_using_offset_from_vbr(self.reg_vbr)
            _vm_part_name = _vb_operand.get_vm_part()

            if _identified_role == 'VR':
                if self.logging_on_use_vr:
                    self.logs_to_show_in_comment.append('[%s : %s]'
                                                        % (
                                                            _vb_operand.get_vm_part(),
                                                            _vb_operand.get_operand_name(),
                                                        ))
            if self.logging_on_vm_role_identified:
                self.logs_to_show_in_comment.append('[R: %s : %s from %s (%s)]'
                                                    % (
                                                        _vb_operand.get_vm_part(),
                                                        _vb_operand.get_operand_name(),
                                                        _vb_operand.get_tainted_by(),
                                                        _vb_operand.get_derived_from(),
                                                    ))

            _tainted_by_for_vb_operand = _vb_operand.get_tainted_by()
            if _vm_part_name not in _tainted_by_for_vb_operand:
                _tainted_by_for_vb_operand.append(_vm_part_name)
                _vb_operand.set_tainted_by(_tainted_by_for_vb_operand)
            self.add_tainted_operand_to_tainted_operands(_vb_operand)

    def identify_the_role_of_vm_part_for_operands(self, operands: list[TraceOperandForX64DbgTrace]):
        for _operand in operands:
            self.identify_the_role_of_vm_part_for_operand(_operand)

    def run_adimeht_single_line_by_x64dbg_trace(self, x64dbg_trace):
        self.logs_to_show_in_comment = []
        self.context.set_context_by_x64dbg_trace(x64dbg_trace)

        # todo: for debugging begin ##################################
        if self.context.x64dbg_trace['id'] == 9933:
            self.api.print(self.context.x64dbg_trace['id'])
        # todo: for debugging end ##################################

        if self.logging_you_are_in_vm:
            _you_are_in_vm = self.check_you_are_in_vm()
            if _you_are_in_vm:
                self.logs_to_show_in_comment.append('[VM]')

        _dst_operands: list[TraceOperandForX64DbgTrace] | None = None
        _src_operands: list[TraceOperandForX64DbgTrace] | None = None
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands(x64dbg_trace)

        self.identify_the_role_of_vm_part_for_operands(_dst_operands)
        self.identify_the_role_of_vm_part_for_operands(_src_operands)

        # back up logs
        _logs_to_show_in_comment = self.logs_to_show_in_comment

        # run taint
        _new_x64dbg_trace = self.run_taint_single_line_by_x64dbg_trace(x64dbg_trace)
        _trace_comment_from_taint = _new_x64dbg_trace['comment']

        _logs_to_show_in_comment.append(_trace_comment_from_taint)
        _new_x64dbg_trace['comment'] = ' | '.join(_logs_to_show_in_comment)
        return _new_x64dbg_trace
