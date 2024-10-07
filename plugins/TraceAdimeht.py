from core.api import Api
from plugins.TraceContext import TraceContext
from plugins.TraceOperand import TraceOperandForX64DbgTrace
from plugins.TraceAdimehtOperand import TraceAdimehtOperandForX64DbgTrace
from plugins.TraceTaint import TraceTaint

import capstone
import re


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

    vm_enter_begin_trace = None
    vm_enter_end_trace = None
    vm_enters: list[dict[str:int]] = []
    vm_vri_begin_trace = None
    vm_vri_end_trace = None
    vm_vris: list[dict[str:int]] = []
    vm_previous_trace = None
    vm_exit_step_count: int = 0
    vm_exit_begin_trace = None
    vm_exits: list[dict[str:int]] = []

    logging_you_are_in_vm: bool = True
    logging_on_vm_role_identified: bool = False
    logging_on_vr_identified: bool = False
    logging_on_lv_identified: bool = False
    logging_pseudo_ir_operands: bool = False
    logging_pseudo_ir: bool = True

    def __init__(
            self,
            api: Api,
            capstone_bridge,
            context: TraceContext,
            vbr_value: int,
            logging_every_tainted_operands: bool = False,
            logging_operands_for_instruction: bool = False,
            logging_on_adding_and_removing_tainted_operand: bool = False,
            logging_detail_of_tainted_operand_on_adding: bool = False,
    ):
        super().__init__(
            api,
            capstone_bridge,
            context,
            logging_every_tainted_operands=logging_every_tainted_operands,
            logging_operands_for_instruction=logging_operands_for_instruction,
            logging_on_adding_and_removing_tainted_operand=logging_on_adding_and_removing_tainted_operand,
            logging_detail_of_tainted_operand_on_adding=logging_detail_of_tainted_operand_on_adding,
        )

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

        # Initialize values related to recognizing VM enter and exit
        self.vm_enter_begin_trace = None
        self.vm_enter_end_trace = None
        self.vm_enters = []
        self.vm_vri_begin_trace = None
        self.vm_vri_end_trace = None
        self.vm_vris = []
        self.vm_previous_trace = None
        self.vm_exit_step_count = 0
        self.vm_exit_begin_trace = None
        self.vm_exits = []

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
    def get_vm_part_from_tainted_by_for_operand(
            operand: TraceAdimehtOperandForX64DbgTrace,
            vm_part_you_looking_for: str,
    ):
        _result = []
        _vm_part_types = ['VB', 'VR']
        if vm_part_you_looking_for not in _vm_part_types:
            raise Exception('[E] Invalid VM part type you looking for, it should be one of %s : %s'
                            % (_vm_part_types, vm_part_you_looking_for))
        _vm_part_form_you_looking_for = '%s_0x' % vm_part_you_looking_for
        _tainted_by_list = operand.get_tainted_by()
        for _tainted_by in _tainted_by_list:
            if _tainted_by.find(_vm_part_form_you_looking_for) == 0:
                _result.append(_tainted_by)
        return _result

    def identify_the_role_of_vm_part_for_operand(
            self,
            operand: TraceOperandForX64DbgTrace,
            initial_esp: int,
            stack_range: int = 0x1000,
    ):
        _identified_role = None
        _tainted_operands: list[TraceAdimehtOperandForX64DbgTrace] = self.get_tainted_operands()
        _tainted_by_for_tainted_operand: list[str] = []
        for _tainted_operand in _tainted_operands:
            if _tainted_operand.is_the_operand_derived_from_me(operand) is False:
                continue
            _tainted_by_for_tainted_operand = _tainted_operand.get_tainted_by()
            _vb_list = self.get_vm_part_from_tainted_by_for_operand(_tainted_operand, 'VB')
            _vr_list = self.get_vm_part_from_tainted_by_for_operand(_tainted_operand, 'VR')
            if self.reg_vbr_name_for_tainted_by in _tainted_by_for_tainted_operand:
                if len(_vb_list) > 0:
                    if operand.get_operand_type() == 'mem':
                        _mem_addr = operand.get_operand_value()
                        if (_mem_addr >= initial_esp - stack_range) and (_mem_addr < initial_esp + stack_range):
                            # memory address within stack
                            _identified_role = 'LV'
                            continue
                    # on VR(Virtual Register)
                    _identified_role = 'VR'
                elif len(_vb_list) == 0 and len(_vr_list) == 0:
                    # on VB(Virtual Bridge)
                    if _identified_role is None:
                        _identified_role = 'VB'
                else:
                    continue
            elif len(_vr_list) > 0:
                # on LV (Local Variable) # todo: maybe wrong? ###################################
                _identified_role = 'LV'
            else:
                continue

        if _identified_role is None:
            return _identified_role

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
            if self.logging_on_vr_identified:
                self.logs_to_show_in_comment.append('[%s : %s]'
                                                    % (
                                                        _vb_operand.get_vm_part(),
                                                        _vb_operand.get_operand_name(),
                                                    ))
        elif _identified_role == 'LV':
            if self.logging_on_lv_identified:
                self.logs_to_show_in_comment.append('[%s : %s]'
                                                    % (
                                                        _vb_operand.get_vm_part(),
                                                        _vb_operand.get_operand_name(),
                                                    ))
        if self.logging_on_vm_role_identified:
            self.logs_to_show_in_comment.append('[Role: %s : %s from %s (%s)]'
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

        return _identified_role

    def identify_the_role_of_vm_part_for_operands(
            self,
            operands: list[TraceOperandForX64DbgTrace],
            initial_esp: int,
            from_memory_formula: bool = False,
    ):
        for _operand in operands:
            if from_memory_formula:
                _memory_variables: list[TraceOperandForX64DbgTrace] = \
                    self.retrieve_operands_from_input_operand_memory_formulas(_operand)
                for _memory_variable in _memory_variables:
                    self.identify_the_role_of_vm_part_for_operand(_memory_variable, initial_esp)
            else:
                self.identify_the_role_of_vm_part_for_operand(_operand, initial_esp)

    def resolve_operands_to_adimeht_operands(self, operands: list[TraceOperandForX64DbgTrace])\
            -> list[TraceOperandForX64DbgTrace | TraceAdimehtOperandForX64DbgTrace]:
        _result = []
        for _operand in operands:
            _operand_from_tainted_operands = self.retrieve_same_operand_from_tainted_operands(_operand)
            if _operand_from_tainted_operands is None:
                _result.append(_operand)
                continue
            _result.append(_operand_from_tainted_operands)
        return _result

    @staticmethod
    def operands_contains_operand_for_pseudo_ir(
            operands: list[TraceOperandForX64DbgTrace | TraceAdimehtOperandForX64DbgTrace],
    ):
        _result = False
        _determined_roles_to_follow = ['VR', 'LV']
        for _operand in operands:
            if type(_operand) is not TraceAdimehtOperandForX64DbgTrace:
                continue
            _determined_role = _operand.get_determined_role()
            if _determined_role not in _determined_roles_to_follow:
                continue
            _result = True
            break
        return _result

    def print_pseudo_ir_related_operands(
            self,
            operands: list[TraceOperandForX64DbgTrace | TraceAdimehtOperandForX64DbgTrace],
            operand_type_to_show: str,
    ):
        for _operand in operands:
            if type(_operand) is TraceOperandForX64DbgTrace:
                self.logs_to_show_in_comment.append('[%s: %s]' % (operand_type_to_show, _operand.get_operand_name()))
            elif type(_operand) is TraceAdimehtOperandForX64DbgTrace:
                self.logs_to_show_in_comment.append('[%s: %s (%s)]'
                                                    % (
                                                        operand_type_to_show,
                                                        _operand.get_vm_part(),
                                                        _operand.get_tainted_by(),
                                                    ))
            else:
                self.logs_to_show_in_comment.append('[%s: %s (%s)]'
                                                    % (
                                                        operand_type_to_show,
                                                        _operand.get_operand_name(),
                                                        _operand.get_tainted_by(),
                                                    ))

    def generate_pseudo_ir(
            self,
            dst_operands: list[TraceOperandForX64DbgTrace | TraceAdimehtOperandForX64DbgTrace],
            src_operands: list[TraceOperandForX64DbgTrace | TraceAdimehtOperandForX64DbgTrace],
            logging_pseudo_ir: bool = False,
    ) -> list[str]:
        _irs = []
        if len(dst_operands) > 1 or len(src_operands) > 1:
            raise Exception('[E] Cannot generate pseudo IR : Too many operand\n - Dst : %s\n - Src : %s'
                            % (dst_operands, src_operands))

        _dst = None
        if len(dst_operands) > 0:
            if type(dst_operands[0]) is TraceAdimehtOperandForX64DbgTrace:
                _dst = dst_operands[0].get_vm_part()
                if _dst == '':
                    _dst = dst_operands[0].get_operand_name()
            else:
                _dst = dst_operands[0].get_operand_name()
        _src = None
        if len(src_operands) > 0:
            if type(src_operands[0]) is TraceAdimehtOperandForX64DbgTrace:
                _src = src_operands[0].get_vm_part()
                if _src == '':
                    _src = src_operands[0].get_operand_name()
            else:
                _src = src_operands[0].get_operand_name()

        if logging_pseudo_ir is True:
            self.logs_to_show_in_comment.append('[IR]')
        if len(self.context.current_capstone_instruction.groups) > 0:
            for _g in self.context.current_capstone_instruction.groups:
                if _g == capstone.x86.X86_GRP_CALL:
                    _irs.append('CALL %s' % _src)
                    if logging_pseudo_ir is True:
                        self.logs_to_show_in_comment.append(_irs[0])
                    return _irs
                elif _g == capstone.x86.X86_GRP_JUMP:
                    _irs.append('JMP %s' % _src)
                    if logging_pseudo_ir is True:
                        self.logs_to_show_in_comment.append(_irs[0])
                    return _irs
                elif _g == capstone.x86.X86_GRP_RET or _g == capstone.x86.X86_GRP_IRET:
                    _irs.append(self.context.x64dbg_trace['disasm'])
                    if logging_pseudo_ir is True:
                        self.logs_to_show_in_comment.append(_irs[0])
                    return _irs

        if self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_MOV,
            capstone.x86.X86_INS_PUSH,
            capstone.x86.X86_INS_PUSHFD,
            capstone.x86.X86_INS_POP,
            capstone.x86.X86_INS_POPFD,
        ]:
            _irs.append('MOV %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_MOVZX,
        ]:
            _irs.append('MOVZX %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_ADD,
        ]:
            _irs.append('ADD %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_SUB,
        ]:
            _irs.append('SUB %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XCHG,
        ]:
            # _irs.append('XCHG %s, %s' % (_dst, _src))
            _irs.append('MOV %%tmp, %s' % _src)
            _irs.append('MOV %s, %s' % (_src, _dst))
            _irs.append('MOV %s, %%tmp' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_CMPXCHG,
        ]:
            _irs.append('CMPXCHG %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_AND,
        ]:
            _irs.append('AND %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_OR,
        ]:
            _irs.append('OR %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XOR,
        ]:
            _irs.append('XOR %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_CMP,
        ]:
            _irs.append('CMP %s, %s' % (_dst, _src))
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_DEC,
        ]:
            _irs.append('DEC %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_INC,
        ]:
            _irs.append('INC %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_NEG,
        ]:
            _irs.append('NEG %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_NOT,
        ]:
            _irs.append('NOT %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_SHL,
        ]:
            _irs.append('SHL %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_SHR,
        ]:
            _irs.append('SHR %s' % _dst)
        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_TEST,
        ]:
            _irs.append('TEST %s' % _dst)
        else:
            raise Exception('[E] Cannot generate pseudo IR : Unhandled instruction')
        if logging_pseudo_ir is True:
            [self.logs_to_show_in_comment.append(_ir) for _ir in _irs]
        return _irs

    def generate_pseudo_ir_by_using_vr_related_instruction(
            self,
            dst_operands: list[TraceOperandForX64DbgTrace],
            src_operands: list[TraceOperandForX64DbgTrace],
    ) -> list[str]:
        _dst_adimeht_operands = self.resolve_operands_to_adimeht_operands(dst_operands)
        _src_adimeht_operands = self.resolve_operands_to_adimeht_operands(src_operands)
        _dst_should_be_converted = self.operands_contains_operand_for_pseudo_ir(_dst_adimeht_operands)
        _src_should_be_converted = self.operands_contains_operand_for_pseudo_ir(_src_adimeht_operands)
        if _dst_should_be_converted is False and _src_should_be_converted is False:
            return []
        _irs = self.generate_pseudo_ir(_dst_adimeht_operands, _src_adimeht_operands, self.logging_pseudo_ir)
        if self.logging_pseudo_ir_operands:
            self.print_pseudo_ir_related_operands(_dst_adimeht_operands, 'dst')
            self.print_pseudo_ir_related_operands(_src_adimeht_operands, 'src')
        return _irs

    def run_adimeht_single_line_by_x64dbg_trace(self, x64dbg_trace, initial_esp):
        self.logs_to_show_in_comment = []
        self.context.set_context_by_x64dbg_trace(x64dbg_trace)

        # todo: for debugging begin ##################################
        if self.context.x64dbg_trace['id'] == 9933:
            self.api.print(self.context.x64dbg_trace['id'])
        # todo: for debugging end ##################################

        _you_are_in_vm = self.check_you_are_in_vm()
        if self.logging_you_are_in_vm:
            if _you_are_in_vm:
                self.logs_to_show_in_comment.append('[VM]')

        _dst_operands: list[TraceOperandForX64DbgTrace] | None = None
        _src_operands: list[TraceOperandForX64DbgTrace] | None = None
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands(x64dbg_trace)

        self.identify_the_role_of_vm_part_for_operands(_dst_operands, initial_esp)
        _from_memory_formula = False  # will be set as True when it's LEA
        if self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_LEA,
        ]:
            _from_memory_formula = True
        self.identify_the_role_of_vm_part_for_operands(
            _src_operands,
            initial_esp,
            from_memory_formula=_from_memory_formula,
        )

        _irs = self.generate_pseudo_ir_by_using_vr_related_instruction(_dst_operands, _src_operands)

        # back up logs
        _logs_to_show_in_comment = self.logs_to_show_in_comment

        # run taint
        _new_x64dbg_trace = self.run_taint_single_line_by_x64dbg_trace(x64dbg_trace)
        if _new_x64dbg_trace['comment'] != '':
            _logs_to_show_in_comment.append(_new_x64dbg_trace['comment'])
        _new_x64dbg_trace['comment'] = ' | '.join(_logs_to_show_in_comment)
        _new_x64dbg_trace['irs'] = _irs
        return _new_x64dbg_trace

    @staticmethod
    def get_memory_type_operands_in_vm_area(
            operands: list[TraceOperandForX64DbgTrace],
            initial_esp: int,
            stack_range=0x1000,
            find_belonging_to_stack=False,
    ) -> list[TraceOperandForX64DbgTrace]:
        _result: list[TraceOperandForX64DbgTrace] = []
        for _operand in operands:
            if _operand.get_operand_type() != 'mem':
                continue
            # look up memory area where it belongs
            _mem_addr = _operand.get_operand_value()
            if (_mem_addr >= initial_esp - stack_range) and (_mem_addr < initial_esp + stack_range):
                # memory address within stack
                if find_belonging_to_stack is False:
                    continue
            else:
                # memory address within VM area
                if find_belonging_to_stack is True:
                    continue
            _result.append(_operand)
        return _result

    @staticmethod
    def is_in_virtualized_instruction_tricky_way_1(x64dbg_trace, initial_esp, stack_range=0x1000):
        _taints: list[TraceAdimehtOperandForX64DbgTrace] = x64dbg_trace['taints']
        _host_map = {
            'eax': 0,
            'ebx': 0,
            'ecx': 0,
            'edx': 0,
            'esi': 0,
            'edi': 0,
            'ebp': 0,
        }
        _vm_map = {
            'eax': 0,
            'ebx': 0,
            'ecx': 0,
            'edx': 0,
            'esi': 0,
            'edi': 0,
            'ebp': 0,
        }
        for _taint in _taints:
            if _taint.get_operand_type() != 'mem':
                continue
            _tainted_by = _taint.get_tainted_by()
            if len(_tainted_by) != 1:
                continue
            _tainted_by_reg = _tainted_by[0]
            if _tainted_by_reg not in _host_map.keys():
                continue
            _mem_addr = _taint.get_operand_value()
            if (_mem_addr >= initial_esp - stack_range) and (_mem_addr < initial_esp + stack_range):
                # memory address within stack
                _host_map[_tainted_by_reg] += 1
            else:
                # memory address within virtual machine
                _vm_map[_tainted_by_reg] += 1
        for _register in _host_map.keys():
            if (_host_map[_register] == 0) and (_vm_map[_register] > 0):
                return True
        return False

    initial_vsp = None

    def is_in_virtualized_instruction_tricky_way_2(self, x64dbg_trace, initial_esp, stack_range=0x1000):
        _esp = self.context.get_register_value('esp')
        if self.initial_vsp is None:
            self.initial_vsp = _esp
            print('[+] Initial VSP : 0x%x' % _esp)
            return False
        if _esp == self.initial_vsp:
            return False
        return True

    def is_in_vm_exit(
            self,
            dst_operands: list[TraceOperandForX64DbgTrace],
            src_operands: list[TraceOperandForX64DbgTrace],
            initial_esp: int,
    ):
        if self.context.current_capstone_instruction.id not in [
            capstone.x86.X86_INS_PUSH,
        ]:
            return False
        if len(dst_operands) != 1 and len(src_operands) != 1:
            print('[E] Invalid operands found while checking whether you are in VM exit')
            print(' - %d : 0x%x : %s (dst: %s, src: %s)' % (
                self.context.x64dbg_trace['id'],
                self.context.x64dbg_trace['ip'],
                self.context.x64dbg_trace['disasm'],
                ', '.join([_op.get_operand_name() for _op in dst_operands]),
                ', '.join([_op.get_operand_name() for _op in src_operands]),
            ))
            return False
        _dst_operands_in_stack = self.get_memory_type_operands_in_vm_area(
            dst_operands,
            initial_esp,
            find_belonging_to_stack=True,
        )
        if len(_dst_operands_in_stack) == 0:
            return False
        _src_operands_in_vm = self.get_memory_type_operands_in_vm_area(
            src_operands,
            initial_esp,
            find_belonging_to_stack=False,
        )
        if len(_src_operands_in_vm) == 0:
            return False
        return True

    def run_recognizing_vm_enter_and_exit(self, x64dbg_trace, initial_esp: int):
        self.logs_to_show_in_comment = []
        self.context.set_context_by_x64dbg_trace(x64dbg_trace)

        _comment = x64dbg_trace['comment']
        if _comment.find('VR') == -1:
            return x64dbg_trace
        # Current instruction is Virtual Register related Instruction (VRI)

        _in_virtualized_instruction = self.is_in_virtualized_instruction_tricky_way_2(x64dbg_trace, initial_esp)
        if _in_virtualized_instruction is False:
            if self.vm_enter_begin_trace is None:
                self.vm_enter_begin_trace = x64dbg_trace
            else:
                self.vm_enter_end_trace = x64dbg_trace
        else:
            if self.vm_enter_begin_trace is not None and self.vm_enter_end_trace is not None:
                self.vm_enters.append({
                    'begin': self.vm_enter_begin_trace['id'],
                    'end': self.vm_enter_end_trace['id']
                })
                self.vm_enter_begin_trace = None
                self.vm_enter_end_trace = None
                self.vm_vri_begin_trace = x64dbg_trace

        _dst_operands: list[TraceOperandForX64DbgTrace] | None = None
        _src_operands: list[TraceOperandForX64DbgTrace] | None = None
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands(x64dbg_trace)
        _is_in_vm_exit = self.is_in_vm_exit(_dst_operands, _src_operands, initial_esp)
        if _is_in_vm_exit is True:
            self.vm_exit_step_count += 1
            if self.vm_exit_step_count == 1:
                self.vm_exit_begin_trace = x64dbg_trace
                self.vm_vri_end_trace = self.vm_previous_trace
            elif self.vm_exit_step_count == 8:
                self.vm_exits.append({
                    'begin': self.vm_exit_begin_trace['id'],
                    'end': x64dbg_trace['id'],
                })
                self.vm_vris.append({
                    'begin': self.vm_vri_begin_trace['id'],
                    'end': self.vm_vri_end_trace['id'],
                })
                self.initial_vsp = None
        else:
            if self.vm_exit_step_count < 8:
                self.vm_exit_begin_trace = None
            self.vm_exit_step_count = 0

        self.vm_previous_trace = x64dbg_trace
        x64dbg_trace['comment'] = _comment
        return x64dbg_trace

    @staticmethod
    def parse_intermediate_representation(index: int, ir: str) -> dict[str, str] | None:
        _reg_exps = [
            r'(?P<operator>[^ ]+) (?P<dst>[^,]+), (?P<src>[^,]+)',
            r'(?P<operator>[^ ]+) (?P<dst>[^,]+)',
        ]
        for _reg_exp in _reg_exps:
            _match = re.match(_reg_exp, ir)
            if _match is None:
                continue
            # ir_structure
            return {
                'index': index,
                'operator': _match.group('operator'),
                'dst': _match.group('dst'),
                'src': _match.group('src') if 'src' in _match.groupdict() else '',
            }
        return None

    # candidate list of list which contains ir_structure
    candidates_of_dummy_irs: list[list[dict[str, str]]] = []
    indexes_for_dummy_ir: list[int] = []

    def identify_single_operand_dummy_ir(self, x64dbg_trace, ir_structure):
        _operator = ir_structure['operator']
        _dst_ir = ir_structure['dst']
        _src_ir = ir_structure['src']
        if _dst_ir == _src_ir:
            self.indexes_for_dummy_ir.append(int(ir_structure['index']))
            return
        _idx_dummy_irs_to_remove: list[int] = []
        _is_appended = False
        for _idx in range(len(self.candidates_of_dummy_irs)):
            _candidate_of_dummy_irs = self.candidates_of_dummy_irs[_idx]
            _head_ir_structure = _candidate_of_dummy_irs[0]
            _tail_ir_structure = _candidate_of_dummy_irs[-1]
            if _operator == 'MOV':
                if _dst_ir == _tail_ir_structure['dst']:
                    _idx_dummy_irs_to_remove.append(_idx)
                if _src_ir == _tail_ir_structure['dst']:
                    _candidate_of_dummy_irs.append(ir_structure)
                    if _dst_ir == _head_ir_structure['src']:
                        _idx_dummy_irs: list[int] = [
                            int(_ir_structure['index']) for _ir_structure in _candidate_of_dummy_irs
                        ]
                        self.indexes_for_dummy_ir.extend(_idx_dummy_irs)
                        _idx_dummy_irs_to_remove.append(_idx)
                    _is_appended = True
            else:
                _is_appended = True
                if (_dst_ir == _tail_ir_structure['dst']) or (_src_ir == _tail_ir_structure['dst']):
                    _idx_dummy_irs_to_remove.append(_idx)

        _idx_dummy_irs_to_remove = list(set(_idx_dummy_irs_to_remove))
        _sorted_idx_dummy_irs_to_remove = sorted(_idx_dummy_irs_to_remove, reverse=True)
        for _idx in _sorted_idx_dummy_irs_to_remove:
            del self.candidates_of_dummy_irs[_idx]
        if _is_appended is False:
            _is_original_ebp = False
            _dst_operands = x64dbg_trace['dst']
            for _dst_operand in _dst_operands:
                _tainted_operand = self.retrieve_same_operand_from_operands(_dst_operand, x64dbg_trace['taints'])
                if _tainted_operand is not None:
                    _tainted_by = _tainted_operand.get_tainted_by()
                    if len(_tainted_by) == 1:
                        if _tainted_by[0] == 'ebp':
                            _is_original_ebp = True
                            break
            if _is_original_ebp is False:
                self.candidates_of_dummy_irs.append([ir_structure])

    def identify_dummy_ir(self, ir_structure):
        _index = int(ir_structure['index'])
        _operator = ir_structure['operator']
        _dst = ir_structure['dst']
        _src = ir_structure['src']
        if _dst == _src:
            self.indexes_for_dummy_ir.append(_index)
            return
        print(' - Candi : %d' % _index)

    def identify_dummy_irs(self, x64dbg_trace):
        _index = x64dbg_trace['id']
        _irs = x64dbg_trace['irs']
        for _ir in _irs:
            _ir_structure = self.parse_intermediate_representation(_index, _ir)
            if _ir_structure is None:
                raise Exception('[E] Cannot parse IR at index %d : %s' % (_index, _ir))
            self.identify_single_operand_dummy_ir(x64dbg_trace, _ir_structure)
            # if x64dbg_trace['comment'].find('VR') == -1:
            #     print('%s : %s' % (x64dbg_trace['id'], x64dbg_trace['comment']))
            #     self.identify_dummy_ir(_ir_structure)

    previous_vr_trace = None

    def identify_virtual_instruction(self, x64dbg_trace):
        _index: int = int(x64dbg_trace['id'])
        _comment: str = x64dbg_trace['comment']
        _dst_operands: list[TraceAdimehtOperandForX64DbgTrace] = x64dbg_trace['dst']
        _src_operands: list[TraceAdimehtOperandForX64DbgTrace] = x64dbg_trace['src']
        if _comment.find('VR') != -1:
            self.previous_vr_trace = x64dbg_trace
            return 'VI'
        if _comment.find('IR') != -1:
            _previous_dst_operands: list[TraceAdimehtOperandForX64DbgTrace] = self.previous_vr_trace['dst']
            for _dst_operand in _dst_operands:
                for _previous_dst_operand in _previous_dst_operands:
                    if _previous_dst_operand.is_the_operand_derived_from_me(_dst_operand) is True:
                        return 'VI'
            for _src_operand in _src_operands:
                for _previous_dst_operand in _previous_dst_operands:
                    if _previous_dst_operand.is_the_operand_derived_from_me(_src_operand) is True:
                        return 'VI'
        return 'VIC'

    def run_identifying_virtual_instruction(self, x64dbg_trace):
        _index = x64dbg_trace['id']
        _comment = x64dbg_trace['comment']
        _is_in_virtualized_instruction = False

        if _comment.find('IR') != -1:
            # Virtual Machine related Instruction
            _comment = '[VMI] ' + _comment
        if _comment.find('VR') != -1:
            # Virtual Register related Instruction
            _comment = '[VRI] ' + _comment

        for _vm_vri in self.vm_vris:
            if _vm_vri['begin'] <= _index <= _vm_vri['end']:
                _is_in_virtualized_instruction = True
        if _is_in_virtualized_instruction is True:
            if (_comment.find('VR') != -1) or (_comment.find('IR') != -1):
                _instruction_type = self.identify_virtual_instruction(x64dbg_trace)
                _comment = '[%s] ' % _instruction_type + _comment

        x64dbg_trace['comment'] = _comment
        return x64dbg_trace
