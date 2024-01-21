from core.api import Api
from plugins.tmpOperand import TmpOperandForX64DbgTrace
from plugins.tmpContext import TmpContext
from plugins.tmpTaintedOperand import TmpTaintedOperandForX64DbgTrace

import capstone


class TmpTaintModule:
    # core.Api
    api = None
    # capstone.Cs
    capstone_bridge = None
    # context
    context: TmpContext = None

    # list of taint [
    #   {
    #     labels: ['your input', ...],
    #     name: 'eax' | '[0x401000]',
    #   }, ...
    # ]
    tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = []

    you_are_in_vm: bool = False

    reg_vbr: TmpTaintedOperandForX64DbgTrace = None
    reg_vbr_value: int = 0
    reg_vbr_role_name: str = 'vbr'

    def __init__(self, api: Api, capstone_bridge, context: TmpContext, vbr_value: int):
        self.api = api
        if capstone_bridge is None:
            self.capstone_bridge = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            self.capstone_bridge.detail = True
        else:
            self.capstone_bridge = capstone_bridge
        if context is None:
            self.context = TmpContext(capstone_bridge=self.capstone_bridge)
        else:
            self.context = context

        # set VBR (Virtual machine Base Register)
        self.reg_vbr = TmpTaintedOperandForX64DbgTrace(self.context, None)
        self.reg_vbr.force_set_tainted_operand(
            'reg',
            'ebp',
            vbr_value,
            [],
            ['ebp'],
            [self.get_reg_vbr_role_name()],
        )
        self.set_reg_vbr_value(vbr_value)

    def get_you_are_in_vm(self) -> bool:
        return self.you_are_in_vm

    def get_tainted_operands(self) -> list[TmpTaintedOperandForX64DbgTrace]:
        return self.tainted_operands

    def get_reg_vbr_value(self) -> int:
        return self.reg_vbr_value

    def get_reg_vbr_role_name(self) -> str:
        return self.reg_vbr_role_name

    def set_you_are_in_vm(self, you_are_in_vm: bool):
        self.you_are_in_vm = you_are_in_vm

    def set_tainted_operands(self, tainted_operands: list[TmpTaintedOperandForX64DbgTrace]):
        self.tainted_operands = tainted_operands

    def set_reg_vbr_value(self, reg_vbr_value: int):
        self.reg_vbr_value = reg_vbr_value

    def get_vm_part_name_of_operand(
            self,
            operand: TmpOperandForX64DbgTrace | TmpTaintedOperandForX64DbgTrace,
    ) -> str | None:
        if operand.get_operand_type() != 'mem':
            return None
        if self.has_operand_with_role_on_memory_formula(operand, self.get_reg_vbr_role_name()) is False:
            return None
        _vm_part_type = 'VB'  # Virtual Bus

        # todo: test begin, see 1,166
        _tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = self.get_tainted_operands()
        for _tainted_operand in _tainted_operands:
            if _tainted_operand.is_the_operand_derived_from_me(operand) is True:
                _tainted_by = _tainted_operand.get_tainted_by()
                if 'ebp' not in _tainted_by:
                    continue
                _b_recognized = False
                for _v_tainted_by in _tainted_by:
                    if _v_tainted_by.find('VB_') != -1:
                        _vm_part_type = 'VR'  # Virtual Register
                        _b_recognized = True
                        break
                if _b_recognized is True:
                    break
        # todo: test end

        _vbr_value = self.get_reg_vbr_value()
        _operand_value: int = operand.get_operand_value()
        _vb_offset = _operand_value - _vbr_value
        _vb_name = '%s_0x%x' % (_vm_part_type, _vb_offset)
        return _vb_name

    def add_tainted_operand_to_tainted_operands(
            self,
            operand: TmpOperandForX64DbgTrace | TmpTaintedOperandForX64DbgTrace,
    ):
        # when the entered operand already has been tainted,
        # the tainted operand's tainted_by should be changed (It seems like it is already doing that)
        self.remove_tainted_operand_from_tainted_operands(operand)
        _vbr_role_name = self.get_reg_vbr_role_name()
        _vm_part_name = operand.get_vm_part()
        if _vm_part_name == '':
            _vm_part_name = self.get_vm_part_name_of_operand(operand)
            if _vm_part_name is not None:
                operand.set_vm_part(_vm_part_name)
        _vm_part_name = operand.get_vm_part()
        if _vm_part_name != '':
            _determined_roles = operand.get_determined_roles()
            if (len(_determined_roles) == 1) and (_determined_roles[0] == 'imm'):
                _tainted_by = operand.get_tainted_by()
                if len(_tainted_by) == 0:
                    _tainted_by.append(_vm_part_name)
                    operand.set_tainted_by(_tainted_by)
        _tainted_operands = self.get_tainted_operands()
        _tainted_operands.append(operand)
        self.set_tainted_operands(_tainted_operands)

    def remove_tainted_operand_from_tainted_operands(
            self,
            operand: TmpOperandForX64DbgTrace | TmpTaintedOperandForX64DbgTrace,
    ) -> bool:
        for _i_tainted_operand in range(len(self.tainted_operands)):
            _tainted_operand = self.tainted_operands[_i_tainted_operand]
            _is_same_operand = _tainted_operand.is_same_operand(operand)
            # when the operand has already been tainted
            if _is_same_operand is True:
                del self.tainted_operands[_i_tainted_operand]
                return True
        return False

    def retrieve_operands_from_context(self) -> list[TmpOperandForX64DbgTrace]:
        _extracted_operands: list[TmpOperandForX64DbgTrace] = []
        if len(self.context.current_capstone_instruction.operands) == 0:
            return _extracted_operands
        for _capstone_operand in self.context.current_capstone_instruction.operands:
            _extracted_operand = TmpOperandForX64DbgTrace(self.context, _capstone_operand)
            _extracted_operands.append(_extracted_operand)
        return _extracted_operands

    # returns dsts, srcs as operand list
    # returns None, None when something goes wrong
    def retrieve_dst_and_src_operands(
            self,
            operands: list[TmpOperandForX64DbgTrace]
    ) -> (list[TmpOperandForX64DbgTrace], list[TmpOperandForX64DbgTrace]):
        _dst_operands: list[TmpOperandForX64DbgTrace] = []
        _src_operands: list[TmpOperandForX64DbgTrace] = []
        if len(self.context.current_capstone_instruction.groups) > 0:
            for _g in self.context.current_capstone_instruction.groups:

                # todo
                # add EIP as operand

                if _g == capstone.x86.X86_GRP_CALL:
                    _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
                    _operand_esp_value = self.context.get_register_value('esp') - 4
                    _operand_esp.force_set_operand(
                        'mem',
                        '[0x%08x]' % _operand_esp_value,
                        _operand_esp_value,
                        '[ esp - 4 ]'.split(' ')
                    )
                    _dst_operands.append(_operand_esp)
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src_operands.append(operands[0])
                    return _dst_operands, _src_operands
                elif _g == capstone.x86.X86_GRP_JUMP:
                    if len(operands) == 0 or len(operands) > 1:
                        return None, None
                    _src_operands.append(operands[0])
                    return _dst_operands, _src_operands
                elif _g == capstone.x86.X86_GRP_RET or _g == capstone.x86.X86_GRP_IRET:
                    _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
                    _operand_esp_value = self.context.get_register_value('esp')
                    _operand_esp.force_set_operand(
                        'mem',
                        '[0x%08x]' % _operand_esp_value,
                        _operand_esp_value,
                        '[ esp ]'.split(' ')
                    )
                    _src_operands.append(_operand_esp)
                    return _dst_operands, _src_operands

        if self.context.current_capstone_instruction.id == capstone.x86.X86_INS_PUSH:
            _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp') - 4
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp - 4 ]'.split(' ')
            )
            _dst_operands.append(_operand_esp)
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _src_operands.append(operands[0])
        elif self.context.current_capstone_instruction.id == capstone.x86.X86_INS_PUSHFD:
            _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp') - 4
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp - 4 ]'.split(' ')
            )
            _dst_operands.append(_operand_esp)
            _operand_eflags = TmpOperandForX64DbgTrace(self.context, None)
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
            _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp')
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp ]'.split(' ')
            )
            if len(operands) == 0 or len(operands) > 1:
                return None, None
            _src_operands.append(_operand_esp)
            _dst_operands.append(operands[0])
        elif self.context.current_capstone_instruction.id == capstone.x86.X86_INS_POPFD:
            _operand_esp = TmpOperandForX64DbgTrace(self.context, None)
            _operand_esp_value = self.context.get_register_value('esp')
            _operand_esp.force_set_operand(
                'mem',
                '[0x%08x]' % _operand_esp_value,
                _operand_esp_value,
                '[ esp ]'.split(' ')
            )
            _src_operands.append(_operand_esp)
            _operand_eflags = TmpOperandForX64DbgTrace(self.context, None)
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
            capstone.x86.X86_INS_CMPXCHG
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
        elif self.context.current_capstone_instruction.id in [capstone.x86.X86_INS_STD]:
            pass
        else:
            raise Exception(
                '[E] Unhandled instruction ID : %s (https://github.com/capstone-engine/capstone/blob/master/include'
                '/capstone/x86.h)' % self.context.current_capstone_instruction.id)
        return _dst_operands, _src_operands

    # todo
    # you have to find a way to notify the operand used some tainted value indirectly via memory formula
    def retrieve_list_of_operands_that_tainted_the_operand(
            self,
            operand: TmpOperandForX64DbgTrace,
    ) -> list[TmpTaintedOperandForX64DbgTrace]:
        _operands_tainted_the_operand: list[TmpTaintedOperandForX64DbgTrace] = []
        for _tainted_operand in self.tainted_operands:
            if _tainted_operand.is_same_operand(operand):
                _operands_tainted_the_operand.append(_tainted_operand)
        return _operands_tainted_the_operand

    def retrieve_tainted_operands_from_input_operands(
            self,
            operands: list[TmpOperandForX64DbgTrace],
    ) -> list[TmpTaintedOperandForX64DbgTrace]:
        _tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = []
        for _operand in operands:
            _operands_tainted_the_operand = self.retrieve_list_of_operands_that_tainted_the_operand(
                _operand,
            )
            # when a length of the _operands_tainted_the_operand is 0,
            # the operand is tainted by any other tainted operands
            if len(_operands_tainted_the_operand) == 0:
                continue
            _new_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
            _new_tainted_by: list[str] = []
            _new_determined_roles: list[str] = []  # maybe a role wouldn't be over 1
            for _operand_tainted_the_operand in _operands_tainted_the_operand:
                _new_tainted_by.extend(_operand_tainted_the_operand.get_tainted_by())
                _determined_roles: list[str] = _operand_tainted_the_operand.get_determined_roles()
                if len(_determined_roles) > 0:
                    _new_determined_roles.extend(_determined_roles)
            # remove duplicates in tainted_by and determined_role
            _new_tainted_by = list(set(_new_tainted_by))
            _new_determined_roles = list(set(_new_determined_roles))
            _new_tainted_operand.force_set_tainted_operand(
                _operand.get_operand_type(),
                _operand.get_operand_name(),
                _operand.get_operand_value(),
                _operand.get_memory_formula(),
                _new_tainted_by,
                _new_determined_roles,
            )
            _vm_part = self.get_vm_part_name_of_operand(_operand)
            if _vm_part is not None:
                _new_tainted_operand.set_vm_part(_vm_part)
            _tainted_operands.append(_new_tainted_operand)
        return _tainted_operands

    def retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
            self,
            tainted_operands: list[TmpTaintedOperandForX64DbgTrace],
    ) -> (list[str], list[str]):
        _merged_tainted_by: list[str] = []
        _merged_determined_roles: list[str] = []
        for _tainted_operand in tainted_operands:
            _tainted_by = _tainted_operand.get_tainted_by()
            _merged_tainted_by.extend(_tainted_by)
            _determined_roles = _tainted_operand.get_determined_roles()
            _merged_determined_roles.extend(_determined_roles)
        _merged_tainted_by = list(set(_merged_tainted_by))
        _merged_determined_roles = list(set(_merged_determined_roles))
        return _merged_tainted_by, _merged_determined_roles

    def run_taint_with_dst_and_src_operands(
            self,
            dst_operands: list[TmpOperandForX64DbgTrace],
            src_operands: list[TmpOperandForX64DbgTrace],
            show_log=False,
    ) -> (list[TmpTaintedOperandForX64DbgTrace], list[TmpTaintedOperandForX64DbgTrace], str):
        def _msg_on_add_operand(operand: TmpTaintedOperandForX64DbgTrace, determined_roles, tainted_by) -> str:
            __len_determined_roles = len(determined_roles)
            __vm_part = operand.get_vm_part()
            if __len_determined_roles > 0:
                if __vm_part != '':
                    return 'Add : %s:%s (%s) from %s' \
                        % (__vm_part, operand.get_operand_name(), determined_roles, tainted_by)
                return 'Add : %s (%s) from %s' \
                    % (operand.get_operand_name(), determined_roles, tainted_by)
            if __vm_part != '':
                return 'Add : %s:%s from %s' \
                    % (__vm_part, operand.get_operand_name(), tainted_by)
            return 'Add : %s from %s' \
                % (operand.get_operand_name(), tainted_by)

        def _msg_on_del_operand(operand: TmpOperandForX64DbgTrace) -> str:
            return 'Del : %s' % operand.get_operand_name()

        _strs_to_show_in_comment: list[str] = []
        _dst_tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = \
            self.retrieve_tainted_operands_from_input_operands(dst_operands)
        _src_tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = \
            self.retrieve_tainted_operands_from_input_operands(src_operands)

        _tainted_operands_to_remove: list[TmpOperandForX64DbgTrace] = []
        _tainted_operands_to_add: list[TmpTaintedOperandForX64DbgTrace] = []

        # todo
        # LEA handler should be added, probably?
        # AND handler should be added, probably?
        # OR handler should be added, probably?
        # POP handler should be added, access VB memory via operands in memory formula
        # -> see 313, maybe it should be added to VB related function

        # todo : you were doing this
        # add vm_part_name when adding new tainted operand is memory and VB
        # recognizing vbr, see 70431(add arg_1, arg_2) 71054 for 0x003d7692
        # on 71054 -> ecx was vbr but when printing tainted operands, ecx has been changed, so it cannot recognize VB
        #          -> set vm_part_name when creating a new tainted operand to add? nope
        #          -> see 4018, the first hit of 0x003d7692, it does not recognized as VB (!!!!!!!!!!!!)

        if self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_ADD,
            capstone.x86.X86_INS_SUB,
        ]:
            # when the source operand has been tainted,
            # it taints the destination operand,
            # but the origin one still remains
            if len(_src_tainted_operands) > 0:
                _dst_operand = dst_operands[0]
                _src_operand = src_operands[0]
                _dst_tainted_by, _dst_determined_roles \
                    = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                        _dst_tainted_operands
                    )
                _src_tainted_by, _src_determined_roles \
                    = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                        _src_tainted_operands
                    )
                _tainted_by = list(set(_dst_tainted_by + _src_tainted_by))
                _determined_roles = list(set(_dst_determined_roles + _src_determined_roles))
                _tainted_operands_to_remove.append(_dst_operand)
                _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                _dst_tainted_operand.force_set_tainted_operand(
                    _dst_operand.get_operand_type(),
                    _dst_operand.get_operand_name(),
                    _dst_operand.get_operand_value(),
                    _dst_operand.get_memory_formula(),
                    _tainted_by,
                    _determined_roles,
                )
                _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                if _vm_part is not None:
                    _dst_tainted_operand.set_vm_part(_vm_part)
                _tainted_operands_to_add.append(_dst_tainted_operand)

        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XOR,
        ]:

            # todo
            # on XOR, deciding taint it or not should be managed by tainted_by
            # see 286 ~ 291

            _dst_operand = dst_operands[0]
            _src_operand = src_operands[0]
            # on XOR, remove destination when destination and source are same
            if _dst_operand.is_same_operand(_src_operand) or _dst_operand.has_same_value(_src_operand):
                _tainted_operands_to_remove.append(_dst_operand)
            # on XOR, extend tainted_by for destination when destination and source are different
            else:
                # on XOR, when the source operand has been tainted,
                # it extends taint the destination operand
                if len(_src_tainted_operands) > 0:
                    _dst_tainted_by, _dst_determined_roles \
                        = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                            _dst_tainted_operands
                        )
                    _src_tainted_by, _src_determined_roles \
                        = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                            _src_tainted_operands
                        )
                    _tainted_by = list(
                        set(_dst_tainted_by + _src_tainted_by)
                        - (set(_dst_tainted_by) & set(_src_tainted_by))
                    )
                    _determined_roles = list(
                        set(_dst_determined_roles + _src_determined_roles)
                        - (set(_dst_determined_roles) & set(_src_determined_roles))
                    )
                    if len(_tainted_by) > 0:
                        _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                        _dst_tainted_operand.force_set_tainted_operand(
                            _dst_operand.get_operand_type(),
                            _dst_operand.get_operand_name(),
                            _dst_operand.get_operand_value(),
                            _dst_operand.get_memory_formula(),
                            _tainted_by,
                            _determined_roles,
                        )
                        _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                        if _vm_part is not None:
                            _dst_tainted_operand.set_vm_part(_vm_part)
                        _tainted_operands_to_add.append(_dst_tainted_operand)
                    else:
                        _tainted_operands_to_remove.append(_dst_operand)

        elif self.context.current_capstone_instruction.id in [
            capstone.x86.X86_INS_XCHG,
            capstone.x86.X86_INS_CMPXCHG,
        ]:
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
                    return _dst_tainted_operands, _src_tainted_operands, ', '.join(_strs_to_show_in_comment)
            if len(_dst_tainted_operands) > 0:
                _tainted_operands_to_remove.append(_dst_operand)
            if len(_src_tainted_operands) > 0:
                _tainted_operands_to_remove.append(_src_operand)
            if len(_dst_tainted_operands) > 0:
                _dst_tainted_by, _dst_determined_roles \
                    = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                        _dst_tainted_operands
                    )
                _src_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                _src_tainted_operand.force_set_tainted_operand(
                    _src_operand.get_operand_type(),
                    _src_operand.get_operand_name(),
                    _src_operand.get_operand_value(),
                    _src_operand.get_memory_formula(),
                    _dst_tainted_by,
                    _dst_determined_roles,
                )
                _vm_part = self.get_vm_part_name_of_operand(_src_tainted_operand)
                if _vm_part is not None:
                    _src_tainted_operand.set_vm_part(_vm_part)
                _tainted_operands_to_add.append(_src_tainted_operand)
            if len(_src_tainted_operands) > 0:
                _src_tainted_by, _src_determined_roles \
                    = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                        _src_tainted_operands
                    )
                _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                _dst_tainted_operand.force_set_tainted_operand(
                    _dst_operand.get_operand_type(),
                    _dst_operand.get_operand_name(),
                    _dst_operand.get_operand_value(),
                    _dst_operand.get_memory_formula(),
                    _src_tainted_by,
                    _src_determined_roles,
                )
                _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                if _vm_part is not None:
                    _dst_tainted_operand.set_vm_part(_vm_part)
                _tainted_operands_to_add.append(_dst_tainted_operand)

        # in normal case
        else:
            # when the source operand has been tainted,
            # it taints the destination operand
            if len(_src_tainted_operands) > 0:
                _src_tainted_by, _src_determined_roles \
                    = self.retrieve_merged_tainted_by_and_determined_roles_from_tainted_operands(
                        _src_tainted_operands
                    )

                # if self.context.x64dbg_trace['id'] == 71054:  # todo: for debugging
                #     for _src_tainted_operand in _src_tainted_operands:
                #         self.api.print('[+] Src tainted operand')
                #         self.api.print(_src_tainted_operand.get_operand_name())
                #         self.api.print(_src_tainted_operand.get_operand_type())
                #         self.api.print('0x%08x' % _src_tainted_operand.get_operand_value())
                #         self.api.print(str(_src_tainted_operand.get_determined_roles()))
                #         self.api.print(str(_src_tainted_operand.get_tainted_by()))
                #         self.api.print('Mem: %s' % _src_tainted_operand.get_memory_formula())
                #         self.api.print('VM: %s' % _src_tainted_operand.get_vm_part())

                for _dst_operand in dst_operands:
                    _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                    _dst_tainted_operand.force_set_tainted_operand(
                        _dst_operand.get_operand_type(),
                        _dst_operand.get_operand_name(),
                        _dst_operand.get_operand_value(),
                        _dst_operand.get_memory_formula(),
                        _src_tainted_by,
                        _src_determined_roles,
                    )
                    _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                    if _vm_part is not None:
                        _dst_tainted_operand.set_vm_part(_vm_part)
                    _tainted_operands_to_add.append(_dst_tainted_operand)
            # when the source operand hasn't been tainted,
            # the destination operands would be removed from tainted operand list
            else:
                for _dst_operand in dst_operands:
                    _tainted_operands_to_remove.append(_dst_operand)
                if (len(dst_operands) == 1) and (len(src_operands) == 1):
                    _dst_operand = dst_operands[0]
                    _src_operand = src_operands[0]
                    _src_operand_type = _src_operand.get_operand_type()
                    if _src_operand_type == 'imm':
                        _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                        _tainted_by = []
                        _determined_roles = ['imm']
                        _dst_tainted_operand.force_set_tainted_operand(
                            _dst_operand.get_operand_type(),
                            _dst_operand.get_operand_name(),
                            _dst_operand.get_operand_value(),
                            _dst_operand.get_memory_formula(),
                            _tainted_by,
                            _determined_roles,
                        )
                        _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                        if _vm_part is not None:
                            _dst_tainted_operand.set_vm_part(_vm_part)
                        _tainted_operands_to_add.append(_dst_tainted_operand)
                    elif _src_operand_type == 'mem':
                        if self.has_operand_with_role_on_memory_formula(
                            _src_operand,
                            self.get_reg_vbr_role_name()
                        ) is True:
                            if len(_src_tainted_operands) == 1:
                                _src_tainted_operand = _src_tainted_operands[0]
                                _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                                _tainted_by = _src_tainted_operand.get_tainted_by()
                                _determined_roles = _src_tainted_operand.get_determined_roles()
                                _dst_tainted_operand.force_set_tainted_operand(
                                    _dst_operand.get_operand_type(),
                                    _dst_operand.get_operand_name(),
                                    _dst_operand.get_operand_value(),
                                    _dst_operand.get_memory_formula(),
                                    _tainted_by,
                                    _determined_roles,
                                )
                                _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                                if _vm_part is not None:
                                    _dst_tainted_operand.set_vm_part(_vm_part)
                                _tainted_operands_to_add.append(_dst_tainted_operand)
                            else:
                                _dst_tainted_operand = TmpTaintedOperandForX64DbgTrace(self.context, None)
                                _vm_part_name = self.get_vm_part_name_of_operand(_src_operand)
                                _tainted_by = [_vm_part_name]
                                _determined_roles = ['imm']
                                _dst_tainted_operand.force_set_tainted_operand(
                                    _dst_operand.get_operand_type(),
                                    _dst_operand.get_operand_name(),
                                    _dst_operand.get_operand_value(),
                                    _dst_operand.get_memory_formula(),
                                    _tainted_by,
                                    _determined_roles,
                                )
                                _vm_part = self.get_vm_part_name_of_operand(_dst_tainted_operand)
                                if _vm_part is not None:
                                    _dst_tainted_operand.set_vm_part(_vm_part)
                                _tainted_operands_to_add.append(_dst_tainted_operand)

        for _tainted_operand_to_remove in _tainted_operands_to_remove:
            if self.remove_tainted_operand_from_tainted_operands(_tainted_operand_to_remove):
                if show_log is True:
                    _strs_to_show_in_comment.append(_msg_on_del_operand(_tainted_operand_to_remove))
        for _tainted_operand_to_add in _tainted_operands_to_add:
            self.add_tainted_operand_to_tainted_operands(_tainted_operand_to_add)
            if show_log is True:
                _strs_to_show_in_comment.append(
                    _msg_on_add_operand(
                        _tainted_operand_to_add,
                        _tainted_operand_to_add.get_determined_roles(),
                        _tainted_operand_to_add.get_tainted_by()
                    )
                )

            # todo: should be moved to somewhere to identify VR begin
            _tainted_by = _tainted_operand_to_add.get_tainted_by()
            _vb_found = False
            _vbr_found = False
            for _tb in _tainted_by:
                if _tb.find('VB_') != -1:
                    _vb_found = True
                elif _tb.find('ebp') != -1:
                    _vbr_found = True
            if _vb_found and _vbr_found:
                _strs_to_show_in_comment.append('[LV2]')
            # todo: should be moved to somewhere to identify VR end

        return _dst_tainted_operands, _src_tainted_operands, ', '.join(_strs_to_show_in_comment)

    def check_vm_intro_and_outro(self) -> str:
        _str_to_show_in_comment: str = ''
        _you_are_in_vm: bool = self.get_you_are_in_vm()
        _ebp_value: int = self.context.get_register_value('ebp')
        _reg_vbr_value: int = self.get_reg_vbr_value()
        if _ebp_value == _reg_vbr_value:
            _str_to_show_in_comment = '[VM]'
            if _you_are_in_vm is False:
                # add EBP as VBR (Virtual machine Base Register) to tainted_operands
                self.add_tainted_operand_to_tainted_operands(self.reg_vbr)
                self.set_you_are_in_vm(True)
        else:
            if _you_are_in_vm is True:
                # remove VBR from tainted_operands
                self.remove_tainted_operand_from_tainted_operands(self.reg_vbr)
                self.set_you_are_in_vm(False)
        return _str_to_show_in_comment

    def retrieve_tainted_operand_with_role(
            self,
            tainted_operands: list[TmpTaintedOperandForX64DbgTrace],
            role_to_find: str,
    ) -> list[TmpTaintedOperandForX64DbgTrace]:
        _tainted_operands_with_role: list[TmpTaintedOperandForX64DbgTrace] = []
        for _operand in tainted_operands:
            if _operand.has_determined_role(role_to_find) is True:
                _tainted_operands_with_role.append(_operand)
        return _tainted_operands_with_role

    def retrieve_tainted_operand_from_memory_formula_with_role(
            self,
            operands: list[TmpOperandForX64DbgTrace],
            role_to_find: str,
    ) -> list[TmpTaintedOperandForX64DbgTrace]:
        _tainted_operands_with_role_from_memory_formula: list[TmpTaintedOperandForX64DbgTrace] = []
        _tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = self.get_tainted_operands()
        _tainted_operands_with_role = self.retrieve_tainted_operand_with_role(_tainted_operands, role_to_find)
        _register_names = self.context.get_register_names()
        for _operand in operands:
            if _operand.get_operand_type() != 'mem':
                continue
            _memory_formula = _operand.get_memory_formula()
            for _memory_var in _memory_formula:
                # in memory formula, only registers could have been tainted
                if _memory_var not in _register_names:
                    continue
                for _tainted_operand in _tainted_operands_with_role:
                    if _tainted_operand.get_operand_name() == _memory_var:
                        _tainted_operands_with_role_from_memory_formula.append(_tainted_operand)
        return _tainted_operands_with_role_from_memory_formula

    def has_operand_with_role_on_memory_formula(
            self,
            operand: TmpOperandForX64DbgTrace,
            role_to_find: str,
    ) -> bool:
        _tainted_operands: list[TmpTaintedOperandForX64DbgTrace] = self.get_tainted_operands()
        _tainted_operands_with_role = self.retrieve_tainted_operand_with_role(_tainted_operands, role_to_find)
        _register_names = self.context.get_register_names()
        if operand.get_operand_type() != 'mem':
            return False
        _memory_formula = operand.get_memory_formula()
        for _memory_var in _memory_formula:
            # in memory formula, only registers could have been tainted
            if _memory_var not in _register_names:
                continue
            # search memory variable from tainted_operands
            for _tainted_operand in _tainted_operands_with_role:
                if _tainted_operand.get_operand_name() != _memory_var:
                    continue
                if role_to_find in _tainted_operand.get_determined_roles():
                    return True
        return False

    def retrieve_operands_with_role_on_memory_formula(
            self,
            operands: list[TmpOperandForX64DbgTrace],
            role_to_find: str,
    ) -> list[TmpOperandForX64DbgTrace]:
        _operands_with_role_on_memory_formula: list[TmpOperandForX64DbgTrace] = []
        for _operand in operands:
            if self.has_operand_with_role_on_memory_formula(_operand, role_to_find) is True:
                _operands_with_role_on_memory_formula.append(_operand)
        return _operands_with_role_on_memory_formula

    def run_taint_single_line_by_x64dbg_trace(self, trace, show_log=False):
        self.context.set_context_by_x64dbg_trace(trace)
        _operands: list[TmpOperandForX64DbgTrace] = self.retrieve_operands_from_context()
        _dst_operands, _src_operands = self.retrieve_dst_and_src_operands(_operands)
        if _src_operands is None:
            self.api.print('%d : 0x%x : %s : %s' % (trace['id'], trace['ip'], trace['disasm'], str(_operands)))
            self.api.print(trace)
            self.api.print('[+] Operands : %s' + str([str(_operand) for _operand in _operands]))
            self.api.print('[+] Tainted : ' + str(self.tainted_operands))
            raise Exception('[E] Something goes wrong')
        elif len(_dst_operands) >= 2 or len(_src_operands) >= 2:
            self.api.print('%d : 0x%x : %s : %s' % (trace['id'], trace['ip'], trace['disasm'], str(_operands)))
            self.api.print(trace)
            self.api.print('[+] Operands : %s' + str([str(_operand) for _operand in _operands]))
            self.api.print('[+] Tainted : ' + str(self.tainted_operands))
            raise Exception('[E] Too many operands are found\n- dst : %s\n- src : %s' % (
                str([str(_operand) for _operand in _dst_operands]),
                str([str(_operand) for _operand in _src_operands])),
            )

        _str_you_are_in_vm: str = self.check_vm_intro_and_outro()
        _dst_tainted_operands, _src_tainted_operands, _str_taint_trace \
            = self.run_taint_with_dst_and_src_operands(
                _dst_operands,
                _src_operands,
                show_log=show_log,
            )

        def _print_operands(
                operands: list[TmpOperandForX64DbgTrace],
                tainted_operands: list[TmpTaintedOperandForX64DbgTrace],
        ) -> str:
            _strs_to_print = []
            if len(tainted_operands) > 0:
                return _print_tainted_operands(tainted_operands)
            for _operand in operands:
                _strs_to_print.append(_operand.get_operand_name())
            return ', '.join(_strs_to_print)

        def _print_tainted_operands(
                tainted_operands: list[TmpTaintedOperandForX64DbgTrace],
        ) -> str:
            _strs_to_print = []
            for _operand in tainted_operands:
                _len_determined_roles = len(_operand.get_determined_roles())
                _vm_part = _operand.get_vm_part()
                if _len_determined_roles > 0:
                    if _vm_part != '':
                        _strs_to_print.append(
                            '%s:%s (%s) from %s'
                            % (
                                _vm_part,
                                _operand.get_operand_name(),
                                _operand.get_determined_roles(),
                                _operand.get_tainted_by()
                            )
                        )
                    else:
                        _strs_to_print.append(
                            '%s (%s) from %s'
                            % (_operand.get_operand_name(), _operand.get_determined_roles(), _operand.get_tainted_by())
                        )
                    continue
                if _vm_part != '':
                    _strs_to_print.append(
                        '%s:%s from %s'
                        % (_vm_part, _operand.get_operand_name(), _operand.get_tainted_by())
                    )
                    continue
                _strs_to_print.append(
                    '%s from %s'
                    % (_operand.get_operand_name(), _operand.get_tainted_by())
                )
            return ', '.join(_strs_to_print)

        def _print_memory_access() -> str:
            _strs_to_print = []
            _memory_accesses = self.context.x64dbg_trace['mem']
            for _memory_access in _memory_accesses:
                # 'mem': [{'access': 'WRITE', 'addr': 20472, 'value': 2852906762}],
                if _memory_access['access'] == 'WRITE':
                    _access = 'W'
                else:
                    _access = 'R'
                _strs_to_print.append('%s:[0x%08x] = 0x%x' % (_access, _memory_access['addr'], _memory_access['value']))
            return ', '.join(_strs_to_print)

        if show_log is True:
            _strs_to_show_in_comment = []
            _str_dst_operands = ''
            _str_src_operands = ''
            if _str_you_are_in_vm != '':
                _strs_to_show_in_comment.append(_str_you_are_in_vm)
            _str_memory_access = _print_memory_access()
            if _str_memory_access != '':
                _strs_to_show_in_comment.append(_str_memory_access)
            if _str_taint_trace != '':
                _strs_to_show_in_comment.append(_str_taint_trace)
            if len(_dst_operands) > 0 or len(_dst_tainted_operands) > 0:
                _str_dst_operands = _print_operands(_dst_operands, _dst_tainted_operands)
                _strs_to_show_in_comment.append('DST: %s' % _str_dst_operands)
            if len(_dst_operands) > 0 or len(_dst_tainted_operands) > 0:
                _str_src_operands = _print_operands(_src_operands, _src_tainted_operands)
                _strs_to_show_in_comment.append('SRC: %s' % _str_src_operands)
            # if len(self.tainted_operands) > 0:  # todo: muted
            #     _strs_to_show_in_comment.append('TAINTED: %s' % _print_tainted_operands(self.tainted_operands))
            if (_str_dst_operands.find('VB') != -1) or (_str_dst_operands.find('vbr') != -1)\
                    or (_str_src_operands.find('VB') != -1) or (_str_src_operands.find('vbr') != -1) \
                    or (_str_taint_trace.find('VB') != -1) or (_str_taint_trace.find('vbr') != -1):
                _strs_to_show_in_comment.append('[T]')
            trace['comment'] = ' | '.join(_strs_to_show_in_comment)

        return trace
