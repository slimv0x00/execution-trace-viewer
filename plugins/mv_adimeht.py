import capstone
import traceback

from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.TraceContext import *
from plugins.TraceTaint import *
from plugins.TraceInstruction import *
from plugins.TraceAdimeht import *


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None

    ARCH_MODE = 32

    show_operands = False
    show_taint_changes = False

    show_you_are_in_vm = True
    show_virtual_instruction = True

    def set_preset1(self, taint_analyzer):
        taint_analyzer.add_taint_register("eax", "host_eax")
        taint_analyzer.add_taint_register("ebx", "host_ebx")
        taint_analyzer.add_taint_register("ecx", "host_ecx")
        taint_analyzer.add_taint_register("edx", "host_edx")
        taint_analyzer.add_taint_register("esi", "host_esi")
        taint_analyzer.add_taint_register("edi", "host_edi")
        taint_analyzer.add_taint_register("ebp", "host_ebp")
        taint_analyzer.add_taint_memory(0xd3f9f4, 4, var_name="arg_1")
        taint_analyzer.add_taint_memory(0xd3f9f8, 4, var_name="arg_2")

    @staticmethod
    def _setup_change_hooks(ctx, enabled):
        """Register change detection hooks on the context.

        Returns (newly_tainted, cleansed) lists that are populated
        during instruction execution via the hooks.
        """
        newly_tainted = []
        cleansed = []

        def on_change_detected(target, old_sym, new_sym):
            was_tainted = old_sym is not None and not z3.is_bv_value(old_sym)
            is_tainted_now = new_sym is not None and not z3.is_bv_value(new_sym)

            if isinstance(target, int):
                name = f"[{hex(target)}]"
            else:
                name = str(target)

            if not was_tainted and is_tainted_now:
                newly_tainted.append(name)
            elif was_tainted and not is_tainted_now:
                cleansed.append(name)
            elif was_tainted and is_tainted_now:
                if str(old_sym) != str(new_sym):
                    cleansed.append(name)
                    newly_tainted.append(name)

        if enabled:
            ctx.hook_reg_write = on_change_detected
            ctx.hook_memory_write = on_change_detected
        else:
            ctx.hook_reg_write = None
            ctx.hook_memory_write = None

        return newly_tainted, cleansed

    @staticmethod
    def _collect_change_message(ctx, newly_tainted, cleansed):
        """Unhook and build a change summary message.

        Returns the formatted message string, or empty string if no changes.
        """
        ctx.hook_reg_write = None
        ctx.hook_memory_write = None

        msgs = []
        if cleansed:
            msgs.append(f"[-] {', '.join(cleansed)}")
        if newly_tainted:
            msgs.append(f"[+] {', '.join(newly_tainted)}")

        return " | ".join(msgs)

    @staticmethod
    def _build_virtual_instruction(inst, adimeht):
        """Build a virtual instruction string using VB/VR/VL labels.

        For each explicit MEM operand, resolves its concrete address and
        looks it up in adimeht.vm_elements to replace with a label like
        VB_1_0x1c, VR_2_0x3c, etc.

        Returns the virtual instruction string, or empty string if no
        operand qualifies.
        """
        op_strs = [p.strip() for p in inst.op_str.split(',')] if inst.op_str else []
        explicit_ops = [op for op in inst.operands if not op.is_implicit]

        has_virtual_operand = False
        result_parts = []

        for i, op in enumerate(explicit_ops):
            original = op_strs[i] if i < len(op_strs) else '?'

            if op.type == OperandType.MEM:
                addr_c, _ = op.resolve_addr(adimeht.ctx, inst.ip)
                elem = adimeht.get_element_at(addr_c)
                if elem is not None:
                    role, depth, offset = elem
                    label = f"{role}_{depth}_{hex(offset)}"
                    has_virtual_operand = True
                    result_parts.append(label)
                    continue

            result_parts.append(original)

        if has_virtual_operand:
            return f"{inst.mnemonic.lower()} {', '.join(result_parts)}"
        return ''

    def execute(self, api: Api):
        self.api = api
        ARCH_MODE = 32

        # Capstone 초기화 (상세 모드 필수)
        if ARCH_MODE == 64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True  # 오퍼랜드 상세 분석을 위해 필수
        ctx_taint = TraceContext(arch_mode=ARCH_MODE)
        taint_analyzer = TraceTaint(ctx_taint)
        ctx_adimeht = TraceContext(arch_mode=ARCH_MODE)
        adimeht_analyzer = TraceAdimeht(ctx_adimeht)
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
            self.set_preset1(taint_analyzer)
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

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Address boundary to trace : 0x%08x ~ 0x%08x'
                       % (_address_boundary_to_trace_begin, _address_boundary_to_trace_end))
        self.api.print(' - Initial target to trace : %s at %d' % (_target_operand, _target_index))

        _x64dbg_traces = self.api.get_full_trace()
        _traces_to_show = []

        for _x64dbg_trace in _x64dbg_traces:
            try:
                # _x64dbg_trace
                # {
                #   'id': 0,
                #   'ip': 4242012,
                #   'disasm': 'push 0xaa0be70a',
                #   'comment': 'push encrypted vm_eip',
                #   'regs': [3806, 309, 326, 292, 0, 20476, 360, 377, 4242012, 0],
                #   'opcodes': '680ae70baa',
                #   'mem': [{'access': 'WRITE', 'addr': 20472, 'value': 2852906762}],
                #   'regchanges': 'ebp: 0x4ff8 '
                #   'taints': tainted_operands,
                # }
                _index = _x64dbg_trace['id']
                if _ttl >= 0:
                    if _index > _ttl:
                        break
                _eip = _x64dbg_trace['ip']
                # skip tracing when EIP is outside the boundary to trace
                if _eip < _address_boundary_to_trace_begin or _eip >= _address_boundary_to_trace_end:
                    continue

                # =========================================================================
                # [구현 부분] 1. Context 동기화 & 2. Operand 생성
                # =========================================================================

                # 1. Context 동기화 (레지스터 값 업데이트 + 메모리 READ 값 미리 주입)
                ctx_taint.load_register_state(_x64dbg_trace)
                ctx_adimeht.load_register_state(_x64dbg_trace)

                # =========================================================================
                # [Refactored] 2. 명령어 객체 생성 (Instruction Parsing)
                # =========================================================================
                inst = TraceInstruction(_x64dbg_trace, md)

                trace_operands = inst.get_operands()
                if self.show_operands:
                    operand_msg = ', '.join([str(_) for _ in trace_operands])
                    _x64dbg_trace['comment'] = operand_msg

                # trace 딕셔너리에 파싱된 정보 저장
                _x64dbg_trace['parsed_operands'] = trace_operands
                _x64dbg_trace['instruction_obj'] = inst

                # =========================================================================
                # [Step 2] Taint 분석 및 변화 감지 (Hook 방식)
                # =========================================================================
                newly_tainted, cleansed = self._setup_change_hooks(ctx_taint, self.show_taint_changes)
                proceed = taint_analyzer.process_instruction(_x64dbg_trace)
                taint_msg = self._collect_change_message(ctx_taint, newly_tainted, cleansed)
                if proceed is False:
                    break

                # =========================================================================
                # [Step 3] Adimeht 분석 (lightweight, no Z3 hooks)
                # =========================================================================
                if _vbr is not None:
                    current_ebp, _, _ = ctx_adimeht.get_register('ebp')
                    if current_ebp == _vbr:
                        if not adimeht_analyzer.is_vbr_initialized:
                            adimeht_analyzer.init_vbr()
                    else:
                        if adimeht_analyzer.is_vbr_initialized:
                            adimeht_analyzer.clear_vbr()

                adimeht_analyzer.process_instruction(_x64dbg_trace)

                virtual_inst_msg = ''
                if self.show_virtual_instruction:
                    virtual_inst_msg = self._build_virtual_instruction(inst, adimeht_analyzer)

                # =========================================================================
                # [Step 4] 코멘트 업데이트
                # =========================================================================
                for msg in (taint_msg, virtual_inst_msg):
                    if msg:
                        if 'comment' in _x64dbg_trace and _x64dbg_trace['comment']:
                            _x64dbg_trace['comment'] += f" | {msg}"
                        else:
                            _x64dbg_trace['comment'] = msg

                if self.show_you_are_in_vm and adimeht_analyzer.is_vbr_initialized:
                    comment = _x64dbg_trace.get('comment', '')
                    _x64dbg_trace['comment'] = f"[VM] {comment}" if comment else "[VM]"

                # -------------------------------------------------------------------------
                # [Step 5] 전체 Taint 상태 스냅샷 저장
                # -------------------------------------------------------------------------
                _x64dbg_trace['taints'] = ctx_taint.get_symbolic_state_snapshot()
                _x64dbg_trace['adimehts'] = adimeht_analyzer.get_vm_elements_snapshot()

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
