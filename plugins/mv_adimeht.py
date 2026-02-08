import capstone
import traceback

from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.TraceContext import *
from plugins.TraceTaint import *
from plugins.TraceInstruction import *


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None

    ARCH_MODE = 32

    show_operands = True
    show_taint_changes = True

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

    def execute(self, api: Api):
        self.api = api
        ARCH_MODE = 32

        # Capstone 초기화 (상세 모드 필수)
        if ARCH_MODE == 64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True  # 오퍼랜드 상세 분석을 위해 필수
        ctx = TraceContext(arch_mode=ARCH_MODE)
        taint_analyzer = TraceTaint(ctx)
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
                ctx.load_register_state(_x64dbg_trace)

                # =========================================================================
                # [Refactored] 2. 명령어 객체 생성 (Instruction Parsing)
                # =========================================================================
                # 복잡한 디스어셈블리/오퍼랜드 생성 로직이 이 한 줄로 캡슐화됨
                inst = TraceInstruction(_x64dbg_trace, md)

                trace_operands = inst.get_operands()
                if self.show_operands:
                    operand_msg = ', '.join([str(_) for _ in trace_operands])
                    _x64dbg_trace['comment'] = operand_msg

                # trace 딕셔너리에 파싱된 정보 저장 (선택 사항)
                _x64dbg_trace['parsed_operands'] = trace_operands
                _x64dbg_trace['instruction_obj'] = inst  # <--- 객체 자체를 저장

                # =========================================================================
                # [Step 2] Taint 분석 및 변화 감지 (Hook 방식)
                # =========================================================================
                newly_tainted_msgs = []
                cleansed_msgs = []

                # 1. 훅(Callback) 함수 정의
                def on_change_detected(target, old_sym, new_sym):
                    """
                    target: 레지스터 이름(str) 또는 메모리 주소(int)
                    old_sym: 변경 전 수식
                    new_sym: 변경 후 수식
                    """
                    # Taint 여부 판단
                    was_tainted = old_sym is not None and not z3.is_bv_value(old_sym)
                    is_tainted_now = new_sym is not None and not z3.is_bv_value(new_sym)

                    # 출력 이름 포맷팅
                    if isinstance(target, int):
                        name = f"[{hex(target)}]"
                    else:
                        name = str(target)

                    # 변화 감지 로직
                    if not was_tainted and is_tainted_now:
                        # Case 1: Untainted -> Tainted (New)
                        newly_tainted_msgs.append(f"{name}")  # 필요시 : {new_sym} 추가

                    elif was_tainted and not is_tainted_now:
                        # Case 2: Tainted -> Untainted (Clean)
                        cleansed_msgs.append(f"{name}")

                    elif was_tainted and is_tainted_now:
                        # Case 3: Tainted -> Tainted (Changed)
                        if str(old_sym) != str(new_sym):
                            cleansed_msgs.append(f"{name}")
                            newly_tainted_msgs.append(f"{name}")

                # 2. Context에 훅 등록 (플래그 확인)
                if self.show_taint_changes:
                    ctx.hook_reg_write = on_change_detected
                    ctx.hook_memory_write = on_change_detected
                else:
                    ctx.hook_reg_write = None
                    ctx.hook_memory_write = None

                # 3. 명령어 실행 (Execution)
                # 이제 내부에서 set_memory/register가 호출될 때마다 자동으로 on_change_detected가 실행됨
                proceed = taint_analyzer.process_instruction(_x64dbg_trace)

                # 4. 훅 해제 (안전을 위해)
                ctx.hook_reg_write = None
                ctx.hook_memory_write = None

                if proceed is False:
                    break

                # =========================================================================
                # [Step 3] 코멘트 업데이트
                # =========================================================================
                msgs = []
                if cleansed_msgs:
                    msgs.append(f"[-] {', '.join(cleansed_msgs)}")
                if newly_tainted_msgs:
                    msgs.append(f"[+] {', '.join(newly_tainted_msgs)}")

                if msgs:
                    taint_msg = " | ".join(msgs)
                    if 'comment' in _x64dbg_trace and _x64dbg_trace['comment']:
                        _x64dbg_trace['comment'] += f" | {taint_msg}"
                    else:
                        _x64dbg_trace['comment'] = taint_msg

                # -------------------------------------------------------------------------
                # [Step 4] 전체 Taint 상태 스냅샷 저장
                # -------------------------------------------------------------------------
                _x64dbg_trace['taints'] = ctx.get_symbolic_state_snapshot()

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
