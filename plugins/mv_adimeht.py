import capstone
import datetime
import traceback

from yapsy.IPlugin import IPlugin
from core.api import Api
from plugins.TraceContext import *
from plugins.TraceTaint import *
from plugins.TraceInstruction import *
from plugins.TraceAdimehtFISH import TraceAdimehtFISH
from plugins.TraceAdimehtLightFISH import TraceAdimehtLightFISH


class PluginMvAdimeht(IPlugin):
    # core.Api
    api = None

    ARCH_MODE = 32

    show_operands = False
    show_taint_changes = False

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

    def set_preset5(self, taint_analyzer):
        taint_analyzer.add_taint_register("eax", "host_eax")
        taint_analyzer.add_taint_register("ebx", "host_ebx")
        taint_analyzer.add_taint_register("ecx", "host_ecx")
        taint_analyzer.add_taint_register("edx", "host_edx")
        taint_analyzer.add_taint_register("esi", "host_esi")
        taint_analyzer.add_taint_register("edi", "host_edi")
        taint_analyzer.add_taint_register("ebp", "host_ebp")
        taint_analyzer.add_taint_memory(0x19ff14, 4, var_name="arg_1")
        taint_analyzer.add_taint_memory(0x19ff18, 4, var_name="arg_2")

    @staticmethod
    def _setup_change_hooks(ctx, enabled):
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
        ctx.hook_reg_write = None
        ctx.hook_memory_write = None

        msgs = []
        if cleansed:
            msgs.append(f"[-] {', '.join(cleansed)}")
        if newly_tainted:
            msgs.append(f"[+] {', '.join(newly_tainted)}")

        return " | ".join(msgs)

    @staticmethod
    def _parse_instruction(trace, md):
        inst = TraceInstruction(trace, md)
        trace_operands = inst.get_operands()
        trace['parsed_operands'] = trace_operands
        trace['instruction_obj'] = inst
        return inst

    def _run_taint_analysis(self, ctx_taint, taint_analyzer, trace):
        newly_tainted, cleansed = self._setup_change_hooks(ctx_taint, self.show_taint_changes)
        proceed = taint_analyzer.process_instruction(trace)
        taint_msg = self._collect_change_message(ctx_taint, newly_tainted, cleansed)
        return proceed, taint_msg

    @staticmethod
    def _update_comment(trace, taint_msg):
        if taint_msg:
            if trace.get('comment'):
                trace['comment'] += f" | {taint_msg}"
            else:
                trace['comment'] = taint_msg

    @staticmethod
    def _save_snapshots(ctx_taint, adimeht_analyzer, trace):
        _by_name = lambda lst: sorted(lst, key=lambda item: item.get('name', ''))
        trace['taints']   = _by_name(ctx_taint.get_symbolic_state_snapshot())
        trace['adimehts'] = _by_name(adimeht_analyzer.get_snapshot())

    # =========================================================================
    # Plugin entry point
    # =========================================================================

    def execute(self, api: Api):
        _start_time = datetime.datetime.now()
        print(f'[*] Start: {_start_time.strftime("%H:%M:%S.%f")}')
        self.api = api
        ARCH_MODE = 32

        if ARCH_MODE == 64:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        else:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        md.detail = True
        ctx_taint = TraceContext(arch_mode=ARCH_MODE)

        _preset_id = 5
        _input_dlg_data = [
            {'label': 'Trace boundary begin', 'data': '0x0'},
            {'label': 'Trace boundary end', 'data': '0x70000000'},
            {'label': 'Target index(#)', 'data': 0},
            {'label': 'Target operand (reg or preset)', 'data': 'preset%d' % _preset_id},
            {'label': 'Target desc (when it\'s reg)', 'data': 'preset%d' % _preset_id},
            {'label': 'Preset', 'data': 'preset%d' % _preset_id},
            {'label': 'TTL (no limit, -1)', 'data': -1},
            {'label': 'Lightweight mode (y/n)', 'data': 'y'},
        ]
        _options = self.api.get_values_from_user("Filter by memory address", _input_dlg_data)
        if not _options:
            return
        _str_address_boundary_to_trace_begin,\
            _str_address_boundary_to_trace_end,\
            _target_index,\
            _target_operand,\
            _target_description,\
            _str_preset, \
            _ttl,\
            _str_lightweight = _options
        _lightweight = str(_str_lightweight).strip().lower() == 'y'
        _taint_enabled = not _lightweight  # lightweight 모드에서 taint를 복구하려면 True로 변경
        _address_boundary_to_trace_begin = int(_str_address_boundary_to_trace_begin, 16)
        _address_boundary_to_trace_end = int(_str_address_boundary_to_trace_end, 16)
        print(f'[*] TTL : {_ttl} ({"no limit" if _ttl < 0 else f"stop at index {_ttl}"})')

        _x64dbg_traces = self.api.get_full_trace()

        ctx_adimeht = TraceContext(arch_mode=ARCH_MODE)
        ctx_adimeht.cap_enabled = True
        if _lightweight:
            adimeht_analyzer = TraceAdimehtLightFISH(ctx_adimeht, _x64dbg_traces, ctx_taint=ctx_taint)
            _by_name = lambda lst: sorted(lst, key=lambda item: item.get('name', ''))
            _taint_esp_snapshot = _by_name(adimeht_analyzer.get_taint_esp_snapshot())
        else:
            adimeht_analyzer = TraceAdimehtFISH(ctx_adimeht, _x64dbg_traces, ctx_taint=ctx_taint)
            _taint_esp_snapshot = None
        taint_analyzer = TraceTaint(ctx_taint)

        if _str_preset == 'preset1':
            self.set_preset1(taint_analyzer)
        elif _str_preset == 'preset5':
            self.set_preset5(taint_analyzer)

        self.api.print('[+] Run taint analysis')
        self.api.print(' - Address boundary to trace : 0x%08x ~ 0x%08x'
                       % (_address_boundary_to_trace_begin, _address_boundary_to_trace_end))
        self.api.print(' - Initial target to trace : %s at %d' % (_target_operand, _target_index))
        self.api.print(f' - TTL : {_ttl} ({"no limit" if _ttl < 0 else f"stop at index {_ttl}"})')

        _traces_to_show = []
        _progress_total = _ttl if _ttl >= 0 else len(_x64dbg_traces)
        _progress_step = max(1, _progress_total // 100)

        for _x64dbg_trace in _x64dbg_traces:
            try:
                _index = _x64dbg_trace['id']
                if _ttl >= 0:
                    if _index > _ttl:
                        break
                if _progress_total > 0 and _index % _progress_step == 0:
                    _pct = min(_index / _progress_total * 100, 100.0)
                    print(f'\r[*] Progress: {_pct:5.1f}%  ({_index} / {_progress_total})', end='', flush=True)
                _eip = _x64dbg_trace['ip']
                if _eip < _address_boundary_to_trace_begin or _eip >= _address_boundary_to_trace_end:
                    continue

                # Step 1: context sync
                ctx_taint.load_register_state(_x64dbg_trace)
                if not _lightweight:
                    ctx_adimeht.cap_occurred = False
                    ctx_adimeht.load_register_state(_x64dbg_trace)

                # Step 1.5: [VM] prefix — set before any other comment so it is always first
                _regs = _x64dbg_trace.get('regs')
                if hasattr(adimeht_analyzer, 'is_trace_in_vm'):
                    _is_in_vm = adimeht_analyzer.is_trace_in_vm(_x64dbg_trace)
                else:
                    _is_in_vm = (adimeht_analyzer.vbr is not None
                                 and _regs and len(_regs) > 5
                                 and _regs[5] == adimeht_analyzer.vbr)
                if not _lightweight:
                    if _is_in_vm and not adimeht_analyzer.is_in_vm:
                        adimeht_analyzer.enter_vm()
                    elif not _is_in_vm and adimeht_analyzer.is_in_vm:
                        adimeht_analyzer.exit_vm()
                if _is_in_vm:
                    _x64dbg_trace['comment'] = '[VM]'

                # Step 2: instruction parsing
                self._parse_instruction(_x64dbg_trace, md)

                # Step 3: taint analysis
                taint_msg = ''
                if _taint_enabled:
                    proceed, taint_msg = self._run_taint_analysis(ctx_taint, taint_analyzer, _x64dbg_trace)
                    if proceed is False:
                        break

                # Step 3.5: adimehts — VBR propagation tracking (independent of taint)
                adimeht_analyzer.process_instruction(_x64dbg_trace)
                internal_events = None
                if not _lightweight:
                    internal_events = adimeht_analyzer.get_internal_events(_x64dbg_trace)

                # Step 4: comment update
                self._update_comment(_x64dbg_trace, taint_msg)
                if not _lightweight and adimeht_analyzer.last_vmi_str:
                    self._update_comment(_x64dbg_trace, adimeht_analyzer.last_vmi_str)
                if internal_events:
                    self._update_comment(_x64dbg_trace, internal_events)

                # Step 4.5: cap annotation
                if not _lightweight and ctx_adimeht.cap_occurred:
                    self._update_comment(_x64dbg_trace, '[exp capped]')

                # Step 5: state snapshots
                if _taint_enabled:
                    self._save_snapshots(ctx_taint, adimeht_analyzer, _x64dbg_trace)
                else:
                    _x64dbg_trace['taints']   = []
                    _x64dbg_trace['adimehts'] = adimeht_analyzer.get_snapshot()
                if _taint_esp_snapshot is not None:
                    _x64dbg_trace['taints_esp'] = _taint_esp_snapshot

                _traces_to_show.append(_x64dbg_trace)
            except Exception as e:
                _traces_to_show.append(_x64dbg_trace.copy())
                print(traceback.format_exc())
                print(e)
                print(_x64dbg_trace)
                break

        print()  # end the progress line
        if len(_traces_to_show) > 0:
            if _lightweight and hasattr(adimeht_analyzer, 'annotate_vi_candidates'):
                cand_count, vi_count = adimeht_analyzer.annotate_vi_candidates(_x64dbg_traces)
                self.api.print(f' - VI candidates annotated : {cand_count}')
                self.api.print(f' - Final arithmetic VI annotated : {vi_count}')
                vi_stats = getattr(adimeht_analyzer, 'last_vi_annotation_stats', {}) or {}
                if vi_stats:
                    real_vi_count = vi_stats.get('real_vi', 0)
                    seed_count = vi_stats.get('semantic_seeds', 0)
                    addr_decode_count = vi_stats.get('address_decode', 0)
                    endpoints = ','.join(hex(v) for v in vi_stats.get('endpoint_addrs', []))
                    self.api.print(f' - Known real VI annotated : {real_vi_count}')
                    self.api.print(f' - Final VI seeds/address-decode : {seed_count}/{addr_decode_count}')
                    self.api.print(f' - Final VI endpoint addrs : {endpoints}')
                    black_filter = vi_stats.get('black_real_vi_filter')
                    if black_filter:
                        categories = black_filter.get('categories', {}) or {}
                        category_summary = ', '.join(
                            f'{name}:{count}' for name, count in sorted(categories.items())
                        )
                        self.api.print(
                            ' - Black real VI filter : '
                            f"selected={black_filter.get('selected', 0)} "
                            f"range={black_filter.get('semantic_start')}..{black_filter.get('semantic_end')} "
                            f"base={hex(black_filter.get('frame_base', 0))}"
                        )
                        roles = black_filter.get('roles', {}) or {}
                        if roles:
                            role_summary = ', '.join(f'{name}={label}' for name, label in sorted(roles.items()))
                            self.api.print(f' - Black real VI roles : {role_summary}')
                        self.api.print(f' - Black real VI categories : {category_summary}')
                    issue_marks = vi_stats.get('issue_marks', {}) or {}
                    if issue_marks:
                        issue_summary = ', '.join(f'{mark}:{count}' for mark, count in sorted(issue_marks.items()))
                        self.api.print(f' - Final VI issue markers : {issue_summary}')

            _end_time = datetime.datetime.now()
            _elapsed = (_end_time - _start_time).total_seconds()
            print(f'[*] End:   {_end_time.strftime("%H:%M:%S.%f")} (elapsed: {_elapsed:.2f}s)')
            print('Length of filtered trace: %d' % len(_traces_to_show))
            self.api.set_filtered_trace(_traces_to_show)
            self.api.show_filtered_trace()
