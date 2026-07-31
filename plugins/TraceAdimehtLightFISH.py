import collections
import importlib
import sys
from pathlib import Path

import z3

from .TraceTaint import TraceTaint
from .TraceOperand import OperandType, OperandAccess

_EBP_IDX          = 5
_VBR_SLOT_RANGE   = 0x200
_VPC_LOOKAHEAD    = 20
_VPC_OFFSET_SLACK = 16
_VPC_FALLBACK_CONFIGS = ((20, 16), (1000, 0x100))
_VPC_MIN_READS    = 3
_VPC_MIN_SCORE    = 0.5
_VHTP_MAX_WRITES    = 3
_VMOP_MIN_WRITES    = 3
_VMOP_MIN_RPW       = 5.0
_VMOP_MAX_PTR_RATIO = 0.1
_BLACK_PRESCAN_ROW_THRESHOLD = 2_000_000
_EFLAGS_IDX         = 9
_REG_INDEX_32       = {
    'EAX': 0, 'ECX': 1, 'EDX': 2, 'EBX': 3,
    'ESP': 4, 'EBP': 5, 'ESI': 6, 'EDI': 7,
    'EIP': 8, 'EFLAGS': 9,
}
_REG_SLICE_32       = {
    'EAX': ('EAX', 0, 32), 'AX': ('EAX', 0, 16), 'AL': ('EAX', 0, 8), 'AH': ('EAX', 8, 8),
    'EBX': ('EBX', 0, 32), 'BX': ('EBX', 0, 16), 'BL': ('EBX', 0, 8), 'BH': ('EBX', 8, 8),
    'ECX': ('ECX', 0, 32), 'CX': ('ECX', 0, 16), 'CL': ('ECX', 0, 8), 'CH': ('ECX', 8, 8),
    'EDX': ('EDX', 0, 32), 'DX': ('EDX', 0, 16), 'DL': ('EDX', 0, 8), 'DH': ('EDX', 8, 8),
    'ESI': ('ESI', 0, 32), 'SI': ('ESI', 0, 16),
    'EDI': ('EDI', 0, 32), 'DI': ('EDI', 0, 16),
    'ESP': ('ESP', 0, 32), 'SP': ('ESP', 0, 16),
    'EBP': ('EBP', 0, 32), 'BP': ('EBP', 0, 16),
}

_JCC_MNEMONICS = frozenset({
    'JE', 'JNE', 'JZ', 'JNZ', 'JA', 'JAE', 'JB', 'JBE',
    'JC', 'JNC', 'JG', 'JGE', 'JL', 'JLE',
    'JS', 'JNS', 'JO', 'JNO', 'JP', 'JNP', 'JPE', 'JPO',
})
_FLAG_MNEMONICS = frozenset({
    'CMP', 'TEST', 'ADD', 'SUB', 'XOR', 'OR', 'AND',
    'ADC', 'SBB', 'NEG', 'INC', 'DEC',
    'SHL', 'SHR', 'SAR', 'ROL', 'ROR',
    'MUL', 'IMUL', 'XADD', 'CMPXCHG',
})
_VI_DIAGNOSTIC_MARKERS = frozenset({
    '[canditates]',
    '[vi]',
    '[real-vi]',
    '[fish-real-core]',
    '[fish-result-materialization]',
    '[fish-native-exit]',
    '[fish-stack-carrier]',
    '[fish-frame-vmblob]',
    '[fish-unaligned-frame]',
    '[fish-vbp]',
    '[fish-vsp]',
    '[fish-arg-read]',
    '[fish-missed-arg-read]',
    '[fish-arg-to-stack]',
})

# 32-bit 하위 레지스터 → 루트 이름 매핑
_REG_ALIAS_TO_ROOT = {
    'al': 'eax', 'ah': 'eax', 'ax': 'eax',
    'bl': 'ebx', 'bh': 'ebx', 'bx': 'ebx',
    'cl': 'ecx', 'ch': 'ecx', 'cx': 'ecx',
    'dl': 'edx', 'dh': 'edx', 'dx': 'edx',
    'sil': 'esi', 'si': 'esi',
    'dil': 'edi', 'di': 'edi',
    'bpl': 'ebp', 'bp': 'ebp',
    'spl': 'esp', 'sp': 'esp',
}

def _root_reg(name: str) -> str:
    """레지스터 이름을 32-bit 루트 이름(대문자)으로 정규화한다."""
    lower = name.lower()
    return _REG_ALIAS_TO_ROOT.get(lower, lower).upper()


class TraceAdimehtLightFISH(TraceTaint):
    """set 기반으로 VMBLOB 전파를 추적하는 경량 FISH VM 분석기.

    초기화 시 세 단계의 pre-pass를 순서대로 실행한다:
      1. _detect_vbr          — EBP 최빈값으로 VBR 탐지
      2. _detect_vpc_and_vhtp — 포인터 역참조 비율로 VPC, 안정 슬롯으로 VHTP 탐지
      3. _prepass_vb_slots    — EBP==VBR 구간의 모든 VBR+offset 접근을 VB 슬롯으로 기록

    _adimehts: dict[str, set[str]]
        symbol(레지스터명·VB 레이블) → 해당 값에 기여한 심볼 레이블 집합
        예) 'ESI' → {'VHTP_0xe', 'VMBLOB_0x7b30c2'}
    """

    def __init__(self, ctx, traces: list, ctx_taint=None):
        super().__init__(ctx)
        self.traces    = traces
        self.ctx_taint = ctx_taint

        self.vbr:       int | None = None
        self.vpc_slot: int | None = None
        self.vhtp_slot:  int | None = None
        self.vmop_slot: int | None = None
        self.vhtp_value: int | None = None  # VHTP 슬롯의 실제 값
        self.vpc_lookahead: int = _VPC_LOOKAHEAD
        self.vpc_offset_slack: int = _VPC_OFFSET_SLACK
        self.stack_temp_tracking_enabled: bool = False
        self.vm_intervals: list[tuple[int, int]] = []
        self.vm_tracking_intervals: list[tuple[int, int]] = []

        # concrete_addr → 'VB_0x{offset:x}'  (pre-pass 결과)
        self.vb_addr_map: dict[int, str] = {}

        # 메인 패스 상태
        self._pending_vpc: int | None = None       # 마지막으로 읽힌 VPC 슬롯 값 (WRITE 직전 old value)
        self._current_vpc: int | None = None       # MOV로 설정된 기준 VPC (ARITH delta의 base)
        self._was_in_vm:   bool = False             # 직전 행의 VM 내부 여부
        self._adimehts:    dict[str, set[str]] = {} # symbol → 기여 레이블 집합
        self._element_sources: dict[str, set[str]] = {} # symbol → 값을 공급한 VM element 레이블 집합
        self._fetch_traces: dict[str, dict] = {}    # VMBLOB label → fetch한 행의 trace dict
        self._fetch_history: dict[str, list[dict]] = {} # VM 내부에서 관찰된 VMBLOB fetch row들
        self._stack_addr_labels: dict[int, set[str]] = {} # host stack temp addr → provenance labels
        self._stack_addr_elements: dict[int, set[str]] = {} # host stack temp addr → VM element labels
        self._vmblob_role_labels: set[str] = set()  # 구조적 역할로 소비된 VMBLOB label
        self._vmblob_data_labels: set[str] = set()  # 일반 VB 슬롯에 한 번이라도 저장된 VMBLOB label
        self._vmblob_relay_fetch_ids: set[int] = set()  # relay comment를 이미 받은 fetch trace id
        self._dead_vmblob_labels: set[str] = set()  # 역할 없이 overwrite로 사라진 VMBLOB label
        self._vch_sources:  dict[str, set[str]] = {} # VCH label → 기여한 VMBLOB label 집합
        self._vch_addr_map: dict[int, str] = {}      # VCH table entry addr → VCH label
        self._vmop_cycle_value: int | None = None
        self._vmop_sources: set[str] = set()
        self._pending_decode_vmop: int | None = None
        self._pending_branch_sources: set[str] = set()
        self._pending_branch_elements: set[str] = set()
        self.last_vi_annotation_stats: dict[str, object] = {}

        self._detect_vbr()
        self._detect_vpc_and_vhtp()
        self._prepass_vb_slots()
        self._relabel_special_slots()
        self._detect_vm_intervals()

    # =========================================================================
    # Pre-pass 1 — VBR 탐지
    # =========================================================================

    def _detect_vbr(self) -> None:
        """전체 trace에서 EBP 최빈값을 VBR로 결정한다."""
        counter = collections.Counter()
        for t in self.traces:
            regs = t.get('regs')
            if regs and len(regs) > _EBP_IDX:
                counter[regs[_EBP_IDX]] += 1
        if not counter:
            print('[LightFISH] VBR detection failed: no register data')
            return
        top3 = counter.most_common(3)
        self.vbr, count = top3[0]
        print(f'[LightFISH] VBR = {hex(self.vbr)} ({count} rows)')
        for rank, (val, cnt) in enumerate(top3, 1):
            print(f'  #{rank}: {hex(val)} — {cnt} rows')

    # =========================================================================
    # Pre-pass 2 — VPC / VHTP 탐지
    # =========================================================================

    def _score_vpc_slots(self, slot_reads, lookahead: int, slack: int) -> tuple[int | None, float]:
        best_offset = None
        best_score  = -1.0
        for offset, reads in slot_reads.items():
            if len(reads) < _VPC_MIN_READS:
                continue
            ptr_hits = 0
            for (ri, val) in reads:
                if val == 0:
                    continue
                found = False
                for j in range(ri + 1, min(ri + lookahead, len(self.traces))):
                    for m2 in (self.traces[j].get('mem') or []):
                        if val <= m2.get('addr', 0) <= val + slack:
                            found = True
                            break
                    if found:
                        break
                if found:
                    ptr_hits += 1
            score = ptr_hits / len(reads)
            if score > best_score:
                best_score  = score
                best_offset = offset
        return best_offset, best_score

    def _detect_vpc_and_vhtp(self) -> None:
        if self.vbr is None:
            print('[LightFISH] VPC/VHTP detection skipped: VBR not set')
            return

        slot_reads  = collections.defaultdict(list)
        slot_writes = collections.defaultdict(int)

        for i, t in enumerate(self.traces):
            for m in (t.get('mem') or []):
                offset = m.get('addr', 0) - self.vbr
                if not (0 <= offset < _VBR_SLOT_RANGE):
                    continue
                if m.get('access') == 'READ':
                    slot_reads[offset].append((i, m.get('value', 0)))
                else:
                    slot_writes[offset] += 1

        # ── VPC ─────────────────────────────────────────────────────────────
        best_offset = None
        best_score = -1.0
        selected_lookahead = _VPC_LOOKAHEAD
        selected_slack = _VPC_OFFSET_SLACK
        overall_best = (None, -1.0, selected_lookahead, selected_slack)

        for lookahead, slack in _VPC_FALLBACK_CONFIGS:
            offset, score = self._score_vpc_slots(slot_reads, lookahead, slack)
            if score > overall_best[1]:
                overall_best = (offset, score, lookahead, slack)
            if offset is not None and score > _VPC_MIN_SCORE:
                best_offset = offset
                best_score = score
                selected_lookahead = lookahead
                selected_slack = slack
                break

        if best_offset is None:
            best_offset, best_score, selected_lookahead, selected_slack = overall_best

        if best_offset is not None and best_score > _VPC_MIN_SCORE:
            self.vpc_slot = best_offset
            self.vpc_lookahead = selected_lookahead
            self.vpc_offset_slack = selected_slack
            self.stack_temp_tracking_enabled = (
                selected_lookahead != _VPC_LOOKAHEAD
                or selected_slack != _VPC_OFFSET_SLACK
            )
            rc = len(slot_reads[best_offset])
            wc = slot_writes.get(best_offset, 0)
            print(f'[LightFISH] VPC = VB_0x{self.vpc_slot:x}'
                  f'  addr={hex(self.vbr + self.vpc_slot)}'
                  f'  reads={rc}  writes={wc}  ptr_ratio={best_score:.1%}'
                  f'  lookahead={self.vpc_lookahead}  slack={hex(self.vpc_offset_slack)}')
        else:
            print('[LightFISH] VPC detection failed')
            return

        # ── VHTP ──────────────────────────────────────────────────────────────
        vpc_seen = {v for (_, v) in slot_reads[self.vpc_slot] if v}
        if not vpc_seen:
            print('[LightFISH] VHTP detection failed: no non-zero VPC values')
            return

        min_vpc         = min(vpc_seen)
        best_vhtp_offset = None
        best_vhtp_reads  = -1
        best_vhtp_value  = None

        for offset, reads in slot_reads.items():
            if offset == self.vpc_slot:
                continue
            if slot_writes.get(offset, 0) > _VHTP_MAX_WRITES:
                continue
            vals = [v for (_, v) in reads if v]
            if not vals:
                continue
            if len(set(vals)) != 1:
                continue
            v = vals[0]
            if v <= 0x10000:
                continue
            if v >= min_vpc:
                continue
            if not all(v <= vpc for vpc in vpc_seen):
                continue
            if len(reads) > best_vhtp_reads:
                best_vhtp_reads  = len(reads)
                best_vhtp_offset = offset
                best_vhtp_value  = v

        if best_vhtp_offset is not None:
            self.vhtp_slot  = best_vhtp_offset
            self.vhtp_value = best_vhtp_value
            wc = slot_writes.get(self.vhtp_slot, 0)
            print(f'[LightFISH] VHTP = VB_0x{self.vhtp_slot:x}'
                  f'  addr={hex(self.vbr + self.vhtp_slot)}'
                  f'  value={hex(best_vhtp_value)}'
                  f'  reads={best_vhtp_reads}  writes={wc}')
        else:
            print('[LightFISH] VHTP detection failed')

        self._detect_vmop(slot_reads, slot_writes)

    def _detect_vmop(self, slot_reads, slot_writes) -> None:
        """VMOP(Virtual Micro OPcode) slot을 VBR-relative slot 통계로 탐지한다."""
        if self.vpc_slot is None:
            print('[LightFISH] VMOP detection skipped: VPC not set')
            return

        best_offset = None
        best_rpw = -1.0

        for offset, reads in slot_reads.items():
            if offset == self.vpc_slot or offset == self.vhtp_slot:
                continue
            writes = slot_writes.get(offset, 0)
            if writes < _VMOP_MIN_WRITES:
                continue

            vals = [v for (_, v) in reads if v != 0]
            if not vals or max(vals) > 0xFF:
                continue

            rpw = len(reads) / writes
            if rpw < _VMOP_MIN_RPW:
                continue

            ptr_hits = 0
            for (ri, val) in reads:
                if val == 0:
                    continue
                found = False
                for j in range(ri + 1, min(ri + self.vpc_lookahead, len(self.traces))):
                    for m2 in (self.traces[j].get('mem') or []):
                        if val <= m2.get('addr', 0) <= val + self.vpc_offset_slack:
                            found = True
                            break
                    if found:
                        break
                if found:
                    ptr_hits += 1
            ptr_ratio = ptr_hits / len(reads)
            if ptr_ratio > _VMOP_MAX_PTR_RATIO:
                continue

            if rpw > best_rpw:
                best_rpw = rpw
                best_offset = offset

        if best_offset is not None:
            self.vmop_slot = best_offset
            rc = len(slot_reads[best_offset])
            wc = slot_writes.get(best_offset, 0)
            print(f'[LightFISH] VMOP = VB_0x{self.vmop_slot:x}'
                  f'  addr={hex(self.vbr + self.vmop_slot)}'
                  f'  reads={rc}  writes={wc}  rpw={best_rpw:.1f}')
        else:
            print('[LightFISH] VMOP detection failed')

    # =========================================================================
    # Pre-pass 3 — VB 슬롯 주소 수집
    # =========================================================================

    def _relabel_special_slots(self) -> None:
        """vb_addr_map에서 VPC/VHTP 주소의 레이블을 전용 심볼로 교체한다."""
        if self.vbr is None:
            return
        if self.vpc_slot is not None:
            addr = self.vbr + self.vpc_slot
            if addr in self.vb_addr_map:
                self.vb_addr_map[addr] = f'VPC_0x{self.vpc_slot:x}'
        if self.vhtp_slot is not None:
            addr = self.vbr + self.vhtp_slot
            if addr in self.vb_addr_map:
                self.vb_addr_map[addr] = f'VHTP_0x{self.vhtp_slot:x}'
        if self.vmop_slot is not None:
            addr = self.vbr + self.vmop_slot
            if addr in self.vb_addr_map:
                self.vb_addr_map[addr] = f'VMOP_0x{self.vmop_slot:x}'

    def _prepass_vb_slots(self) -> None:
        """EBP==VBR 구간에서 VBR+offset 메모리 접근을 VB 슬롯으로 기록한다."""
        if self.vbr is None:
            return
        for trace in self.traces:
            regs = trace.get('regs')
            if not regs or len(regs) <= _EBP_IDX:
                continue
            if regs[_EBP_IDX] != self.vbr:
                continue
            for m in (trace.get('mem') or []):
                addr   = m.get('addr', 0) & 0xFFFFFFFF
                offset = (addr - self.vbr) & 0xFFFFFFFF
                if offset < _VBR_SLOT_RANGE and addr not in self.vb_addr_map:
                    self.vb_addr_map[addr] = f'VB_0x{offset:x}'
        print(f'[LightFISH] VB slot pre-pass: {len(self.vb_addr_map)} addresses recorded')

    # =========================================================================
    # Pre-pass 4 — VM interval 탐지
    # =========================================================================

    @staticmethod
    def _trace_mnemonic(trace: dict) -> str:
        return ((trace.get('disasm') or '').split(' ', 1)[0]).upper()

    def _initial_stack_bounds(self) -> tuple[int, int] | None:
        for trace in self.traces:
            regs = trace.get('regs') or []
            if len(regs) <= _EBP_IDX:
                continue
            esp = regs[_REG_INDEX_32['ESP']]
            ebp = regs[_REG_INDEX_32['EBP']]
            lo = (min(esp, ebp) - 0x4000) & 0xFFFFFFFF
            hi = (max(esp, ebp) + 0x4000) & 0xFFFFFFFF
            if lo <= hi:
                return lo, hi
        return None

    @staticmethod
    def _has_mem_access_in_range(trace: dict, lo: int, hi: int, access: str | None = None) -> bool:
        for m in (trace.get('mem') or []):
            if access is not None and m.get('access') != access:
                continue
            addr = m.get('addr', 0) & 0xFFFFFFFF
            if lo <= addr <= hi:
                return True
        return False

    def _is_stack_access(self, trace: dict, stack_bounds: tuple[int, int] | None, access: str | None = None) -> bool:
        if stack_bounds is None:
            return False
        lo, hi = stack_bounds
        return self._has_mem_access_in_range(trace, lo, hi, access)

    def _is_vm_structural_evidence(self, trace: dict) -> bool:
        if self.vbr is None:
            return False
        regs = trace.get('regs') or []
        if len(regs) > _EBP_IDX and regs[_EBP_IDX] == self.vbr:
            return True
        for m in (trace.get('mem') or []):
            addr = m.get('addr', 0) & 0xFFFFFFFF
            if addr in self.vb_addr_map:
                return True
            offset = (addr - self.vbr) & 0xFFFFFFFF
            if offset < _VBR_SLOT_RANGE:
                return True
            if self.vhtp_value is not None and self.vhtp_value <= addr < self.vhtp_value + 0x10000:
                return True
        return False

    def _find_vm_entry_start(self, first_evidence: int, stack_bounds: tuple[int, int] | None) -> int:
        lower = max(0, first_evidence - 5000)
        entry = first_evidence

        # Prefer the context-save prologue.  The protected stubs observed in
        # red/white/black all save host flags/registers through the stack before
        # VBR becomes stable; black additionally interleaves stack shuffles.
        for row_id in range(first_evidence, lower - 1, -1):
            row = self.traces[row_id]
            if self._trace_mnemonic(row) not in ('PUSHFD', 'PUSHF', 'PUSHFQ'):
                continue
            if not self._is_stack_access(row, stack_bounds, 'WRITE'):
                continue
            entry = row_id
            break

        # Include the short host-to-stub transfer immediately before pushfd.
        while entry > 0 and entry - 1 >= max(0, lower):
            prev = self.traces[entry - 1]
            prev_mn = self._trace_mnemonic(prev)
            if prev_mn in ('CALL', 'JMP'):
                entry -= 1
                continue
            break
        return entry

    def _find_vm_exit_end(self, last_evidence: int, stack_bounds: tuple[int, int] | None) -> int:
        upper = min(len(self.traces) - 1, last_evidence + 50000)
        fallback = last_evidence
        for row_id in range(last_evidence + 1, upper + 1):
            row = self.traces[row_id]
            mn = self._trace_mnemonic(row)
            if mn not in ('RET', 'RETN'):
                continue
            if fallback == last_evidence:
                fallback = row_id
            if not self._is_stack_access(row, stack_bounds, 'READ'):
                continue
            prev_lo = max(last_evidence, row_id - 300)
            saw_popfd = any(
                self._trace_mnemonic(self.traces[prev]) in ('POPFD', 'POPF', 'POPFQ')
                for prev in range(prev_lo, row_id)
            )
            if saw_popfd:
                return row_id
        return fallback

    def _detect_vm_intervals(self) -> None:
        self.vm_intervals = []
        self.vm_tracking_intervals = []
        if self.vbr is None:
            return
        evidence_rows = [
            trace.get('id', idx)
            for idx, trace in enumerate(self.traces)
            if self._is_vm_structural_evidence(trace)
        ]
        if not evidence_rows:
            print('[LightFISH] VM interval detection failed: no structural evidence')
            return

        stack_bounds = self._initial_stack_bounds()
        first_evidence = min(evidence_rows)
        last_evidence = max(evidence_rows)
        start = self._find_vm_entry_start(first_evidence, stack_bounds)
        end = self._find_vm_exit_end(last_evidence, stack_bounds)
        if end < start:
            start, end = first_evidence, last_evidence
        self.vm_intervals = [(start, end)]
        self.vm_tracking_intervals = [(first_evidence, end)]
        print(f'[LightFISH] VM interval = rows {start}..{end}'
              f' (structural rows {first_evidence}..{last_evidence})')

    def is_row_index_in_vm(self, row_id: int | None) -> bool:
        if row_id is None:
            return False
        if self.vm_intervals:
            return any(start <= row_id <= end for start, end in self.vm_intervals)
        if self.vbr is None or row_id < 0 or row_id >= len(self.traces):
            return False
        regs = self.traces[row_id].get('regs') or []
        return len(regs) > _EBP_IDX and regs[_EBP_IDX] == self.vbr

    def is_trace_in_vm(self, trace: dict) -> bool:
        row_id = trace.get('id')
        if row_id is not None:
            return self.is_row_index_in_vm(row_id)
        if self.vbr is None:
            return False
        regs = trace.get('regs') or []
        return len(regs) > _EBP_IDX and regs[_EBP_IDX] == self.vbr

    def is_row_index_in_vm_tracking(self, row_id: int | None) -> bool:
        if row_id is None:
            return False
        intervals = self.vm_tracking_intervals or self.vm_intervals
        if intervals:
            return any(start <= row_id <= end for start, end in intervals)
        return self.is_row_index_in_vm(row_id)

    def is_trace_in_vm_tracking(self, trace: dict) -> bool:
        return self.is_row_index_in_vm_tracking(trace.get('id'))

    # =========================================================================
    # 메인 패스 헬퍼
    # =========================================================================

    def _get_dst_symbol(self, trace) -> str | None:
        """명령어의 WRITE 오퍼랜드에서 저장소 심볼 이름을 반환한다."""
        dst = self._get_dst_symbol_and_access(trace)
        return dst[0] if dst is not None else None

    def _get_dst_symbol_and_access(self, trace) -> tuple[str, OperandAccess] | None:
        """명령어의 WRITE 오퍼랜드에서 저장소 심볼 이름과 access type을 반환한다."""
        for op in (trace.get('parsed_operands') or []):
            if op.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                continue
            if op.is_implicit:
                continue
            if op.type == OperandType.REG:
                return _root_reg(op.reg_name), op.access
            if op.type == OperandType.MEM:
                if self.ctx_taint is None:
                    return None
                try:
                    addr, _ = op.resolve_addr(self.ctx_taint, trace.get('ip'))
                    addr &= 0xFFFFFFFF
                    if addr in self.vb_addr_map:
                        return self.vb_addr_map[addr], op.access
                except Exception:
                    pass
                return None
        return None

    def _addr_to_sym(self, addr: int) -> str | None:
        """concrete 주소를 vb_addr_map 또는 _fetch_traces 심볼로 변환한다."""
        if addr in self.vb_addr_map:
            return self.vb_addr_map[addr]
        if addr in self._vch_addr_map:
            return self._vch_addr_map[addr]
        if addr in self._stack_addr_labels or addr in self._stack_addr_elements:
            return self._stack_label(addr)
        label = f'VMBLOB_0x{addr:x}'
        return label if label in self._fetch_traces else None

    def _resolve_mem_operand_addr(self, op, trace) -> int | None:
        if op.type != OperandType.MEM:
            return None
        ctx = self.ctx_taint if self.ctx_taint is not None else self.ctx
        try:
            addr, _ = op.resolve_addr(ctx, trace.get('ip'))
            return addr & 0xFFFFFFFF
        except Exception:
            return None

    def _find_mem_operand(self, trace: dict, addr: int, is_write: bool):
        """Trace mem entry 주소와 매칭되는 explicit MEM operand를 찾는다."""
        wanted_accesses = (
            (OperandAccess.WRITE, OperandAccess.READ_WRITE)
            if is_write else
            (OperandAccess.READ, OperandAccess.READ_WRITE)
        )
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit or op.type != OperandType.MEM:
                continue
            if op.access not in wanted_accesses:
                continue
            resolved = self._resolve_mem_operand_addr(op, trace)
            if resolved == (addr & 0xFFFFFFFF):
                return op
        return None

    def _address_carrier_labels(self, op) -> set[str]:
        """MEM operand 주소 계산에 사용된 base/index register의 provenance labels."""
        if op is None or op.type != OperandType.MEM:
            return set()
        labels = set()
        mem = op.mem_info or {}
        for reg_key in ('base', 'index'):
            reg_name = mem.get(reg_key)
            if not reg_name:
                continue
            labels |= self._adimehts.get(_root_reg(reg_name), set())
        return labels

    def _labels_for_addr_value(self, addr: int) -> set[str]:
        """주소에서 읽히는 값의 provenance labels."""
        addr &= 0xFFFFFFFF
        if addr in self.vb_addr_map:
            label = self.vb_addr_map[addr]
            return set(self._adimehts.get(label, {label}))
        if addr in self._vch_addr_map:
            return {self._vch_addr_map[addr]}
        if addr in self._stack_addr_labels:
            return set(self._stack_addr_labels.get(addr, set()))
        label = f'VMBLOB_0x{addr:x}'
        if label in self._fetch_traces:
            return {label}
        return set()

    def _labels_for_operand_value(self, op, trace: dict) -> set[str]:
        if op.type == OperandType.REG:
            return set(self._adimehts.get(_root_reg(op.reg_name), set()))
        if op.type == OperandType.MEM:
            inst = trace.get('instruction_obj')
            if inst and inst.mnemonic.upper() == 'LEA':
                return self._address_carrier_labels(op)
            addr = self._resolve_mem_operand_addr(op, trace)
            if addr is None:
                return set()
            return self._labels_for_addr_value(addr)
        return set()

    def _elements_for_addr_value(self, addr: int) -> set[str]:
        """주소에서 읽히는 값을 직접 공급한 VM element label."""
        addr &= 0xFFFFFFFF
        if addr in self.vb_addr_map:
            return {self.vb_addr_map[addr]}
        if addr in self._vch_addr_map:
            return {self._vch_addr_map[addr]}
        if addr in self._stack_addr_elements:
            return set(self._stack_addr_elements.get(addr, set()))
        return set()

    def _elements_for_operand_value(self, op, trace: dict) -> set[str]:
        if op.type == OperandType.REG:
            return set(self._element_sources.get(_root_reg(op.reg_name), set()))
        if op.type == OperandType.MEM:
            inst = trace.get('instruction_obj')
            if inst and inst.mnemonic.upper() == 'LEA':
                return self._address_carrier_elements(op)
            addr = self._resolve_mem_operand_addr(op, trace)
            if addr is None:
                return set()
            return self._elements_for_addr_value(addr)
        return set()

    def _address_carrier_elements(self, op) -> set[str]:
        """MEM operand 주소 계산에 사용된 base/index register의 VM element labels."""
        if op is None or op.type != OperandType.MEM:
            return set()
        labels = set()
        mem = op.mem_info or {}
        for reg_key in ('base', 'index'):
            reg_name = mem.get(reg_key)
            if not reg_name:
                continue
            labels |= self._element_sources.get(_root_reg(reg_name), set())
        return labels

    def _trace_reg_slice(self, reg_name: str) -> tuple[str, int, int]:
        return _REG_SLICE_32.get(reg_name.upper(), (_root_reg(reg_name), 0, 32))

    def _trace_reg_value(self, trace: dict, reg_name: str) -> int:
        root, low, bits = self._trace_reg_slice(reg_name)
        regs = trace.get('regs') or []
        idx = _REG_INDEX_32.get(root)
        if idx is None or idx >= len(regs) or regs[idx] is None:
            return 0
        return (regs[idx] >> low) & ((1 << bits) - 1)

    def _trace_mem_operand_addr(self, op, trace: dict) -> int | None:
        if op.type != OperandType.MEM:
            return None
        mem = op.mem_info or {}
        addr = mem.get('disp', 0) or 0
        base = mem.get('base')
        index = mem.get('index')
        if base:
            addr += self._trace_reg_value(trace, base)
        if index:
            addr += self._trace_reg_value(trace, index) * mem.get('scale', 1)
        return addr & 0xFFFFFFFF

    def _mem_operand_accesses(self, trace: dict, addr: int) -> list[OperandAccess]:
        """trace mem entry 주소와 매칭되는 explicit MEM operand access 목록."""
        accesses = []
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit or op.type != OperandType.MEM:
                continue
            resolved = self._trace_mem_operand_addr(op, trace)
            if resolved == (addr & 0xFFFFFFFF):
                accesses.append(op.access)
        return accesses

    def _implicit_mem_addr(self, trace: dict, accesses: tuple[OperandAccess, ...]) -> int | None:
        for op in (trace.get('parsed_operands') or []):
            if not op.is_implicit or op.type != OperandType.MEM:
                continue
            if op.access not in accesses:
                continue
            addr = self._trace_mem_operand_addr(op, trace)
            if addr is not None:
                return addr
        return None

    def _operand_concrete_value(self, op, trace: dict) -> int | None:
        if op.type == OperandType.REG:
            return self._trace_reg_value(trace, op.reg_name)
        if op.type == OperandType.IMM:
            return op.imm_value
        if op.type == OperandType.MEM:
            addr = self._trace_mem_operand_addr(op, trace)
            if addr is None:
                return None
            for m in (trace.get('mem') or []):
                if m.get('access') == 'READ' and (m.get('addr', 0) & 0xFFFFFFFF) == addr:
                    return m.get('value', 0)
        return None

    def _estimate_mem_write_value(self, trace: dict, addr: int, observed_value: int) -> int:
        """WRITE로 잘못 기록되지 않은 READ_WRITE 메모리 명령의 결과 값을 보수적으로 추정한다."""
        inst = trace.get('instruction_obj')
        if inst is None:
            return observed_value
        operands = [op for op in (trace.get('parsed_operands') or [])
                    if not op.is_implicit]
        if not operands:
            return observed_value

        dst = operands[0]
        if dst.type != OperandType.MEM:
            return observed_value
        if self._trace_mem_operand_addr(dst, trace) != (addr & 0xFFFFFFFF):
            return observed_value
        if dst.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
            return observed_value

        bits = max(dst.size * 8, 1)
        mask = (1 << bits) - 1
        mnemonic = inst.mnemonic.upper()
        src_val = self._operand_concrete_value(operands[1], trace) if len(operands) > 1 else None
        if src_val is None:
            return observed_value
        src_val &= mask

        if mnemonic in ('MOV', 'MOVZX', 'MOVSX', 'MOVSXD'):
            return src_val

        old_val = observed_value & mask
        if mnemonic == 'ADD':
            return (old_val + src_val) & mask
        if mnemonic == 'SUB':
            return (old_val - src_val) & mask
        if mnemonic == 'XOR':
            return (old_val ^ src_val) & mask
        if mnemonic == 'OR':
            return (old_val | src_val) & mask
        if mnemonic == 'AND':
            return (old_val & src_val) & mask
        return observed_value

    def _collect_read_labels(self, trace: dict, exclude_mem_addrs: set[int] | None = None) -> set[str]:
        labels = set()
        exclude_mem_addrs = exclude_mem_addrs or set()
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit:
                continue
            if op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                continue
            if op.type == OperandType.MEM:
                addr = self._resolve_mem_operand_addr(op, trace)
                if addr in exclude_mem_addrs:
                    continue
            labels |= self._labels_for_operand_value(op, trace)
        return labels

    def _collect_read_elements(self, trace: dict, exclude_mem_addrs: set[int] | None = None) -> set[str]:
        labels = set()
        exclude_mem_addrs = exclude_mem_addrs or set()
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit:
                continue
            if op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                continue
            if op.type == OperandType.MEM:
                addr = self._resolve_mem_operand_addr(op, trace)
                if addr in exclude_mem_addrs:
                    continue
            labels |= self._elements_for_operand_value(op, trace)
        return labels

    @staticmethod
    def _vm_element_labels(labels: set[str]) -> set[str]:
        prefixes = ('VB_', 'VPC_', 'VHTP_', 'VMOP_', 'VCH_')
        return {label for label in labels if label == 'VTABLE' or label.startswith(prefixes)}

    @staticmethod
    def _vmblob_labels(labels: set[str]) -> set[str]:
        return {label for label in labels if label.startswith('VMBLOB_')}

    def _single_vmblob_label(self, labels: set[str]) -> set[str]:
        vmblob_labels = self._vmblob_labels(labels)
        return vmblob_labels if len(vmblob_labels) == 1 else set()

    @staticmethod
    def _has_label_prefix(labels: set[str], prefix: str) -> bool:
        return any(label.startswith(prefix) for label in labels)

    def _special_self_label(self, label: str) -> set[str]:
        if label.startswith(('VPC_', 'VHTP_', 'VMOP_')):
            return {label}
        return set()

    def _write_symbol(self, symbol: str, labels: set[str], access=OperandAccess.WRITE) -> None:
        labels = set(labels)
        labels |= self._special_self_label(symbol)
        if access == OperandAccess.READ_WRITE:
            labels |= self._adimehts.get(symbol, set())
        if labels:
            self._adimehts[symbol] = labels
        else:
            self._adimehts.pop(symbol, None)

    def _write_elements(self, symbol: str, labels: set[str], access=OperandAccess.WRITE) -> None:
        labels = self._vm_element_labels(set(labels))
        if access == OperandAccess.READ_WRITE:
            labels |= self._element_sources.get(symbol, set())
        if labels:
            self._element_sources[symbol] = labels
        else:
            self._element_sources.pop(symbol, None)

    def _remove_labels_from_symbols(self, labels: set[str]) -> None:
        if not labels:
            return
        for symbol in list(self._adimehts.keys()):
            remaining = self._adimehts[symbol] - labels
            if remaining:
                self._adimehts[symbol] = remaining
            else:
                self._adimehts.pop(symbol, None)

    def _remove_elements_from_symbols(self, labels: set[str]) -> None:
        if not labels:
            return
        for symbol in list(self._element_sources.keys()):
            remaining = self._element_sources[symbol] - labels
            if remaining:
                self._element_sources[symbol] = remaining
            else:
                self._element_sources.pop(symbol, None)

    @staticmethod
    def _stack_label(addr: int) -> str:
        return f'STACK_0x{addr & 0xFFFFFFFF:x}'

    def _write_stack_temp(self, addr: int, labels: set[str], elements: set[str] | None = None) -> None:
        if not self.stack_temp_tracking_enabled:
            return
        addr &= 0xFFFFFFFF
        labels = set(labels)
        elements = self._vm_element_labels(set(elements or set()))
        if labels:
            self._stack_addr_labels[addr] = labels
        else:
            self._stack_addr_labels.pop(addr, None)
        if elements:
            self._stack_addr_elements[addr] = elements
        else:
            self._stack_addr_elements.pop(addr, None)

    def _propagate_stack_read(self, trace: dict, addr: int, handled_dsts: set[str]) -> bool:
        addr &= 0xFFFFFFFF
        labels = set(self._stack_addr_labels.get(addr, set()))
        elements = set(self._stack_addr_elements.get(addr, set()))
        if not labels and not elements:
            return False

        dst_info = self._get_dst_symbol_and_access(trace)
        if dst_info is None:
            return False

        dst_sym, dst_access = dst_info
        self._write_symbol(dst_sym, labels, dst_access)
        self._write_elements(dst_sym, elements, dst_access)
        handled_dsts.add(dst_sym)
        return True

    def _mark_vmblob_data_labels(self, labels: set[str]) -> None:
        for label in self._vmblob_labels(labels):
            self._vmblob_data_labels.add(label)
            self._clear_dead_vmblob_label(label)

    def _mark_dead_vmblob_labels(self, labels: set[str]) -> None:
        candidates = (
            self._vmblob_labels(labels)
            - self._vmblob_role_labels
            - self._vmblob_data_labels
            - self._dead_vmblob_labels
        )
        for label in sorted(candidates):
            if self._annotate_fetch(label, 'dead', include_history=False):
                self._dead_vmblob_labels.add(label)

    def _mark_dead_from_overwrite(self, old_labels: set[str], new_labels: set[str] | None = None) -> None:
        new_labels = new_labels or set()
        dropped = self._vmblob_labels(old_labels) - self._vmblob_labels(new_labels)
        self._mark_dead_vmblob_labels(dropped)

    def _annotate_vb_relay(self, labels: set[str], vb_label: str, row_id: int | None) -> None:
        vmblob_labels = self._vmblob_labels(labels)
        if not vmblob_labels:
            return
        self._mark_vmblob_data_labels(vmblob_labels)
        for label in sorted(vmblob_labels):
            fetch_trace = self._current_unrelayed_fetch_trace(label)
            if fetch_trace is None:
                continue
            self._append_fetch_trace_annotation(fetch_trace, f'relayed to {vb_label}', row_id)
            self._vmblob_relay_fetch_ids.add(id(fetch_trace))

    def _append_fetch_trace_annotation(self, fetch_trace: dict, tag: str, row_id: int | None = None) -> None:
        annotated = f'[{row_id} : {tag}]' if row_id is not None else f'[{tag}]'
        existing = fetch_trace.get('comment') or ''
        if annotated not in existing:
            fetch_trace['comment'] = (existing + f' | {annotated}').lstrip(' | ')

    def _current_unrelayed_fetch_trace(self, label: str) -> dict | None:
        current = self._fetch_traces.get(label)
        if current is not None and id(current) not in self._vmblob_relay_fetch_ids:
            return current
        for fetch_trace in reversed(self._fetch_history.get(label, [])):
            if id(fetch_trace) not in self._vmblob_relay_fetch_ids:
                return fetch_trace
        return None

    def _fetch_annotation_targets(self, label: str, include_history: bool = True) -> list[dict]:
        targets = []
        current = self._fetch_traces.get(label)
        if current is not None:
            targets.append(current)
        if include_history:
            targets.extend(self._fetch_history.get(label, []))
        return targets

    def _remove_fetch_annotation(self, label: str, annotation: str, include_history: bool = True) -> None:
        seen = set()
        for fetch_trace in self._fetch_annotation_targets(label, include_history=include_history):
            trace_id = id(fetch_trace)
            if trace_id in seen:
                continue
            seen.add(trace_id)
            parts = [part.strip() for part in (fetch_trace.get('comment') or '').split('|')]
            parts = [part for part in parts if part and part != annotation]
            fetch_trace['comment'] = ' | '.join(parts)

    def _clear_dead_vmblob_label(self, label: str) -> None:
        if label not in self._dead_vmblob_labels:
            return
        self._dead_vmblob_labels.discard(label)
        self._remove_fetch_annotation(label, '[dead]')

    def _reset_runtime_state(self) -> None:
        self._pending_vpc = None
        self._current_vpc = None
        self._adimehts.clear()
        self._element_sources.clear()
        self._fetch_traces.clear()
        self._fetch_history.clear()
        self._stack_addr_labels.clear()
        self._stack_addr_elements.clear()
        self._vmblob_role_labels.clear()
        self._vmblob_data_labels.clear()
        self._vmblob_relay_fetch_ids.clear()
        self._dead_vmblob_labels.clear()
        self._vch_sources.clear()
        self._vch_addr_map.clear()
        self._vmop_cycle_value = None
        self._vmop_sources = set()
        self._pending_decode_vmop = None
        self._pending_branch_sources = set()
        self._pending_branch_elements = set()

    def _enter_vm(self) -> None:
        vpc_label = f'VPC_0x{self.vpc_slot:x}'
        self._adimehts[vpc_label] = {vpc_label}
        self._element_sources[vpc_label] = {vpc_label}
        if self.vhtp_slot is not None:
            vhtp_label = f'VHTP_0x{self.vhtp_slot:x}'
            self._adimehts[vhtp_label] = {vhtp_label}
            self._element_sources[vhtp_label] = {vhtp_label}
        if self.vmop_slot is not None:
            vmop_label = f'VMOP_0x{self.vmop_slot:x}'
            self._adimehts[vmop_label] = {vmop_label}
            self._element_sources[vmop_label] = {vmop_label}

    def _start_new_dispatch_cycle(self) -> None:
        """현재 dispatch의 bytecode fetch annotation window를 닫는다."""
        self._fetch_traces.clear()
        self._vch_sources.clear()
        self._vch_addr_map.clear()
        self._vmop_cycle_value = None
        self._vmop_sources = set()
        self._pending_decode_vmop = None
        self._pending_branch_elements = set()

    def _build_symbolic_disasm(self, trace: dict) -> str | None:
        """오퍼랜드 중 하나라도 adimehts에 등록되거나 MEM이 식별된 경우 symbolic disasm을 반환한다.
        MEM 주소는 trace['mem']의 실제 접근 주소를 사용한다 (src=READ 순서, dst=WRITE 순서)."""
        inst     = trace.get('instruction_obj')
        operands = trace.get('parsed_operands') or []
        if not inst or not operands:
            return None

        # trace['mem']의 실제 접근 주소 수집 (순서 보존)
        read_addrs  = [m.get('addr', 0) & 0xFFFFFFFF
                       for m in (trace.get('mem') or []) if m.get('access') == 'READ']
        write_addrs = [m.get('addr', 0) & 0xFFFFFFFF
                       for m in (trace.get('mem') or []) if m.get('access') != 'READ']

        read_idx       = 0
        write_idx      = 0
        parts          = []
        has_tracked_op = False

        for op in operands:
            if op.is_implicit:
                continue
            if op.type == OperandType.REG:
                reg = _root_reg(op.reg_name)
                if self._adimehts.get(reg):
                    has_tracked_op = True
                parts.append(reg)
            elif op.type == OperandType.IMM:
                parts.append(hex(op.imm_value))
            elif op.type == OperandType.MEM:
                is_src = op.access != OperandAccess.WRITE
                sym    = None
                if is_src and read_idx < len(read_addrs):
                    used_addr = read_addrs[read_idx]
                    sym = self._addr_to_sym(used_addr)
                    if sym is None:
                        base_reg = _root_reg((op.mem_info or {}).get('base', ''))
                        if 'VTABLE' in self._adimehts.get(base_reg, set()) and self.vhtp_value is not None:
                            offset = (used_addr - self.vhtp_value) & 0xFFFFFFFF
                            sym = f'VTABLE_0x{offset:x}'
                    read_idx += 1
                elif not is_src and write_idx < len(write_addrs):
                    used_addr = write_addrs[write_idx]
                    sym = self._addr_to_sym(used_addr)
                    write_idx += 1
                if sym:
                    parts.append(sym)
                    has_tracked_op = True
                else:
                    mem        = op.mem_info or {}
                    base       = mem.get('base', '')
                    idx        = mem.get('index', '')
                    scale      = mem.get('scale', 1)
                    disp       = mem.get('disp', 0)
                    addr_parts = []
                    if base:
                        addr_parts.append(base.upper())
                    if idx:
                        addr_parts.append(f'{idx.upper()}*{scale}' if scale > 1 else idx.upper())
                    if disp:
                        addr_parts.append(hex(disp) if disp > 0 else f'-{hex(-disp)}')
                    parts.append(f'[{"+".join(addr_parts) or "0"}]')

        if not has_tracked_op or not parts:
            return None
        return f'{inst.mnemonic} {", ".join(parts)}'

    def _signed_delta(self, a: int, b: int) -> tuple[str, int]:
        mask = (1 << self.ctx.arch_mode) - 1
        half = 1 << (self.ctx.arch_mode - 1)
        raw  = (b - a) & mask
        if raw >= half:
            return '-', (1 << self.ctx.arch_mode) - raw
        return '+', raw

    @staticmethod
    def _append_comment(trace: dict, msg: str) -> None:
        existing = trace.get('comment') or ''
        trace['comment'] = (existing + f' | {msg}').lstrip(' | ')

    @staticmethod
    def _append_unique_comment(trace: dict, msg: str) -> None:
        existing = trace.get('comment') or ''
        parts = [part.strip() for part in existing.split('|') if part.strip()]
        if msg not in parts:
            trace['comment'] = (existing + f' | {msg}').lstrip(' | ')

    @staticmethod
    def _remove_comment_parts(trace: dict, removals: set[str] | frozenset[str]) -> None:
        existing = trace.get('comment') or ''
        if not existing:
            return
        parts = [part.strip() for part in existing.split('|') if part.strip()]
        kept = [part for part in parts if part not in removals]
        trace['comment'] = ' | '.join(kept)

    @staticmethod
    def _insert_after_vm(trace: dict, msg: str) -> None:
        """msg를 [VM] 바로 뒤에 삽입한다. [VM]이 없으면 _append_comment와 동일."""
        comment = trace.get('comment') or ''
        tag = '[VM]'
        if comment == tag:
            trace['comment'] = f'{tag} | {msg}'
        elif comment.startswith(tag + ' | '):
            trace['comment'] = f'{tag} | {msg} | {comment[len(tag) + 3:]}'
        else:
            existing = comment
            trace['comment'] = (existing + f' | {msg}').lstrip(' | ')

    def _annotate_fetch(
        self,
        label: str,
        tag: str,
        row_id: int | None = None,
        include_history: bool = True,
    ) -> bool:
        """label의 fetch 행 comment에 [row_id : tag] 형태로 역방향 어노테이션한다."""
        if tag != 'dead' and label.startswith('VMBLOB_'):
            self._vmblob_role_labels.add(label)
            self._clear_dead_vmblob_label(label)
        targets = self._fetch_annotation_targets(label, include_history=include_history)
        if not targets:
            return False
        annotated = f'[{row_id} : {tag}]' if row_id is not None else f'[{tag}]'
        seen = set()
        annotated_any = False
        for fetch_trace in targets:
            trace_id = id(fetch_trace)
            if trace_id in seen:
                continue
            seen.add(trace_id)
            existing  = fetch_trace.get('comment') or ''
            if annotated not in existing:
                fetch_trace['comment'] = (existing + f' | {annotated}').lstrip(' | ')
            annotated_any = True
        return annotated_any

    def _check_vb_offset(self, trace: dict, vb_addr: int) -> None:
        """VB 슬롯 접근 명령어의 addressing 레지스터에 VMBLOB이 있으면 fetch 행에 vb offset 어노테이션."""
        vb_label = self.vb_addr_map.get(vb_addr, f'VB_0x{(vb_addr - self.vbr):x}')
        row_id   = trace.get('id')
        consumed = set()
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit or op.type != OperandType.MEM:
                continue
            resolved = self._trace_mem_operand_addr(op, trace)
            if resolved != (vb_addr & 0xFFFFFFFF):
                continue
            for reg_key in ('base', 'index'):
                reg_name = (op.mem_info or {}).get(reg_key, '')
                if not reg_name:
                    continue
                labels = self._adimehts.get(_root_reg(reg_name), set())
                for lbl in self._vmblob_labels(labels):
                    self._annotate_fetch(lbl, f'vb offset : {vb_label}', row_id)
                    consumed.add(lbl)
        self._remove_labels_from_symbols(consumed)

    _FETCH_SIZE_KEYWORDS = (('qword', 8), ('dword', 4), ('word', 2), ('byte', 1))

    def _build_fetch_comment(self, fetch_addr: int, trace: dict) -> str:
        disasm     = (trace.get('disasm') or '').lower()
        fetch_size = next((v for k, v in self._FETCH_SIZE_KEYWORDS
                           if k + ' ptr' in disasm), None)
        size_str   = f' ({fetch_size})' if fetch_size is not None else ''
        mask = (1 << self.ctx.arch_mode) - 1
        half = 1 << (self.ctx.arch_mode - 1)
        if self._current_vpc is not None:
            delta = (fetch_addr - self._current_vpc) & mask
            if delta >= half:
                return f'[fetch : -{hex((1 << self.ctx.arch_mode) - delta)}{size_str}]'
            return f'[fetch : +{hex(delta)}{size_str}]'
        return f'[fetch{size_str}]'

    # ── VPC move 처리 ────────────────────────────────────────────────────────

    _MOV_MNEMONICS   = frozenset({'MOV', 'MOVZX', 'MOVSX', 'MOVSXD', 'LEA', 'POP'})
    _ARITH_MNEMONICS = frozenset({'ADD', 'SUB', 'INC', 'DEC', 'ADC', 'SBB'})

    def _handle_vpc_write(self, trace: dict, new_val: int, source_labels: set[str]) -> None:
        inst     = trace.get('instruction_obj')
        mnemonic = inst.mnemonic.upper() if inst else ''
        vmblob_sources = self._vmblob_labels(source_labels)
        consumed = set()

        if mnemonic in self._MOV_MNEMONICS:
            self._append_comment(trace, f'[VPC moved : {hex(new_val)}]')
            self._current_vpc = new_val
            for lbl in vmblob_sources:
                self._annotate_fetch(lbl, 'vpc move', trace.get('id'))
                consumed.add(lbl)
        elif mnemonic in self._ARITH_MNEMONICS and self._pending_vpc is not None:
            old_val = self._pending_vpc
            step_sign, abs_step = self._signed_delta(old_val, new_val)
            base = self._current_vpc if self._current_vpc is not None else old_val
            disp_sign, abs_disp = self._signed_delta(base, new_val)
            self._append_comment(
                trace,
                f'[VPC moved : {step_sign}{hex(abs_step)}'
                f' ({hex(base)} {disp_sign} {hex(abs_disp)})]'
            )
            row_id = trace.get('id')
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    continue
                if op.type == OperandType.REG:
                    label_set = self._adimehts.get(_root_reg(op.reg_name))
                    if label_set:
                        for lbl in self._vmblob_labels(label_set):
                            self._annotate_fetch(lbl, 'vpc stride', row_id)
                            consumed.add(lbl)
                elif op.type == OperandType.MEM:
                    addr = self._resolve_mem_operand_addr(op, trace)
                    if addr is None:
                        continue
                    vb_lbl = self.vb_addr_map.get(addr & 0xFFFFFFFF)
                    if vb_lbl:
                        label_set = self._adimehts.get(vb_lbl)
                        if label_set:
                            for lbl in self._vmblob_labels(label_set):
                                self._annotate_fetch(lbl, 'vpc stride', row_id)
                                consumed.add(lbl)
            for lbl in vmblob_sources:
                self._annotate_fetch(lbl, 'vpc stride', row_id)
                consumed.add(lbl)
        else:
            self._append_comment(trace, f'[VPC moved : {hex(new_val)}]')
            self._current_vpc = new_val
            for lbl in vmblob_sources:
                self._annotate_fetch(lbl, 'vpc move', trace.get('id'))
                consumed.add(lbl)
        self._remove_labels_from_symbols(consumed)

    def _is_vpc_fetch(self, trace: dict, addr: int) -> bool:
        if (self._pending_vpc is not None
                and self._pending_vpc <= addr <= self._pending_vpc + self.vpc_offset_slack):
            return True
        op = self._find_mem_operand(trace, addr, is_write=False)
        carrier = self._address_carrier_labels(op)
        return self._has_label_prefix(carrier, 'VPC_')

    def _handle_vmop_access(self, trace: dict, addr: int, access: str, value: int) -> None:
        if self.vmop_slot is None or self.vbr is None:
            return
        vmop_addr = self.vbr + self.vmop_slot
        if addr != vmop_addr:
            return

        vmop_label = f'VMOP_0x{self.vmop_slot:x}'
        if access == 'READ':
            self._vmop_cycle_value = value & 0xFF
            labels = self._adimehts.get(vmop_label, set())
            self._vmop_sources = self._vmblob_labels(labels)
            return

        labels = self._collect_read_labels(trace)
        self._write_symbol(vmop_label, labels | {vmop_label})
        vmop_value = value & 0xFF
        self._vmop_cycle_value = vmop_value
        self._vmop_sources = self._vmblob_labels(labels)
        for lbl in self._vmop_sources:
            self._annotate_fetch(lbl, f'vmop : {hex(vmop_value)}', trace.get('id'))

    def _same_explicit_operand_storage(self, trace: dict) -> bool:
        """XOR/SUB/CMP reg, reg 같은 flag 상수화 패턴인지 확인한다."""
        operands = [op for op in (trace.get('parsed_operands') or [])
                    if not op.is_implicit]
        if len(operands) < 2:
            return False
        lhs, rhs = operands[0], operands[1]
        if lhs.type != rhs.type:
            return False
        if lhs.type == OperandType.REG:
            return self._trace_reg_slice(lhs.reg_name) == self._trace_reg_slice(rhs.reg_name)
        if lhs.type == OperandType.MEM:
            lhs_addr = self._trace_mem_operand_addr(lhs, trace)
            rhs_addr = self._trace_mem_operand_addr(rhs, trace)
            return lhs_addr is not None and lhs_addr == rhs_addr
        return False

    def _flag_result_ignores_sources(self, trace: dict) -> bool:
        inst = trace.get('instruction_obj')
        if inst is None:
            return False
        mnemonic = inst.mnemonic.upper()
        if mnemonic in ('XOR', 'SUB', 'CMP') and self._same_explicit_operand_storage(trace):
            return True
        return False

    def _write_result_ignores_sources(self, trace: dict) -> bool:
        inst = trace.get('instruction_obj')
        if inst is None:
            return False
        mnemonic = inst.mnemonic.upper()
        return mnemonic in ('XOR', 'SUB') and self._same_explicit_operand_storage(trace)

    def _clear_explicit_write_symbols(self, trace: dict, handled_dsts: set[str]) -> None:
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit or op.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                continue
            if op.type == OperandType.REG:
                sym = _root_reg(op.reg_name)
                self._mark_dead_from_overwrite(self._adimehts.get(sym, set()))
                self._adimehts.pop(sym, None)
                self._element_sources.pop(sym, None)
                handled_dsts.add(sym)
                continue
            if op.type == OperandType.MEM:
                addr = self._trace_mem_operand_addr(op, trace)
                if addr is None:
                    continue
                sym = self.vb_addr_map.get(addr & 0xFFFFFFFF)
                if sym is not None:
                    self._adimehts.pop(sym, None)
                    self._element_sources.pop(sym, None)
                    handled_dsts.add(sym)

    def _annotate_conditional_branch(self, trace: dict) -> None:
        row_id = trace.get('id')
        for lbl in sorted(self._pending_branch_sources):
            self._annotate_fetch(lbl, 'conditional branch', row_id)
            self._append_comment(trace, f'=========[conditional branch by {lbl}]=========')
        for lbl in sorted(self._pending_branch_elements):
            self._append_comment(trace, f'=========[conditional branch by {lbl}]=========')
        self._remove_labels_from_symbols(self._pending_branch_sources)
        self._remove_elements_from_symbols(self._pending_branch_elements)

    def _track_decode_decision(self, trace: dict) -> None:
        inst = trace.get('instruction_obj')
        if inst is None:
            return
        mnemonic = inst.mnemonic.upper()
        if mnemonic in _FLAG_MNEMONICS:
            labels = self._collect_read_labels(trace)
            elements = self._collect_read_elements(trace)
            if self._flag_result_ignores_sources(trace):
                self._pending_branch_sources = set()
                self._pending_branch_elements = set()
            else:
                self._pending_branch_sources = self._vmblob_labels(labels)
                self._pending_branch_elements = self._vm_element_labels(elements)
            vmop_label = f'VMOP_0x{self.vmop_slot:x}' if self.vmop_slot is not None else None
            if vmop_label is not None and (vmop_label in labels or (labels & self._vmop_sources)):
                self._pending_decode_vmop = self._vmop_cycle_value
            else:
                self._pending_decode_vmop = None
            return

        if mnemonic in _JCC_MNEMONICS:
            if self._pending_branch_sources or self._pending_branch_elements:
                self._annotate_conditional_branch(trace)
                self._pending_branch_sources = set()
                self._pending_branch_elements = set()
            if self._pending_decode_vmop is not None:
                regs = trace.get('regs') or []
                flags = regs[_EFLAGS_IDX] if len(regs) > _EFLAGS_IDX else 0
                zf = (flags >> 6) & 1
                if zf == 1:
                    self._append_comment(trace, f'[decode : {hex(self._pending_decode_vmop)}]')
                self._pending_decode_vmop = None

    # =========================================================================
    # Black FISH real VI 필터
    # =========================================================================

    @staticmethod
    def _raw_reads(trace: dict) -> list[tuple[int, int]]:
        return [
            (m.get('addr', 0) & 0xFFFFFFFF, m.get('value', 0) & 0xFFFFFFFF)
            for m in (trace.get('mem') or [])
            if m.get('access') == 'READ'
        ]

    @staticmethod
    def _raw_writes(trace: dict) -> list[tuple[int, int]]:
        return [
            (m.get('addr', 0) & 0xFFFFFFFF, m.get('value', 0) & 0xFFFFFFFF)
            for m in (trace.get('mem') or [])
            if m.get('access') == 'WRITE'
        ]

    @staticmethod
    def _operand_access_name(op) -> str:
        return str(op.access).split('.')[-1]

    @staticmethod
    def _mem_base_root(op) -> str | None:
        mem = op.mem_info or {}
        base = mem.get('base')
        return _root_reg(base) if base else None

    def _label_addr(self, label: str) -> int | None:
        for addr, current in self.vb_addr_map.items():
            if current == label:
                return addr & 0xFFFFFFFF
        return None

    def _explicit_mem_infos(self, trace: dict) -> list[tuple[object, int, str | None, str]]:
        infos = []
        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit or op.type != OperandType.MEM:
                continue
            addr = self._trace_mem_operand_addr(op, trace)
            if addr is None:
                continue
            addr &= 0xFFFFFFFF
            infos.append((op, addr, self.vb_addr_map.get(addr), self._operand_access_name(op)))
        return infos

    def _reads_label(self, trace: dict, label: str) -> bool:
        for _op, _addr, current, access in self._explicit_mem_infos(trace):
            if current == label and access in {'READ', 'READ_WRITE'}:
                return True
        return False

    def _writes_label(self, trace: dict, label: str) -> bool:
        for _op, _addr, current, access in self._explicit_mem_infos(trace):
            if current == label and access in {'WRITE', 'READ_WRITE'}:
                return True
        return False

    def _has_non_esp_explicit_write(self, trace: dict, addr: int) -> bool:
        addr &= 0xFFFFFFFF
        for op, op_addr, _label, access in self._explicit_mem_infos(trace):
            if op_addr != addr or access not in {'WRITE', 'READ_WRITE'}:
                continue
            if self._mem_base_root(op) == 'ESP':
                continue
            return True
        return False

    def _has_read(self, trace: dict, addr: int, value: int | None = None) -> bool:
        addr &= 0xFFFFFFFF
        for read_addr, read_value in self._raw_reads(trace):
            if read_addr != addr:
                continue
            if value is None or read_value == (value & 0xFFFFFFFF):
                return True
        return False

    def _has_write(self, trace: dict, addr: int, value: int | None = None) -> bool:
        addr &= 0xFFFFFFFF
        for write_addr, write_value in self._raw_writes(trace):
            if write_addr != addr:
                continue
            if value is None or write_value == (value & 0xFFFFFFFF):
                return True
        return False

    def _after_reg_value(self, rows: list[dict], row_id: int, reg_name: str) -> int | None:
        if row_id + 1 >= len(rows):
            return None
        regs = rows[row_id + 1].get('regs') or []
        idx = _REG_INDEX_32.get(_root_reg(reg_name))
        if idx is None or idx >= len(regs) or regs[idx] is None:
            return None
        return regs[idx] & 0xFFFFFFFF

    @staticmethod
    def _is_black_stack_temp_addr(frame: dict, addr: int) -> bool:
        addr &= 0xFFFFFFFF
        return (frame['local_addr'] - 0x10) <= addr <= (frame['saved_ebp_addr'] + 0x10)

    def _first_stack_read(self, trace: dict, frame: dict, value: int) -> int | None:
        for read_addr, read_value in self._raw_reads(trace):
            if read_value != (value & 0xFFFFFFFF):
                continue
            if self._is_black_stack_temp_addr(frame, read_addr):
                return read_addr
        return None

    def _add_forward_materialization(
        self,
        rows: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        value: int,
        bucket: str,
        lookahead: int = 4,
    ) -> None:
        for row_id in range(seed_row + 1, min(len(rows), seed_row + lookahead + 1)):
            row = rows[row_id]
            if self._trace_mnemonic(row) not in {'MOV', 'POP'}:
                continue
            if self._first_stack_read(row, frame, value) is None:
                continue
            buckets[bucket].add(row_id)
            break

    def _find_previous_stack_store(
        self,
        rows: list[dict],
        frame: dict,
        seed_row: int,
        value: int,
        lookback: int = 6,
    ) -> int | None:
        lower = max(frame['semantic_start'] - 1, seed_row - lookback - 1)
        for row_id in range(seed_row - 1, lower, -1):
            row = rows[row_id]
            if self._trace_mnemonic(row) != 'MOV':
                continue
            writes = self._raw_writes(row)
            if not any(write_value == (value & 0xFFFFFFFF) for _addr, write_value in writes):
                continue
            if not any(self._is_black_stack_temp_addr(frame, write_addr) for write_addr, _value in writes):
                continue
            return row_id
        return None

    def _add_previous_stack_store(
        self,
        rows: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        value: int,
        bucket: str,
        lookback: int = 6,
    ) -> int | None:
        row_id = self._find_previous_stack_store(rows, frame, seed_row, value, lookback=lookback)
        if row_id is not None:
            buckets[bucket].add(row_id)
        return row_id

    def _add_next_stack_store_by_value(
        self,
        rows: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        value: int,
        bucket: str,
        lookahead: int = 8,
    ) -> int | None:
        value &= 0xFFFFFFFF
        for row_id in range(seed_row + 1, min(len(rows), seed_row + lookahead + 1)):
            row = rows[row_id]
            if self._trace_mnemonic(row) not in {'MOV', 'PUSH'}:
                continue
            for write_addr, write_value in self._raw_writes(row):
                if write_value != value:
                    continue
                if not self._is_black_stack_temp_addr(frame, write_addr):
                    continue
                buckets[bucket].add(row_id)
                return row_id
        return None

    def _add_previous_reg_writer_by_value(
        self,
        rows: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        reg_name: str,
        value: int,
        bucket: str,
        lookback: int = 240,
    ) -> int | None:
        root = _root_reg(reg_name)
        value &= 0xFFFFFFFF
        lower = max((frame.get('semantic_start') or 0) - 1, seed_row - lookback - 1)
        for row_id in range(seed_row - 1, lower, -1):
            if not self._black_row_writes_full_reg(rows[row_id], root):
                continue
            if self._after_reg_value(rows, row_id, root) != value:
                continue
            buckets[bucket].add(row_id)
            self._add_previous_stack_store(rows, buckets, frame, row_id, value, bucket, lookback=8)
            return row_id
        return None

    @staticmethod
    def _black_first_read_value_from_addr(row: dict, addr: int) -> int | None:
        addr &= 0xFFFFFFFF
        for read_addr, read_value in TraceAdimehtLightFISH._raw_reads(row):
            if read_addr == addr:
                return read_value & 0xFFFFFFFF
        return None

    def _black_arithmetic_source_values(self, row: dict) -> dict[str, int]:
        values: dict[str, int] = {}
        for reg_name in self._black_arithmetic_read_regs(row):
            values[reg_name] = self._trace_reg_value(row, reg_name) & 0xFFFFFFFF
        return values

    def _vb_labels(self) -> set[str]:
        return {label for label in self.vb_addr_map.values() if label.startswith('VB_')}

    @staticmethod
    def _top_role_scores(scores: dict[str, int], limit: int = 5) -> list[dict[str, object]]:
        ranked = [(score, label) for label, score in scores.items() if score > 0]
        ranked.sort(reverse=True)
        return [{'label': label, 'score': score} for score, label in ranked[:limit]]

    def _black_base_frame(self, rows: list[dict], activation=None) -> dict | None:
        initial_regs = rows[0].get('regs') or []
        if len(initial_regs) <= max(_REG_INDEX_32['ESP'], _REG_INDEX_32['EBP']):
            return None

        frame_base = getattr(activation, 'base', None)
        if frame_base is None:
            frame_base = (initial_regs[_REG_INDEX_32['ESP']] - 8) & 0xFFFFFFFF
        frame_base &= 0xFFFFFFFF
        return {
            'frame_base': frame_base,
            'saved_ebp_addr': frame_base,
            'local_addr': (frame_base - 4) & 0xFFFFFFFF,
            'arg1_addr': (frame_base + 8) & 0xFFFFFFFF,
            'arg2_addr': (frame_base + 0xC) & 0xFFFFFFFF,
            'post_pop_sp': (frame_base + 4) & 0xFFFFFFFF,
            'caller_ebp': initial_regs[_REG_INDEX_32['EBP']] & 0xFFFFFFFF,
            'caller_ecx': initial_regs[_REG_INDEX_32['ECX']] & 0xFFFFFFFF,
        }

    def _infer_black_stack_roles(self, rows: list[dict], frame: dict, activation=None) -> dict | None:
        """Infer black FISH vSP/vBP labels from frame setup/teardown only.

        This intentionally ignores arithmetic operands and result values so the
        stack frame carriers can be recovered independently from sample-specific
        arithmetic semantics.
        """
        labels = self._vb_labels()
        if not labels:
            return None

        vbp_scores: dict[str, int] = collections.defaultdict(int)
        vsp_scores: dict[str, int] = collections.defaultdict(int)

        activation_vsp = getattr(activation, 'vsp_label', None)
        if activation_vsp in labels:
            vsp_scores[activation_vsp] += 80

        for row in rows:
            mn = self._trace_mnemonic(row)
            for _op, addr, label, access in self._explicit_mem_infos(row):
                if label not in labels:
                    continue
                reads = access in {'READ', 'READ_WRITE'}
                writes = access in {'WRITE', 'READ_WRITE'}

                if reads:
                    if self._has_read(row, addr, frame['caller_ebp']):
                        vbp_scores[label] += 12
                        if mn == 'PUSH' and self._has_write(row, frame['saved_ebp_addr'], frame['caller_ebp']):
                            vbp_scores[label] += 120
                    if self._has_read(row, addr, frame['frame_base']):
                        vbp_scores[label] += 12

                if writes:
                    if self._has_write(row, addr, frame['frame_base']):
                        vbp_scores[label] += 45
                        vsp_scores[label] += 35
                    if self._has_write(row, addr, frame['caller_ebp']):
                        vbp_scores[label] += 35
                        if self._has_read(row, frame['saved_ebp_addr'], frame['caller_ebp']):
                            vbp_scores[label] += 95
                    if self._has_write(row, addr, frame['local_addr']):
                        vsp_scores[label] += 45
                    if self._has_write(row, addr, frame['post_pop_sp']):
                        vsp_scores[label] += 65

        def best(scores: dict[str, int], *, exclude: set[str] | None = None, minimum: int = 1) -> str | None:
            exclude = exclude or set()
            ranked = [(score, label) for label, score in scores.items() if score >= minimum and label not in exclude]
            if not ranked:
                return None
            ranked.sort(reverse=True)
            return ranked[0][1]

        vbp_label = best(vbp_scores, minimum=80)
        vsp_label = best(vsp_scores, exclude={vbp_label} if vbp_label else set(), minimum=60)
        if not (vbp_label and vsp_label):
            return None

        vbp_addr = self._label_addr(vbp_label) or 0
        vsp_addr = self._label_addr(vsp_label) or 0

        semantic_start = None
        for row_id, row in enumerate(rows):
            if self._trace_mnemonic(row) != 'PUSH':
                continue
            if not self._reads_label(row, vbp_label):
                continue
            if (
                self._has_read(row, vbp_addr, frame['caller_ebp'])
                and self._has_write(row, frame['saved_ebp_addr'], frame['caller_ebp'])
            ):
                semantic_start = row_id
                break

        bp_set_row = None
        search_start = semantic_start if semantic_start is not None else 0
        for row_id in range(search_start, len(rows)):
            row = rows[row_id]
            if not self._writes_label(row, vbp_label):
                continue
            if self._has_write(row, vbp_addr, frame['frame_base']):
                bp_set_row = row_id
                break

        if semantic_start is None and bp_set_row is not None:
            saved_write_row = None
            for row_id in range(bp_set_row):
                if self._has_write(rows[row_id], frame['saved_ebp_addr'], frame['caller_ebp']):
                    saved_write_row = row_id
                    break
            if saved_write_row is not None:
                semantic_start = saved_write_row
                lower = max(0, saved_write_row - 96)
                for row_id in range(saved_write_row, lower - 1, -1):
                    row = rows[row_id]
                    if (
                        self._trace_mnemonic(row) == 'PUSH'
                        and self._reads_label(row, vbp_label)
                        and self._has_read(row, vbp_addr, frame['caller_ebp'])
                    ):
                        semantic_start = row_id
                        break

        semantic_end = None
        for row_id in range(len(rows) - 1, search_start - 1, -1):
            row = rows[row_id]
            if (
                self._writes_label(row, vsp_label)
                and self._has_write(row, vsp_addr, frame['post_pop_sp'])
            ):
                semantic_end = row_id
                break

        return {
            'vbp_label': vbp_label,
            'vsp_label': vsp_label,
            'vbp_addr': vbp_addr,
            'vsp_addr': vsp_addr,
            'semantic_start': semantic_start,
            'bp_set_row': bp_set_row,
            'semantic_end': semantic_end,
            'role_scores': {
                'vbp': dict(vbp_scores),
                'vsp': dict(vsp_scores),
            },
            'top_scores': {
                'vbp': self._top_role_scores(vbp_scores),
                'vsp': self._top_role_scores(vsp_scores),
            },
        }

    @staticmethod
    def _add_black_stack_role_markers(issue_mark_rows: dict[str, set[int]], role_rows: dict) -> None:
        for key, marker in (
            ('semantic_start', '[fish-vbp]'),
            ('bp_set_row', '[fish-vbp]'),
            ('semantic_end', '[fish-vsp]'),
        ):
            row_id = role_rows.get(key)
            if isinstance(row_id, int):
                issue_mark_rows[marker].add(row_id)

    @staticmethod
    def _build_black_stack_stats(frame: dict, roles: dict) -> dict:
        return {
            'roles': {
                'vbp_label': roles['vbp_label'],
                'vsp_label': roles['vsp_label'],
            },
            'addresses': {
                'vbp_addr': roles['vbp_addr'],
                'vsp_addr': roles['vsp_addr'],
            },
            'frame': {
                key: frame[key]
                for key in ('frame_base', 'saved_ebp_addr', 'local_addr', 'post_pop_sp', 'caller_ebp')
            },
            'rows': {
                key: roles.get(key)
                for key in ('semantic_start', 'bp_set_row', 'semantic_end')
            },
            'top_scores': roles['top_scores'],
        }

    def _detect_black_stack_stats(self, rows: list[dict], activation=None) -> dict | None:
        frame = self._black_base_frame(rows, activation)
        if frame is None:
            return None
        roles = self._infer_black_stack_roles(rows, frame, activation=activation)
        if roles is None:
            return None
        return self._build_black_stack_stats(frame, roles)

    @staticmethod
    def _print_black_stack_stats(stats: dict) -> None:
        roles = stats['roles']
        addrs = stats['addresses']
        role_rows = stats['rows']
        print(
            f"[LightFISH] black stack roles: "
            f"vBP={roles['vbp_label']}@{hex(addrs['vbp_addr'])} "
            f"vSP={roles['vsp_label']}@{hex(addrs['vsp_addr'])} "
            f"rows={role_rows}"
        )

    @staticmethod
    def _black_taint_read_mem(mem_taint: dict[int, set[str]], addr: int, size: int) -> set[str]:
        labels: set[str] = set()
        for offset in range(max(size, 1)):
            labels |= mem_taint.get((addr + offset) & 0xFFFFFFFF, set())
        return labels

    @staticmethod
    def _black_taint_write_mem(mem_taint: dict[int, set[str]], addr: int, size: int, labels: set[str]) -> None:
        for offset in range(max(size, 1)):
            byte_addr = (addr + offset) & 0xFFFFFFFF
            if labels:
                mem_taint[byte_addr] = set(labels)
            else:
                mem_taint.pop(byte_addr, None)

    @staticmethod
    def _black_taint_set_reg(reg_taint: dict[str, set[str]], reg_name: str, labels: set[str]) -> None:
        root = _root_reg(reg_name)
        if labels:
            reg_taint[root] = set(labels)
        else:
            reg_taint.pop(root, None)

    @staticmethod
    def _black_labels_have(labels: set[str], *wanted: str) -> bool:
        return set(wanted).issubset(labels)

    def _black_operand_addr_taint(self, op, reg_taint: dict[str, set[str]]) -> set[str]:
        if op.type != OperandType.MEM:
            return set()
        labels: set[str] = set()
        mem = op.mem_info or {}
        for reg_key in ('base', 'index'):
            reg_name = mem.get(reg_key)
            if reg_name:
                labels |= reg_taint.get(_root_reg(reg_name), set())
        return labels

    def _black_operand_value_taint(
        self,
        op,
        row: dict,
        reg_taint: dict[str, set[str]],
        mem_taint: dict[int, set[str]],
    ) -> set[str]:
        if op.type == OperandType.REG:
            root = _root_reg(op.reg_name)
            if root == 'ESP':
                return set()
            return set(reg_taint.get(root, set()))
        if op.type == OperandType.MEM:
            addr = self._trace_mem_operand_addr(op, row)
            if addr is None:
                return set()
            return self._black_taint_read_mem(mem_taint, addr, op.size)
        return set()

    def _black_read_taint(
        self,
        row: dict,
        reg_taint: dict[str, set[str]],
        mem_taint: dict[int, set[str]],
    ) -> set[str]:
        inst = row.get('instruction_obj')
        mnemonic = inst.mnemonic.upper() if inst else self._trace_mnemonic(row)
        operands = row.get('parsed_operands') or []
        explicit = [op for op in operands if not op.is_implicit]

        if mnemonic in {'XOR', 'SUB'} and self._same_explicit_operand_storage(row):
            return set()

        if mnemonic == 'LEA' and len(explicit) >= 2 and explicit[1].type == OperandType.MEM:
            return self._black_operand_addr_taint(explicit[1], reg_taint)

        if mnemonic in {'DIV', 'IDIV'}:
            labels = set(reg_taint.get('EAX', set())) | set(reg_taint.get('EDX', set()))
            labels |= self._black_explicit_read_taint(row, reg_taint, mem_taint)
            return labels

        if mnemonic == 'MUL' or (mnemonic == 'IMUL' and len(explicit) == 1):
            labels = set(reg_taint.get('EAX', set()))
            labels |= self._black_explicit_read_taint(row, reg_taint, mem_taint)
            return labels

        if mnemonic in {'CDQ', 'CWD', 'CWDE', 'CDQE'}:
            return set(reg_taint.get('EAX', set()))

        return self._black_all_read_taint(row, reg_taint, mem_taint)

    def _black_explicit_read_taint(
        self,
        row: dict,
        reg_taint: dict[str, set[str]],
        mem_taint: dict[int, set[str]],
    ) -> set[str]:
        labels: set[str] = set()
        for op in row.get('parsed_operands') or []:
            if op.is_implicit or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                continue
            labels |= self._black_operand_value_taint(op, row, reg_taint, mem_taint)
        return labels

    def _black_all_read_taint(
        self,
        row: dict,
        reg_taint: dict[str, set[str]],
        mem_taint: dict[int, set[str]],
    ) -> set[str]:
        labels: set[str] = set()
        for op in row.get('parsed_operands') or []:
            if op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                continue
            labels |= self._black_operand_value_taint(op, row, reg_taint, mem_taint)
        return labels

    def _black_taint_replay(
        self,
        rows: list[dict],
        frame: dict,
        replay_end: int | None = None,
    ) -> list[dict]:
        reg_taint: dict[str, set[str]] = {}
        mem_taint: dict[int, set[str]] = {}
        self._black_taint_write_mem(mem_taint, frame['arg1_addr'], 4, {'arg_1'})
        self._black_taint_write_mem(mem_taint, frame['arg2_addr'], 4, {'arg_2'})

        records: list[dict] = [
            {
                'read_labels': set(),
                'mem_reads': [],
                'mem_writes': [],
                'reg_writes': [],
                'vb_reads': [],
                'vb_writes': [],
            }
            for _row in rows
        ]

        start = max(0, frame.get('semantic_start') or 0)
        end = min(len(rows) - 1, replay_end if replay_end is not None else len(rows) - 1)
        for row_id in range(start, end + 1):
            row = rows[row_id]
            inst = row.get('instruction_obj')
            mnemonic = inst.mnemonic.upper() if inst else self._trace_mnemonic(row)
            operands = row.get('parsed_operands') or []
            explicit = [op for op in operands if not op.is_implicit]
            record = records[row_id]

            for op in operands:
                if op.type != OperandType.MEM or op.access not in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    continue
                addr = self._trace_mem_operand_addr(op, row)
                if addr is None:
                    continue
                labels = self._black_taint_read_mem(mem_taint, addr, op.size)
                record['mem_reads'].append((addr & 0xFFFFFFFF, set(labels)))
                vb_label = self.vb_addr_map.get(addr & 0xFFFFFFFF)
                if vb_label is not None and labels:
                    record['vb_reads'].append((vb_label, set(labels)))

            read_labels = self._black_read_taint(row, reg_taint, mem_taint)
            record['read_labels'] = set(read_labels)

            if mnemonic in {'CMP', 'TEST'}:
                continue

            if mnemonic == 'XCHG' and len(explicit) >= 2:
                left, right = explicit[0], explicit[1]
                left_labels = self._black_operand_value_taint(left, row, reg_taint, mem_taint)
                right_labels = self._black_operand_value_taint(right, row, reg_taint, mem_taint)
                self._black_write_operand_taint(row, left, right_labels, reg_taint, mem_taint, record)
                self._black_write_operand_taint(row, right, left_labels, reg_taint, mem_taint, record)
                continue

            manual_reg_writes: list[str] = []
            if mnemonic in {'DIV', 'IDIV', 'MUL'} or (mnemonic == 'IMUL' and len(explicit) == 1):
                manual_reg_writes = ['EAX', 'EDX']
            elif mnemonic in {'CDQ', 'CWD'}:
                manual_reg_writes = ['EDX']
            elif mnemonic in {'CWDE', 'CDQE'}:
                manual_reg_writes = ['EAX']

            if manual_reg_writes:
                for reg_name in manual_reg_writes:
                    self._black_taint_set_reg(reg_taint, reg_name, read_labels)
                    record['reg_writes'].append((_root_reg(reg_name), set(read_labels)))
                continue

            for op in operands:
                if op.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                    continue
                self._black_write_operand_taint(row, op, read_labels, reg_taint, mem_taint, record)

        return records

    def _black_write_operand_taint(
        self,
        row: dict,
        op,
        labels: set[str],
        reg_taint: dict[str, set[str]],
        mem_taint: dict[int, set[str]],
        record: dict,
    ) -> None:
        if op.type == OperandType.REG:
            root = _root_reg(op.reg_name)
            if root == 'ESP':
                self._black_taint_set_reg(reg_taint, root, set())
                return
            self._black_taint_set_reg(reg_taint, root, labels)
            record['reg_writes'].append((root, set(labels)))
            return
        if op.type != OperandType.MEM:
            return
        addr = self._trace_mem_operand_addr(op, row)
        if addr is None:
            return
        addr &= 0xFFFFFFFF
        self._black_taint_write_mem(mem_taint, addr, op.size, labels)
        record['mem_writes'].append((addr, set(labels)))
        vb_label = self.vb_addr_map.get(addr)
        if vb_label is not None and labels:
            record['vb_writes'].append((vb_label, set(labels)))

    @staticmethod
    def _black_record_writes_labels(record: dict, labels: set[str], *, reg_only: bool = False) -> bool:
        writes = list(record.get('reg_writes') or [])
        if not reg_only:
            writes.extend(record.get('mem_writes') or [])
        return any(labels.issubset(set(write_labels)) for _target, write_labels in writes)

    @staticmethod
    def _black_record_reads_addr_label(record: dict, addr: int, label: str) -> bool:
        addr &= 0xFFFFFFFF
        return any(
            read_addr == addr and label in set(labels)
            for read_addr, labels in record.get('mem_reads') or []
        )

    @staticmethod
    def _black_record_writes_addr_labels(record: dict, addr: int, labels: set[str]) -> bool:
        addr &= 0xFFFFFFFF
        return any(
            write_addr == addr and labels.issubset(set(write_labels))
            for write_addr, write_labels in record.get('mem_writes') or []
        )

    @staticmethod
    def _black_record_writes_reg_labels(record: dict, reg_name: str, labels: set[str]) -> bool:
        root = _root_reg(reg_name)
        return any(
            write_reg == root and labels.issubset(set(write_labels))
            for write_reg, write_labels in record.get('reg_writes') or []
        )

    @staticmethod
    def _black_record_any_reg_write_labels(record: dict, reg_name: str) -> set[str]:
        root = _root_reg(reg_name)
        labels: set[str] = set()
        for write_reg, write_labels in record.get('reg_writes') or []:
            if write_reg == root:
                labels |= set(write_labels)
        return labels

    @staticmethod
    def _black_first_write_value(trace: dict, addr: int) -> int | None:
        addr &= 0xFFFFFFFF
        for write_addr, write_value in TraceAdimehtLightFISH._raw_writes(trace):
            if write_addr == addr:
                return write_value
        return None

    @staticmethod
    def _black_first_read_value(trace: dict, addr: int) -> int | None:
        addr &= 0xFFFFFFFF
        for read_addr, read_value in TraceAdimehtLightFISH._raw_reads(trace):
            if read_addr == addr:
                return read_value
        return None

    def _add_tainted_forward_materialization(
        self,
        rows: list[dict],
        records: list[dict],
        buckets: dict[str, set[int]],
        seed_row: int,
        labels: set[str],
        bucket: str,
        lookahead: int = 4,
    ) -> int | None:
        for row_id in range(seed_row + 1, min(len(rows), seed_row + lookahead + 1)):
            row = rows[row_id]
            if self._trace_mnemonic(row) not in {'MOV', 'POP'}:
                continue
            record = records[row_id]
            if not labels.issubset(set(record.get('read_labels') or set())):
                continue
            if not self._black_record_writes_labels(record, labels, reg_only=True):
                continue
            buckets[bucket].add(row_id)
            return row_id
        return None

    def _add_previous_tainted_stack_store(
        self,
        rows: list[dict],
        records: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        labels: set[str],
        bucket: str,
        lookback: int = 8,
    ) -> int | None:
        lower = max((frame.get('semantic_start') or 0) - 1, seed_row - lookback - 1)
        for row_id in range(seed_row - 1, lower, -1):
            if self._trace_mnemonic(rows[row_id]) != 'MOV':
                continue
            for write_addr, write_labels in records[row_id].get('mem_writes') or []:
                if not labels.issubset(set(write_labels)):
                    continue
                if not self._is_black_stack_temp_addr(frame, write_addr):
                    continue
                buckets[bucket].add(row_id)
                return row_id
        return None

    def _add_tainted_reg_writer_before(
        self,
        rows: list[dict],
        records: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        seed_row: int,
        reg_name: str,
        labels: set[str],
        bucket: str,
        lookback: int = 160,
    ) -> int | None:
        lower = max((frame.get('semantic_start') or 0) - 1, seed_row - lookback - 1)
        root = _root_reg(reg_name)
        for row_id in range(seed_row - 1, lower, -1):
            if not self._black_record_writes_reg_labels(records[row_id], root, labels):
                continue
            if not self._black_row_writes_full_reg(rows[row_id], root):
                continue
            buckets[bucket].add(row_id)
            self._add_previous_tainted_stack_store(
                rows, records, buckets, frame, row_id, labels, bucket, lookback=8
            )
            return row_id
        return None

    def _black_arithmetic_output_value(self, rows: list[dict], row_id: int) -> int | None:
        row = rows[row_id]
        mnemonic = self._trace_mnemonic(row)
        operands = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]

        if mnemonic in {'DIV', 'IDIV', 'MUL'} or (mnemonic == 'IMUL' and len(operands) == 1):
            return self._after_reg_value(rows, row_id, 'EAX')

        if not operands or operands[0].type != OperandType.REG:
            return None
        return self._after_reg_value(rows, row_id, operands[0].reg_name)

    def _black_reads_vm_slot_operand(self, row: dict) -> bool:
        for op, _addr, label, access in self._explicit_mem_infos(row):
            if label is not None and access in {'READ', 'READ_WRITE'}:
                return True
        return False

    def _black_reads_plain_vb_operand(self, row: dict, *, exclude: set[str] | None = None) -> bool:
        exclude = exclude or set()
        for _op, _addr, label, access in self._explicit_mem_infos(row):
            if label in exclude or not (label or '').startswith('VB_'):
                continue
            if access in {'READ', 'READ_WRITE'}:
                return True
        return False

    @staticmethod
    def _black_row_writes_full_reg(row: dict, reg_name: str) -> bool:
        root = _root_reg(reg_name)
        for op in row.get('parsed_operands') or []:
            if op.type != OperandType.REG or op.access not in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                continue
            if _root_reg(op.reg_name) == root and op.size >= 4:
                return True
        return False

    def _black_arithmetic_read_regs(self, row: dict) -> set[str]:
        mnemonic = self._trace_mnemonic(row)
        operands = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]
        regs: set[str] = set()

        if mnemonic in {'DIV', 'IDIV'}:
            for op in operands:
                if op.type == OperandType.REG and op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    regs.add(_root_reg(op.reg_name))
            return regs
        elif mnemonic == 'MUL' or (mnemonic == 'IMUL' and len(operands) == 1):
            for op in operands:
                if op.type == OperandType.REG and op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    regs.add(_root_reg(op.reg_name))
            return regs

        if mnemonic in {'ADD', 'SUB', 'IMUL'} and len(operands) >= 2:
            for op in operands:
                if op.type == OperandType.REG and op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    regs.add(_root_reg(op.reg_name))
            return regs

        for op in operands:
            if op.type == OperandType.REG and op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                regs.add(_root_reg(op.reg_name))
        return regs

    def _add_black_arithmetic_materialization(
        self,
        rows: list[dict],
        records: list[dict],
        buckets: dict[str, set[int]],
        frame: dict,
        arithmetic_row: int,
    ) -> None:
        for reg_name in self._black_arithmetic_read_regs(rows[arithmetic_row]):
            for labels in ({'arg_1'}, {'arg_2'}, {'arg_1', 'arg_2'}):
                self._add_tainted_reg_writer_before(
                    rows, records, buckets, frame, arithmetic_row, reg_name, labels, 'semantic_core'
                )

    def _black_taint_role_stats(self, records: list[dict]) -> dict:
        role_scores: dict[str, collections.Counter] = {
            'arg1': collections.Counter(),
            'arg2': collections.Counter(),
            'result': collections.Counter(),
        }
        for record in records:
            for label, labels in record.get('vb_writes') or []:
                label_set = set(labels)
                if label_set == {'arg_1'}:
                    role_scores['arg1'][label] += 8
                if label_set == {'arg_2'}:
                    role_scores['arg2'][label] += 8
                if {'arg_1', 'arg_2'}.issubset(label_set):
                    role_scores['result'][label] += 12
            for label, labels in record.get('vb_reads') or []:
                label_set = set(labels)
                if label_set == {'arg_1'}:
                    role_scores['arg1'][label] += 3
                if label_set == {'arg_2'}:
                    role_scores['arg2'][label] += 3
                if {'arg_1', 'arg_2'}.issubset(label_set):
                    role_scores['result'][label] += 5

        def best(counter: collections.Counter) -> str | None:
            return counter.most_common(1)[0][0] if counter else None

        return {
            'arg1_label': best(role_scores['arg1']),
            'arg2_label': best(role_scores['arg2']),
            'result_label': best(role_scores['result']),
            'top_scores': {
                key: [{'label': label, 'score': score} for label, score in counter.most_common(5)]
                for key, counter in role_scores.items()
            },
        }

    def _black_reverse_storage_for_addr(self, addr: int) -> str:
        addr &= 0xFFFFFFFF
        label = self.vb_addr_map.get(addr)
        if label:
            return f'vm:{label}'
        return f'mem:{addr:08x}'

    @staticmethod
    def _black_reverse_reg_storage(reg_name: str | None) -> str:
        return f'reg:{_root_reg(reg_name or "")}'

    def _black_reverse_row_access(self, row: dict) -> dict[str, set[str]]:
        reads: set[str] = set()
        writes: set[str] = set()

        for addr, _value in self._raw_reads(row):
            reads.add(self._black_reverse_storage_for_addr(addr))
        for addr, _value in self._raw_writes(row):
            writes.add(self._black_reverse_storage_for_addr(addr))

        for op in row.get('parsed_operands') or []:
            if op.type == OperandType.REG:
                key = self._black_reverse_reg_storage(op.reg_name)
                if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                    reads.add(key)
                if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                    writes.add(key)
                continue

            if op.type != OperandType.MEM:
                continue

            addr = self._trace_mem_operand_addr(op, row)
            if addr is None:
                continue
            label = self.vb_addr_map.get(addr & 0xFFFFFFFF)

            # For concrete host/guest boundary memory, keep effective-address
            # dependencies.  For VM slots, avoid pulling VBR-relative helper
            # registers into every reverse slice.
            if label is None:
                mem = op.mem_info or {}
                for reg_key in ('base', 'index'):
                    reg_name = mem.get(reg_key)
                    if reg_name:
                        reads.add(self._black_reverse_reg_storage(reg_name))

            key = self._black_reverse_storage_for_addr(addr)
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                reads.add(key)
            if op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                writes.add(key)

        mnemonic = self._trace_mnemonic(row)
        if mnemonic in {'CDQ', 'CWD'}:
            reads.add('reg:EAX')
            writes.add('reg:EDX')
        elif mnemonic in {'DIV', 'IDIV'}:
            reads.update({'reg:EAX', 'reg:EDX'})
            writes.update({'reg:EAX', 'reg:EDX'})
        elif mnemonic == 'MUL':
            reads.add('reg:EAX')
            writes.update({'reg:EAX', 'reg:EDX'})
        elif mnemonic == 'IMUL':
            explicit = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]
            if len(explicit) == 1:
                reads.add('reg:EAX')
                writes.update({'reg:EAX', 'reg:EDX'})

        return {'reads': reads, 'writes': writes}

    @staticmethod
    def _black_reverse_slice(accesses: list[dict[str, set[str]]], start: int, sink_row: int) -> set[int]:
        needed = set(accesses[sink_row]['reads'])
        selected = {sink_row}
        for row_id in range(sink_row - 1, max(start, 0) - 1, -1):
            hit = needed & accesses[row_id]['writes']
            if not hit:
                continue
            selected.add(row_id)
            needed -= hit
            needed |= accesses[row_id]['reads']
        return selected

    def _select_black_prescanned_real_vi_rows(self, rows: list[dict], activation=None) -> dict | None:
        base_frame = self._black_base_frame(rows, activation)
        if base_frame is None:
            return None
        stack_roles = self._infer_black_stack_roles(rows, base_frame, activation=activation)
        if stack_roles is None or stack_roles.get('semantic_start') is None:
            return None

        semantic_end = stack_roles.get('semantic_end')
        activation_end = getattr(activation, 'end_row', None)
        if semantic_end is None:
            semantic_end = activation_end
        if semantic_end is None:
            semantic_end = len(rows) - 1

        frame = {
            **base_frame,
            'vbp_label': stack_roles['vbp_label'],
            'vsp_label': stack_roles['vsp_label'],
            'vbp_addr': stack_roles['vbp_addr'],
            'vsp_addr': stack_roles['vsp_addr'],
            'semantic_start': stack_roles['semantic_start'],
            'bp_set_row': stack_roles.get('bp_set_row'),
            'semantic_end': min(semantic_end, len(rows) - 1),
            'semantic_end_inferred': stack_roles.get('semantic_end'),
            'taint_top_scores': stack_roles.get('top_scores'),
        }

        buckets: dict[str, set[int]] = collections.defaultdict(set)
        sinks: dict[str, set[int]] = collections.defaultdict(set)
        start = frame['semantic_start']
        end = frame['semantic_end']

        def add(bucket: str, row_id: int | None, *, sink: bool = False) -> None:
            if not isinstance(row_id, int) or not (0 <= row_id < len(rows)):
                return
            buckets[bucket].add(row_id)
            if sink:
                sinks[bucket].add(row_id)

        add('context', start, sink=True)
        add('context', frame.get('bp_set_row'), sink=True)
        add('context', frame.get('semantic_end_inferred'), sink=True)

        local_save_row = None
        zero_row = None
        first_arg1_row = None
        first_arg2_row = None
        arg1_value = None
        arg2_value = None
        result_store_row = None
        result_store_value = None
        result_read_row = None
        result_arith_candidates: list[int] = []
        local_result_candidates: list[tuple[int, int]] = []

        for row_id in range(start, end + 1):
            row = rows[row_id]
            mnemonic = self._trace_mnemonic(row)

            if self._writes_label(row, frame['vbp_label']):
                if self._has_write(row, frame['vbp_addr'], frame['frame_base']):
                    add('context', row_id, sink=True)
                elif (
                    self._has_write(row, frame['vbp_addr'], frame['caller_ebp'])
                    and self._has_read(row, frame['saved_ebp_addr'], frame['caller_ebp'])
                ):
                    add('context', row_id, sink=True)

            if self._writes_label(row, frame['vsp_label']):
                if self._has_write(row, frame['vsp_addr'], frame['local_addr']):
                    add('context', row_id, sink=True)
                elif self._has_write(row, frame['vsp_addr'], frame['post_pop_sp']):
                    add('context', row_id, sink=True)

            if (
                self._has_write(row, frame['local_addr'], 0)
                and self._has_non_esp_explicit_write(row, frame['local_addr'])
            ):
                add('boundary', row_id, sink=True)
                if zero_row is None:
                    zero_row = row_id

            local_write_value = self._black_first_write_value(row, frame['local_addr'])
            if (
                local_save_row is None
                and local_write_value is not None
                and local_write_value != 0
                and local_write_value == frame.get('caller_ecx')
                and frame.get('bp_set_row') is not None
                and row_id > frame['bp_set_row']
                and (zero_row is None or row_id < zero_row)
                and self._black_reads_plain_vb_operand(row, exclude={frame['vbp_label'], frame['vsp_label']})
            ):
                add('context', row_id, sink=True)
                local_save_row = row_id

            read_arg1 = self._black_first_read_value_from_addr(row, frame['arg1_addr'])
            if first_arg1_row is None and read_arg1 is not None:
                first_arg1_row = row_id
                arg1_value = read_arg1
                add('boundary', row_id, sink=True)
                self._add_forward_materialization(rows, buckets, frame, row_id, read_arg1, 'boundary')
                self._add_next_stack_store_by_value(rows, buckets, frame, row_id, read_arg1, 'boundary')

            read_arg2 = self._black_first_read_value_from_addr(row, frame['arg2_addr'])
            if first_arg2_row is None and read_arg2 is not None:
                first_arg2_row = row_id
                arg2_value = read_arg2
                add('boundary', row_id, sink=True)
                self._add_forward_materialization(rows, buckets, frame, row_id, read_arg2, 'boundary')
                self._add_next_stack_store_by_value(rows, buckets, frame, row_id, read_arg2, 'boundary')

            if (
                mnemonic in {'ADD', 'SUB', 'IMUL', 'MUL', 'DIV', 'IDIV'}
                and not self._black_reads_vm_slot_operand(row)
            ):
                result_arith_candidates.append(row_id)

            arg_ready_values = [value for value in (first_arg1_row, first_arg2_row) if value is not None]
            if (
                len(arg_ready_values) == 2
                and row_id > max(arg_ready_values)
                and local_write_value is not None
                and self._has_non_esp_explicit_write(row, frame['local_addr'])
            ):
                local_result_candidates.append((row_id, local_write_value & 0xFFFFFFFF))

        for candidate_row, candidate_value in local_result_candidates:
            for row_id in range(candidate_row + 1, end + 1):
                row = rows[row_id]
                if not self._has_read(row, frame['local_addr'], candidate_value):
                    continue
                if self._has_write(row, frame['local_addr']):
                    continue
                result_store_row = candidate_row
                result_store_value = candidate_value
                result_read_row = row_id
                break
            if result_store_row is not None:
                break
        if result_store_row is None and local_result_candidates:
            result_store_row, result_store_value = local_result_candidates[-1]

        if result_store_row is not None and result_store_value is not None:
            add('result', result_store_row, sink=True)
            self._add_previous_stack_store(
                rows, buckets, frame, result_store_row, result_store_value, 'result', lookback=16
            )
        if result_read_row is not None and result_store_value is not None:
            add('result', result_read_row, sink=True)
            self._add_forward_materialization(rows, buckets, frame, result_read_row, result_store_value, 'result')

        arithmetic_row = None
        if first_arg1_row is not None and first_arg2_row is not None:
            arg_ready_row = max(first_arg1_row, first_arg2_row)
            arithmetic_limit = min(
                value
                for value in (result_store_row, result_read_row, end)
                if value is not None and value >= arg_ready_row
            )
            div_arithmetic_rows = [
                row_id
                for row_id in result_arith_candidates
                if arg_ready_row <= row_id <= arithmetic_limit
                and self._trace_mnemonic(rows[row_id]) in {'DIV', 'IDIV'}
                and any(read_addr == frame['arg2_addr'] for read_addr, _value in self._raw_reads(rows[row_id]))
            ]
            matching_arithmetic_rows = [
                row_id
                for row_id in result_arith_candidates
                if arg_ready_row <= row_id <= arithmetic_limit
                and (
                    result_store_value is None
                    or self._black_arithmetic_output_value(rows, row_id) == result_store_value
                )
            ]
            if not matching_arithmetic_rows:
                semantic_values = {value for value in (arg1_value, arg2_value, result_store_value) if value is not None}
                matching_arithmetic_rows = [
                    row_id
                    for row_id in result_arith_candidates
                    if arg_ready_row <= row_id <= arithmetic_limit
                    and bool(set(self._black_arithmetic_source_values(rows[row_id]).values()) & semantic_values)
                ]
            if div_arithmetic_rows:
                arithmetic_row = div_arithmetic_rows[0]
            else:
                arithmetic_row = matching_arithmetic_rows[0] if matching_arithmetic_rows else None

        if arithmetic_row is not None:
            add('arithmetic', arithmetic_row, sink=True)
            source_values = self._black_arithmetic_source_values(rows[arithmetic_row])
            for reg_name, value in source_values.items():
                if value in {arg1_value, arg2_value, result_store_value}:
                    self._add_previous_reg_writer_by_value(
                        rows, buckets, frame, arithmetic_row, reg_name, value, 'arithmetic'
                    )
            if self._trace_mnemonic(rows[arithmetic_row]) in {'DIV', 'IDIV'}:
                cdq_search_start = first_arg1_row if first_arg1_row is not None else start
                cdq_rows = [
                    row_id
                    for row_id in range(cdq_search_start, arithmetic_row)
                    if self._trace_mnemonic(rows[row_id]) in {'CDQ', 'CWD'}
                ]
                if cdq_rows:
                    add('arithmetic', cdq_rows[-1], sink=True)

        if result_read_row is not None:
            restore_vsp_row = None
            for row_id in range(result_read_row + 1, end + 1):
                row = rows[row_id]
                if not (
                    self._writes_label(row, frame['vsp_label'])
                    and self._has_write(row, frame['vsp_addr'], frame['frame_base'])
                ):
                    continue
                add('context', row_id, sink=True)
                self._add_previous_stack_store(rows, buckets, frame, row_id, frame['frame_base'], 'context')
                restore_vsp_row = row_id
                break

            for row_id in range(result_read_row + 1, end + 1):
                row = rows[row_id]
                if not (
                    self._trace_mnemonic(row) == 'PUSH'
                    and self._reads_label(row, frame['vbp_label'])
                    and self._has_read(row, frame['vbp_addr'], frame['frame_base'])
                ):
                    continue
                add('context', row_id, sink=True)
                if restore_vsp_row is not None and row_id < restore_vsp_row:
                    self._add_forward_materialization(rows, buckets, frame, row_id, frame['frame_base'], 'context')
                break

        if result_store_value is not None:
            result_search_start = max(
                value
                for value in (end + 1, result_read_row or 0, result_store_row or 0)
                if value is not None
            )
            native_seed_row = None
            for row_id in range(result_search_start, len(rows)):
                row = rows[row_id]
                if self._trace_mnemonic(row) != 'PUSH':
                    continue
                if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                    continue
                add('native', row_id, sink=True)
                native_seed_row = row_id
                self._add_forward_materialization(rows, buckets, frame, row_id, result_store_value, 'native', lookahead=8)
                break

            native_exit_row = None
            for wanted_mnemonic in ('MOV', 'POP'):
                for row_id in range(result_search_start, len(rows)):
                    row = rows[row_id]
                    if self._trace_mnemonic(row) != wanted_mnemonic:
                        continue
                    ops = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]
                    if not ops or ops[0].type != OperandType.REG or _root_reg(ops[0].reg_name) != 'EAX':
                        continue
                    if wanted_mnemonic == 'MOV' and len(ops) < 2:
                        continue
                    if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                        continue
                    if self._after_reg_value(rows, row_id, 'EAX') != result_store_value:
                        continue
                    native_exit_row = row_id
                    add('native', row_id, sink=True)
                    break
                if native_exit_row is not None:
                    break

            if native_exit_row is not None:
                for row_id in range(native_exit_row + 1, min(len(rows), native_exit_row + 16)):
                    if not self._black_row_writes_full_reg(rows[row_id], 'EAX'):
                        continue
                    if self._after_reg_value(rows, row_id, 'EAX') != result_store_value:
                        continue
                    add('native', row_id, sink=True)
                    break
            elif native_seed_row is not None:
                for row_id in range(native_seed_row + 1, min(len(rows), native_seed_row + 16)):
                    if not self._black_row_writes_full_reg(rows[row_id], 'EAX'):
                        continue
                    if self._after_reg_value(rows, row_id, 'EAX') != result_store_value:
                        continue
                    add('native', row_id, sink=True)
                    break

        selected: set[int] = set()
        for row_ids in buckets.values():
            selected.update(row_ids)
        if not selected:
            return None

        return {
            'frame': {
                **frame,
                'arg1_label': None,
                'arg2_label': None,
                'result_label': None,
                'local_save_row': local_save_row,
                'zero_row': zero_row,
                'first_arg1_row': first_arg1_row,
                'first_arg2_row': first_arg2_row,
                'arg1_value': arg1_value,
                'arg2_value': arg2_value,
                'result_store_row': result_store_row,
                'result_store_value': result_store_value,
                'result_read_row': result_read_row,
                'arithmetic_row': arithmetic_row,
                'reverse_candidate_count': 0,
            },
            'buckets': {bucket: set(row_ids) for bucket, row_ids in buckets.items()},
            'sinks': {bucket: set(row_ids) for bucket, row_ids in sinks.items()},
            'reverse_candidates': set(),
            'rows': selected,
            'mode': 'raw-prescan-host-effect',
        }

    def _select_black_reverse_host_effect_real_vi_rows(self, rows: list[dict], activation=None) -> dict | None:
        base_frame = self._black_base_frame(rows, activation)
        if base_frame is None:
            return None
        stack_roles = self._infer_black_stack_roles(rows, base_frame, activation=activation)
        if stack_roles is None or stack_roles.get('semantic_start') is None:
            return None

        semantic_end = stack_roles.get('semantic_end')
        activation_end = getattr(activation, 'end_row', None)
        if semantic_end is None:
            semantic_end = activation_end
        if semantic_end is None:
            semantic_end = len(rows) - 1

        frame = {
            **base_frame,
            'vbp_label': stack_roles['vbp_label'],
            'vsp_label': stack_roles['vsp_label'],
            'vbp_addr': stack_roles['vbp_addr'],
            'vsp_addr': stack_roles['vsp_addr'],
            'semantic_start': stack_roles['semantic_start'],
            'bp_set_row': stack_roles.get('bp_set_row'),
            'semantic_end': min(semantic_end, len(rows) - 1),
            'semantic_end_inferred': stack_roles.get('semantic_end'),
        }
        records = self._black_taint_replay(rows, frame, replay_end=len(rows) - 1)
        taint_roles = self._black_taint_role_stats(records)
        result_labels = {'arg_1', 'arg_2'}

        buckets: dict[str, set[int]] = collections.defaultdict(set)
        sinks: dict[str, set[int]] = collections.defaultdict(set)
        start = frame['semantic_start']
        end = frame['semantic_end']
        first_arg1_row = None
        first_arg2_row = None
        local_save_row = None
        zero_row = None
        result_store_row = None
        result_store_value = None
        result_read_row = None
        result_arith_candidates: list[int] = []

        if isinstance(start, int):
            buckets['context'].add(start)
            sinks['context'].add(start)
        if isinstance(frame.get('bp_set_row'), int):
            buckets['context'].add(frame['bp_set_row'])
            sinks['context'].add(frame['bp_set_row'])
        if isinstance(frame.get('semantic_end_inferred'), int):
            buckets['context'].add(frame['semantic_end_inferred'])
            sinks['context'].add(frame['semantic_end_inferred'])

        for row_id in range(start, end + 1):
            row = rows[row_id]
            record = records[row_id]
            mnemonic = self._trace_mnemonic(row)

            if self._writes_label(row, frame['vbp_label']):
                if self._has_write(row, frame['vbp_addr'], frame['frame_base']):
                    buckets['context'].add(row_id)
                    sinks['context'].add(row_id)
                elif (
                    self._has_write(row, frame['vbp_addr'], frame['caller_ebp'])
                    and self._has_read(row, frame['saved_ebp_addr'], frame['caller_ebp'])
                ):
                    buckets['context'].add(row_id)
                    sinks['context'].add(row_id)

            if self._writes_label(row, frame['vsp_label']):
                if self._has_write(row, frame['vsp_addr'], frame['local_addr']):
                    buckets['context'].add(row_id)
                    sinks['boundary'].add(row_id)
                elif self._has_write(row, frame['vsp_addr'], frame['post_pop_sp']):
                    buckets['context'].add(row_id)
                    sinks['context'].add(row_id)
                elif self._has_write(row, frame['vsp_addr'], frame['frame_base']):
                    # Frame-base writes to vSP are treated as teardown only
                    # after result readback; earlier occurrences are helper
                    # traffic in black traces.
                    pass

            if self._has_write(row, frame['local_addr'], 0) and self._has_non_esp_explicit_write(row, frame['local_addr']):
                buckets['boundary'].add(row_id)
                sinks['boundary'].add(row_id)
                if zero_row is None:
                    zero_row = row_id

            local_write_value = self._black_first_write_value(row, frame['local_addr'])
            if (
                local_save_row is None
                and local_write_value is not None
                and local_write_value != 0
                and local_write_value == frame.get('caller_ecx')
                and frame.get('bp_set_row') is not None
                and row_id > frame['bp_set_row']
                and (zero_row is None or row_id < zero_row)
                and self._black_reads_plain_vb_operand(row, exclude={frame['vbp_label'], frame['vsp_label']})
            ):
                buckets['context'].add(row_id)
                sinks['boundary'].add(row_id)
                local_save_row = row_id

            if self._black_record_reads_addr_label(record, frame['arg1_addr'], 'arg_1'):
                buckets['boundary'].add(row_id)
                sinks['boundary'].add(row_id)
                if first_arg1_row is None:
                    first_arg1_row = row_id
                self._add_tainted_forward_materialization(rows, records, buckets, row_id, {'arg_1'}, 'boundary')

            if self._black_record_reads_addr_label(record, frame['arg2_addr'], 'arg_2'):
                buckets['boundary'].add(row_id)
                sinks['boundary'].add(row_id)
                if first_arg2_row is None:
                    first_arg2_row = row_id
                self._add_tainted_forward_materialization(rows, records, buckets, row_id, {'arg_2'}, 'boundary')

            if (
                mnemonic in {'ADD', 'SUB', 'IMUL', 'MUL', 'DIV', 'IDIV'}
                and not self._black_reads_vm_slot_operand(row)
                and (
                    self._black_record_writes_labels(record, result_labels, reg_only=True)
                    or (
                        mnemonic in {'DIV', 'IDIV'}
                        and any(read_addr == frame['arg2_addr'] for read_addr, _value in self._raw_reads(row))
                    )
                )
            ):
                result_arith_candidates.append(row_id)

            if self._black_record_writes_addr_labels(record, frame['local_addr'], result_labels):
                if result_store_row is None and self._has_non_esp_explicit_write(row, frame['local_addr']):
                    buckets['result'].add(row_id)
                    sinks['boundary'].add(row_id)
                    result_store_row = row_id
                    result_store_value = self._black_first_write_value(row, frame['local_addr'])
                    self._add_previous_tainted_stack_store(rows, records, buckets, frame, row_id, result_labels, 'result')

            local_result_read = (
                self._black_record_reads_addr_label(record, frame['local_addr'], 'arg_1')
                and self._black_record_reads_addr_label(record, frame['local_addr'], 'arg_2')
            )
            if not local_result_read and result_store_value is not None:
                local_result_read = self._has_read(row, frame['local_addr'], result_store_value)
            if local_result_read and result_store_row is not None and result_read_row is None and row_id > result_store_row:
                buckets['result'].add(row_id)
                sinks['boundary'].add(row_id)
                result_read_row = row_id
                if result_store_value is not None:
                    self._add_forward_materialization(rows, buckets, frame, row_id, result_store_value, 'result')
                else:
                    self._add_tainted_forward_materialization(rows, records, buckets, row_id, result_labels, 'result')

        arithmetic_row = None
        if first_arg1_row is not None and first_arg2_row is not None:
            arg_ready_row = max(first_arg1_row, first_arg2_row)
            arithmetic_limit = min(
                value
                for value in (result_store_row, result_read_row, end)
                if value is not None and value >= arg_ready_row
            )
            matching_arithmetic_rows = [
                row_id
                for row_id in result_arith_candidates
                if arg_ready_row <= row_id <= arithmetic_limit
                and (
                    result_store_value is None
                    or self._black_arithmetic_output_value(rows, row_id) == result_store_value
                )
            ]
            if not matching_arithmetic_rows:
                matching_arithmetic_rows = [
                    row_id
                    for row_id in result_arith_candidates
                    if arg_ready_row <= row_id <= arithmetic_limit
                ]
            arithmetic_row = matching_arithmetic_rows[0] if matching_arithmetic_rows else None

        accesses = [self._black_reverse_row_access(row) for row in rows]
        reverse_candidates: set[int] = set()
        for row_ids in sinks.values():
            for sink_row in sorted(row_ids):
                reverse_candidates |= self._black_reverse_slice(accesses, start, sink_row)

        if arithmetic_row is not None:
            buckets['arithmetic'].add(arithmetic_row)
            sinks['arithmetic'].add(arithmetic_row)
            arithmetic_slice = self._black_reverse_slice(accesses, start, arithmetic_row)
            reverse_candidates |= arithmetic_slice
            self._add_black_arithmetic_materialization(rows, records, buckets, frame, arithmetic_row)

            if self._trace_mnemonic(rows[arithmetic_row]) in {'DIV', 'IDIV'}:
                cdq_rows = [
                    row_id
                    for row_id in arithmetic_slice
                    if start <= row_id < arithmetic_row and self._trace_mnemonic(rows[row_id]) in {'CDQ', 'CWD'}
                ]
                if not cdq_rows:
                    lower = first_arg1_row if first_arg1_row is not None else start
                    cdq_rows = [
                        row_id
                        for row_id in range(lower, arithmetic_row)
                        if self._trace_mnemonic(rows[row_id]) in {'CDQ', 'CWD'}
                    ]
                if cdq_rows:
                    buckets['arithmetic'].add(cdq_rows[-1])

        if result_read_row is not None:
            restore_vsp_row = None
            for row_id in range(result_read_row + 1, end + 1):
                row = rows[row_id]
                if not (
                    self._writes_label(row, frame['vsp_label'])
                    and self._has_write(row, frame['vsp_addr'], frame['frame_base'])
                ):
                    continue
                buckets['context'].add(row_id)
                sinks['context'].add(row_id)
                self._add_previous_stack_store(rows, buckets, frame, row_id, frame['frame_base'], 'context')
                restore_vsp_row = row_id
                break

            for row_id in range(result_read_row + 1, end + 1):
                row = rows[row_id]
                if not (
                    self._trace_mnemonic(row) == 'PUSH'
                    and self._reads_label(row, frame['vbp_label'])
                    and self._has_read(row, frame['vbp_addr'], frame['frame_base'])
                ):
                    continue
                buckets['context'].add(row_id)
                sinks['context'].add(row_id)
                if restore_vsp_row is not None and row_id < restore_vsp_row:
                    self._add_forward_materialization(rows, buckets, frame, row_id, frame['frame_base'], 'context')

        # Trust host/native EAX sinks only after a concrete result store exists.
        # This prevents truncated-tail helper values from being treated as
        # result materialization in partial black div traces.
        if result_store_value is not None:
            result_search_start = max(
                value
                for value in (end + 1, result_read_row or 0, result_store_row or 0)
                if value is not None
            )
            for row_id in range(result_search_start, len(rows)):
                row = rows[row_id]
                if self._trace_mnemonic(row) != 'PUSH':
                    continue
                if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                    continue
                buckets['native'].add(row_id)
                sinks['native'].add(row_id)
                self._add_forward_materialization(rows, buckets, frame, row_id, result_store_value, 'native', lookahead=8)
                break

            native_exit_row = None
            for wanted_mnemonic in ('MOV', 'POP'):
                for row_id in range(result_search_start, len(rows)):
                    row = rows[row_id]
                    if self._trace_mnemonic(row) != wanted_mnemonic:
                        continue
                    ops = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]
                    if not ops or ops[0].type != OperandType.REG or _root_reg(ops[0].reg_name) != 'EAX':
                        continue
                    if wanted_mnemonic == 'MOV' and len(ops) < 2:
                        continue
                    if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                        continue
                    if self._after_reg_value(rows, row_id, 'EAX') != result_store_value:
                        continue
                    native_exit_row = row_id
                    break
                if native_exit_row is not None:
                    buckets['native'].add(native_exit_row)
                    sinks['native'].add(native_exit_row)
                    reverse_candidates |= self._black_reverse_slice(accesses, start, native_exit_row)
                    break

        selected: set[int] = set()
        for row_ids in buckets.values():
            selected.update(row_ids)
        if not selected:
            return None

        return {
            'frame': {
                **frame,
                'arg1_label': taint_roles['arg1_label'],
                'arg2_label': taint_roles['arg2_label'],
                'result_label': taint_roles['result_label'],
                'taint_top_scores': taint_roles['top_scores'],
                'local_save_row': local_save_row,
                'zero_row': zero_row,
                'result_store_row': result_store_row,
                'result_store_value': result_store_value,
                'result_read_row': result_read_row,
                'reverse_candidate_count': len(reverse_candidates),
            },
            'buckets': {bucket: set(row_ids) for bucket, row_ids in buckets.items()},
            'sinks': {bucket: set(row_ids) for bucket, row_ids in sinks.items()},
            'reverse_candidates': set(reverse_candidates),
            'rows': selected,
            'mode': 'reverse-host-effect',
        }

    def _select_black_tainted_real_vi_rows(self, rows: list[dict], activation=None) -> dict | None:
        base_frame = self._black_base_frame(rows, activation)
        if base_frame is None:
            return None
        stack_roles = self._infer_black_stack_roles(rows, base_frame, activation=activation)
        if stack_roles is None:
            return None

        semantic_start = stack_roles.get('semantic_start')
        if semantic_start is None:
            return None
        semantic_end = stack_roles.get('semantic_end')
        activation_end = getattr(activation, 'end_row', None)
        if semantic_end is None:
            semantic_end = activation_end
        if semantic_end is None:
            semantic_end = len(rows) - 1

        frame = {
            **base_frame,
            'vbp_label': stack_roles['vbp_label'],
            'vsp_label': stack_roles['vsp_label'],
            'vbp_addr': stack_roles['vbp_addr'],
            'vsp_addr': stack_roles['vsp_addr'],
            'semantic_start': semantic_start,
            'bp_set_row': stack_roles.get('bp_set_row'),
            'semantic_end': min(semantic_end, len(rows) - 1),
        }
        replay_end = len(rows) - 1
        records = self._black_taint_replay(rows, frame, replay_end=replay_end)
        taint_roles = self._black_taint_role_stats(records)
        result_labels = {'arg_1', 'arg_2'}

        buckets: dict[str, set[int]] = collections.defaultdict(set)
        start = frame['semantic_start']
        end = frame['semantic_end']
        local_save_row = None
        zero_row = None
        result_store_row = None
        result_store_value = None
        result_read_row = None
        vsp_framebase_row = None
        first_arg1_row = None
        first_arg2_row = None
        result_arith_candidates: list[int] = []
        cdq_candidates: list[int] = []

        if isinstance(frame.get('semantic_start'), int):
            buckets['semantic_core'].add(frame['semantic_start'])
        if isinstance(frame.get('bp_set_row'), int):
            buckets['semantic_core'].add(frame['bp_set_row'])
        if isinstance(stack_roles.get('semantic_end'), int):
            buckets['semantic_core'].add(stack_roles['semantic_end'])

        for row_id in range(start, min(len(rows), end + 1)):
            row = rows[row_id]
            record = records[row_id]
            mn = self._trace_mnemonic(row)

            if self._writes_label(row, frame['vbp_label']):
                if self._has_write(row, frame['vbp_addr'], frame['frame_base']):
                    buckets['semantic_core'].add(row_id)
                elif (
                    self._has_write(row, frame['vbp_addr'], frame['caller_ebp'])
                    and self._has_read(row, frame['saved_ebp_addr'], frame['caller_ebp'])
                ):
                    buckets['semantic_core'].add(row_id)

            if self._writes_label(row, frame['vsp_label']):
                if self._has_write(row, frame['vsp_addr'], frame['local_addr']):
                    buckets['semantic_core'].add(row_id)
                elif self._has_write(row, frame['vsp_addr'], frame['post_pop_sp']):
                    buckets['semantic_core'].add(row_id)

            if self._has_write(row, frame['local_addr'], 0) and self._has_non_esp_explicit_write(row, frame['local_addr']):
                buckets['semantic_core'].add(row_id)
                if zero_row is None:
                    zero_row = row_id

            local_write_value = self._black_first_write_value(row, frame['local_addr'])
            if (
                local_save_row is None
                and local_write_value is not None
                and local_write_value != 0
                and local_write_value == frame.get('caller_ecx')
                and frame.get('bp_set_row') is not None
                and row_id > frame['bp_set_row']
                and (zero_row is None or row_id < zero_row)
                and self._black_reads_plain_vb_operand(
                    row, exclude={frame['vbp_label'], frame['vsp_label']}
                )
            ):
                buckets['semantic_core'].add(row_id)
                local_save_row = row_id

            if self._black_record_reads_addr_label(record, frame['arg1_addr'], 'arg_1'):
                buckets['semantic_core'].add(row_id)
                if first_arg1_row is None:
                    first_arg1_row = row_id
                self._add_tainted_forward_materialization(rows, records, buckets, row_id, {'arg_1'}, 'semantic_core')

            if self._black_record_reads_addr_label(record, frame['arg2_addr'], 'arg_2'):
                buckets['semantic_core'].add(row_id)
                if first_arg2_row is None:
                    first_arg2_row = row_id
                self._add_tainted_forward_materialization(rows, records, buckets, row_id, {'arg_2'}, 'semantic_core')

            if (
                mn in {'ADD', 'SUB', 'IMUL', 'MUL', 'DIV', 'IDIV'}
                and not self._black_reads_vm_slot_operand(row)
                and self._black_record_writes_labels(record, result_labels, reg_only=True)
            ):
                result_arith_candidates.append(row_id)

            if mn in {'CDQ', 'CWD'} and self._black_record_writes_labels(record, {'arg_1'}, reg_only=True):
                cdq_candidates.append(row_id)

            if self._black_record_writes_addr_labels(record, frame['local_addr'], result_labels):
                if result_store_row is None and self._has_non_esp_explicit_write(row, frame['local_addr']):
                    buckets['semantic_core'].add(row_id)
                    result_store_row = row_id
                    result_store_value = self._black_first_write_value(row, frame['local_addr'])
                    self._add_previous_tainted_stack_store(
                        rows, records, buckets, frame, row_id, result_labels, 'semantic_core'
                    )

            local_result_read = (
                self._black_record_reads_addr_label(record, frame['local_addr'], 'arg_1')
                and self._black_record_reads_addr_label(record, frame['local_addr'], 'arg_2')
            )
            if not local_result_read and result_store_value is not None:
                local_result_read = self._has_read(row, frame['local_addr'], result_store_value)
            if local_result_read:
                if result_store_row is not None and result_read_row is None and row_id > result_store_row:
                    buckets['semantic_core'].add(row_id)
                    result_read_row = row_id
                    if result_store_value is not None:
                        self._add_forward_materialization(
                            rows, buckets, frame, row_id, result_store_value, 'semantic_core'
                        )
                    else:
                        self._add_tainted_forward_materialization(
                            rows, records, buckets, row_id, result_labels, 'semantic_core'
                        )

        if first_arg1_row is not None and first_arg2_row is not None:
            arg_ready_row = max(first_arg1_row, first_arg2_row)
            arithmetic_limit = min(
                value
                for value in (result_store_row, result_read_row, end)
                if value is not None and value >= arg_ready_row
            )
            matching_arithmetic_rows = [
                row_id
                for row_id in result_arith_candidates
                if arg_ready_row <= row_id <= arithmetic_limit
                and (
                    result_store_value is None
                    or self._black_arithmetic_output_value(rows, row_id) == result_store_value
                )
            ]
            if not matching_arithmetic_rows:
                matching_arithmetic_rows = [
                    row_id
                    for row_id in result_arith_candidates
                    if arg_ready_row <= row_id <= arithmetic_limit
                ]
            arithmetic_row = matching_arithmetic_rows[0] if matching_arithmetic_rows else None
            if arithmetic_row is not None:
                buckets['semantic_core'].add(arithmetic_row)
                self._add_black_arithmetic_materialization(rows, records, buckets, frame, arithmetic_row)
                if self._trace_mnemonic(rows[arithmetic_row]) in {'DIV', 'IDIV'}:
                    cdq_row = next(
                        (
                            row_id
                            for row_id in reversed(cdq_candidates)
                            if arg_ready_row <= row_id < arithmetic_row
                        ),
                        None,
                    )
                    if cdq_row is not None:
                        buckets['semantic_core'].add(cdq_row)

        if result_read_row is not None:
            restore_vsp_row = None
            for row_id in range(result_read_row + 1, min(len(rows), end + 1)):
                row = rows[row_id]
                if not (
                    self._writes_label(row, frame['vsp_label'])
                    and self._has_write(row, frame['vsp_addr'], frame['frame_base'])
                ):
                    continue
                buckets['semantic_core'].add(row_id)
                self._add_previous_stack_store(
                    rows, buckets, frame, row_id, frame['frame_base'], 'semantic_core'
                )
                restore_vsp_row = row_id
                if vsp_framebase_row is None:
                    vsp_framebase_row = row_id
                break

            for row_id in range(result_read_row + 1, min(len(rows), end + 1)):
                row = rows[row_id]
                if not (
                    self._trace_mnemonic(row) == 'PUSH'
                    and self._reads_label(row, frame['vbp_label'])
                    and self._has_read(row, frame['vbp_addr'], frame['frame_base'])
                ):
                    continue
                buckets['semantic_core'].add(row_id)
                if restore_vsp_row is not None and row_id < restore_vsp_row:
                    self._add_forward_materialization(
                        rows, buckets, frame, row_id, frame['frame_base'], 'semantic_core'
                    )

        result_search_start = max(
            value for value in (end + 1, result_read_row or 0, result_store_row or 0) if value is not None
        )
        for row_id in range(result_search_start, len(rows)):
            row = rows[row_id]
            record = records[row_id]
            if self._trace_mnemonic(row) != 'PUSH':
                continue
            if result_store_value is not None:
                if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                    continue
            elif not result_labels.issubset(set(record.get('read_labels') or set())):
                continue
            buckets['result_materialization'].add(row_id)
            if result_store_value is not None:
                self._add_forward_materialization(
                    rows, buckets, frame, row_id, result_store_value, 'result_materialization', lookahead=8
                )
            else:
                self._add_tainted_forward_materialization(
                    rows, records, buckets, row_id, result_labels, 'result_materialization'
                )
            break

        native_exit_row = None
        for wanted_mnemonic in ('MOV', 'POP'):
            for row_id in range(result_search_start, len(rows)):
                row = rows[row_id]
                if self._trace_mnemonic(row) != wanted_mnemonic:
                    continue
                ops = [op for op in (row.get('parsed_operands') or []) if not op.is_implicit]
                if len(ops) < 1 or ops[0].type != OperandType.REG:
                    continue
                if wanted_mnemonic == 'MOV' and len(ops) < 2:
                    continue
                if _root_reg(ops[0].reg_name) != 'EAX':
                    continue
                if result_store_value is not None:
                    if not any(read_value == result_store_value for _addr, read_value in self._raw_reads(row)):
                        continue
                    if self._after_reg_value(rows, row_id, 'EAX') != result_store_value:
                        continue
                elif not self._black_record_writes_labels(records[row_id], result_labels, reg_only=True):
                    continue
                native_exit_row = row_id
                break
            if native_exit_row is not None:
                buckets['native_exit_materialization'].add(native_exit_row)
                break

        selected: set[int] = set()
        for row_ids in buckets.values():
            selected.update(row_ids)
        if not selected:
            return None

        return {
            'frame': {
                **frame,
                'arg1_label': taint_roles['arg1_label'],
                'arg2_label': taint_roles['arg2_label'],
                'result_label': taint_roles['result_label'],
                'taint_top_scores': taint_roles['top_scores'],
                'local_save_row': local_save_row,
                'zero_row': zero_row,
                'result_store_row': result_store_row,
                'result_store_value': result_store_value,
                'result_read_row': result_read_row,
                'vsp_framebase_row': vsp_framebase_row,
            },
            'buckets': {bucket: set(row_ids) for bucket, row_ids in buckets.items()},
            'rows': selected,
            'mode': 'endpoint-slice',
        }

    def _annotate_black_real_vi_filter(
        self,
        rows: list[dict],
        black_real_vi_filter: dict,
        black_stack_stats: dict | None,
        *,
        annotation_error: str | None = None,
    ) -> tuple[int, int]:
        issue_mark_rows: dict[str, set[int]] = collections.defaultdict(set)
        if black_stack_stats is not None:
            self._add_black_stack_role_markers(issue_mark_rows, black_stack_stats['rows'])

        final_rows = set(black_real_vi_filter['rows'])
        marker_by_bucket = {
            'semantic_core': '[fish-real-core]',
            'context': '[fish-real-core]',
            'boundary': '[fish-real-core]',
            'arithmetic': '[fish-real-core]',
            'result': '[fish-result-materialization]',
            'native': '[fish-native-exit]',
            'result_materialization': '[fish-result-materialization]',
            'native_exit_materialization': '[fish-native-exit]',
        }
        for bucket, row_ids in black_real_vi_filter['buckets'].items():
            marker = marker_by_bucket.get(bucket)
            if marker is not None:
                issue_mark_rows[marker].update(row_ids)

        for row_id in sorted(final_rows):
            if 0 <= row_id < len(rows):
                self._append_unique_comment(rows[row_id], '[vi]')
                self._append_unique_comment(rows[row_id], '[real-vi]')
        for mark, row_ids in sorted(issue_mark_rows.items()):
            for row_id in sorted(row_ids):
                if 0 <= row_id < len(rows):
                    self._append_unique_comment(rows[row_id], mark)

        frame = black_real_vi_filter['frame']
        black_real_vi_stats = {
            'selected': len(final_rows),
            'categories': {
                bucket: len(row_ids)
                for bucket, row_ids in sorted(black_real_vi_filter['buckets'].items())
            },
            'semantic_start': frame['semantic_start'],
            'semantic_end': frame['semantic_end'],
            'frame_base': frame['frame_base'],
            'local_addr': frame['local_addr'],
            'arg1_addr': frame['arg1_addr'],
            'arg2_addr': frame['arg2_addr'],
            'roles': {
                key: frame.get(key)
                for key in (
                    'vbp_label',
                    'vsp_label',
                    'arg1_label',
                    'arg2_label',
                    'ecx_label',
                    'result_label',
                    'addr_carrier_label',
                )
            },
            'mode': black_real_vi_filter.get('mode'),
            'taint_top_scores': frame.get('taint_top_scores'),
            'reverse_candidate_count': frame.get('reverse_candidate_count'),
            'sink_categories': {
                bucket: len(row_ids)
                for bucket, row_ids in sorted((black_real_vi_filter.get('sinks') or {}).items())
            },
        }
        self.last_vi_annotation_stats = {
            'candidates': 0,
            'final': len(final_rows),
            'real_vi': len(final_rows),
            'semantic_seeds': 0,
            'address_decode': 0,
            'endpoint_addrs': [],
            'activation': None,
            'fallback_frame': True,
            'issue_marks': {mark: len(row_ids) for mark, row_ids in sorted(issue_mark_rows.items())},
            'black_real_vi_filter': black_real_vi_stats,
            'black_stack_roles': black_stack_stats,
            'annotation_error': annotation_error,
        }
        if issue_mark_rows:
            marker_summary = ', '.join(f'{mark}={len(row_ids)}' for mark, row_ids in sorted(issue_mark_rows.items()))
            print(f'[LightFISH] arithmetic VI issue markers: {marker_summary}')
        if black_stack_stats is not None:
            self._print_black_stack_stats(black_stack_stats)
        print(
            f"[LightFISH] black {black_real_vi_stats['mode']} VI filter: "
            f"selected={black_real_vi_stats['selected']} "
            f"categories={black_real_vi_stats['categories']}"
        )
        return 0, len(final_rows)

    # =========================================================================
    # VI 후보 / 최종 VI 후처리 annotation
    # =========================================================================

    def annotate_vi_candidates(self, rows: list[dict]) -> tuple[int, int]:
        """Row-level VI candidates and final arithmetic VI rows를 trace comment에 표시한다.

        Broad row candidates receive ``[canditates]`` (사용자가 요청한 표기 유지),
        final arithmetic VI rows receive ``[vi]``.  Native island VIs can be
        discovered after candidate extraction, so they may carry only ``[vi]``.
        """
        tools_dir = Path(__file__).resolve().parents[1] / 'tools'
        if str(tools_dir) not in sys.path:
            sys.path.insert(0, str(tools_dir))

        for row in rows:
            self._remove_comment_parts(row, _VI_DIAGNOSTIC_MARKERS)

        if len(rows) >= _BLACK_PRESCAN_ROW_THRESHOLD:
            try:
                black_stack_stats = self._detect_black_stack_stats(rows)
                if black_stack_stats is not None:
                    black_real_vi_filter = self._select_black_prescanned_real_vi_rows(rows)
                    if black_real_vi_filter is not None:
                        return self._annotate_black_real_vi_filter(
                            rows,
                            black_real_vi_filter,
                            black_stack_stats,
                        )
            except Exception as exc:
                print(f'[LightFISH] black prescan VI filter skipped: {exc}')

        try:
            import extract_fish_vi_slices  # type: ignore
            import refine_fish_vi_semantics  # type: ignore

            # x64dbg/GUI sessions can keep Python modules alive across plugin
            # runs. Reload the local tools so filter tweaks are visible without
            # restarting the host process.
            extract_fish_vi_slices = importlib.reload(extract_fish_vi_slices)
            refine_fish_vi_semantics = importlib.reload(refine_fish_vi_semantics)

            build_model = extract_fish_vi_slices.build_model
            build_windows = extract_fish_vi_slices.build_windows
            extract_candidates = extract_fish_vi_slices.extract_candidates
            extract_vi_row_candidates = extract_fish_vi_slices.extract_vi_row_candidates
            select_semantic_rows = refine_fish_vi_semantics.select_semantic_rows
            frame_addr_set = refine_fish_vi_semantics.frame_addr_set
            mnemonic = refine_fish_vi_semantics.mnemonic
            non_vm_mem_accesses = refine_fish_vi_semantics.non_vm_mem_accesses
            frame_fallback_label = refine_fish_vi_semantics.FRAME_FALLBACK_LABEL
        except Exception as exc:
            print(f'[LightFISH] VI annotation skipped: failed to import extractor ({exc})')
            self.last_vi_annotation_stats = {}
            return 0, 0

        try:
            model = build_model(rows, self)
            windows = build_windows(rows, model)
            candidates = extract_candidates(rows, model, windows)
            vi_rows = extract_vi_row_candidates(rows, model, windows, candidates, min_score=3)
            selection = select_semantic_rows(rows, model, windows, vi_rows)
        except Exception as exc:
            black_stack_stats = self._detect_black_stack_stats(rows)
            if black_stack_stats is not None:
                issue_mark_rows: dict[str, set[int]] = collections.defaultdict(set)
                self._add_black_stack_role_markers(issue_mark_rows, black_stack_stats['rows'])
                black_real_vi_filter = self._select_black_prescanned_real_vi_rows(rows)
                if black_real_vi_filter is None:
                    black_real_vi_filter = self._select_black_reverse_host_effect_real_vi_rows(rows)
                if black_real_vi_filter is None:
                    black_real_vi_filter = self._select_black_tainted_real_vi_rows(rows)
                final_rows: set[int] = set()
                black_real_vi_stats = None
                if black_real_vi_filter is not None:
                    final_rows = set(black_real_vi_filter['rows'])
                    for bucket, row_ids in black_real_vi_filter['buckets'].items():
                        marker = {
                            'semantic_core': '[fish-real-core]',
                            'context': '[fish-real-core]',
                            'boundary': '[fish-real-core]',
                            'arithmetic': '[fish-real-core]',
                            'result': '[fish-result-materialization]',
                            'native': '[fish-native-exit]',
                            'result_materialization': '[fish-result-materialization]',
                            'native_exit_materialization': '[fish-native-exit]',
                        }.get(bucket)
                        if marker is not None:
                            issue_mark_rows[marker].update(row_ids)
                    frame = black_real_vi_filter['frame']
                    black_real_vi_stats = {
                        'selected': len(final_rows),
                        'categories': {
                            bucket: len(row_ids)
                            for bucket, row_ids in sorted(black_real_vi_filter['buckets'].items())
                        },
                        'semantic_start': frame['semantic_start'],
                        'semantic_end': frame['semantic_end'],
                        'frame_base': frame['frame_base'],
                        'local_addr': frame['local_addr'],
                        'arg1_addr': frame['arg1_addr'],
                        'arg2_addr': frame['arg2_addr'],
                        'roles': {
                            key: frame.get(key)
                            for key in (
                                'vbp_label',
                                'vsp_label',
                                'arg1_label',
                                'arg2_label',
                                'result_label',
                            )
                        },
                        'mode': black_real_vi_filter.get('mode'),
                        'taint_top_scores': frame.get('taint_top_scores'),
                        'reverse_candidate_count': frame.get('reverse_candidate_count'),
                        'sink_categories': {
                            bucket: len(row_ids)
                            for bucket, row_ids in sorted((black_real_vi_filter.get('sinks') or {}).items())
                        },
                    }
                for row_id in sorted(final_rows):
                    if 0 <= row_id < len(rows):
                        self._append_unique_comment(rows[row_id], '[vi]')
                        self._append_unique_comment(rows[row_id], '[real-vi]')
                for mark, row_ids in sorted(issue_mark_rows.items()):
                    for row_id in sorted(row_ids):
                        if 0 <= row_id < len(rows):
                            self._append_unique_comment(rows[row_id], mark)
                self.last_vi_annotation_stats = {
                    'candidates': 0,
                    'final': len(final_rows),
                    'real_vi': len(final_rows),
                    'semantic_seeds': 0,
                    'address_decode': 0,
                    'endpoint_addrs': [],
                    'activation': None,
                    'fallback_frame': None,
                    'issue_marks': {mark: len(row_ids) for mark, row_ids in sorted(issue_mark_rows.items())},
                    'black_real_vi_filter': black_real_vi_stats,
                    'black_stack_roles': black_stack_stats,
                    'annotation_error': str(exc),
                }
                print(f'[LightFISH] VI annotation skipped: extraction failed ({exc}); black stack roles recovered')
                if issue_mark_rows:
                    marker_summary = ', '.join(
                        f'{mark}={len(row_ids)}' for mark, row_ids in sorted(issue_mark_rows.items())
                    )
                    print(f'[LightFISH] arithmetic VI issue markers: {marker_summary}')
                self._print_black_stack_stats(black_stack_stats)
                if black_real_vi_stats is not None:
                    print(
                        f"[LightFISH] black {black_real_vi_stats['mode']} VI filter: "
                        f"selected={black_real_vi_stats['selected']} "
                        f"categories={black_real_vi_stats['categories']}"
                    )
                return 0, len(final_rows)
            print(f'[LightFISH] VI annotation skipped: extraction failed ({exc})')
            self.last_vi_annotation_stats = {}
            return 0, 0

        candidate_rows = {candidate.row for candidate in vi_rows}
        final_rows = set(selection.rows)
        real_vi_rows: set[int] = set()
        issue_mark_rows: dict[str, set[int]] = collections.defaultdict(set)
        activation = selection.activation
        fallback_frame = getattr(activation, 'vbp_label', None) == frame_fallback_label
        semantic_frame_addrs = frame_addr_set(activation.base)
        arg_addrs = {((activation.base + 8) & 0xFFFFFFFF), ((activation.base + 0xC) & 0xFFFFFFFF)}
        confirmed_real_vi_rows: set[int] = set()
        black_real_vi_filter = None
        if fallback_frame:
            black_real_vi_filter = self._select_black_prescanned_real_vi_rows(rows, activation)
            if black_real_vi_filter is None:
                black_real_vi_filter = self._select_black_reverse_host_effect_real_vi_rows(rows, activation)
            if black_real_vi_filter is None:
                black_real_vi_filter = self._select_black_tainted_real_vi_rows(rows, activation)
        black_real_vi_stats = None
        black_stack_stats = None

        if fallback_frame:
            black_stack_frame = self._black_base_frame(rows, activation)
            black_stack_roles = (
                self._infer_black_stack_roles(rows, black_stack_frame, activation=activation)
                if black_stack_frame is not None
                else None
            )
            if black_stack_frame is not None and black_stack_roles is not None:
                self._add_black_stack_role_markers(issue_mark_rows, black_stack_roles)
                black_stack_stats = self._build_black_stack_stats(black_stack_frame, black_stack_roles)

        if black_real_vi_filter is not None:
            final_rows = set(black_real_vi_filter['rows'])
            for bucket, row_ids in black_real_vi_filter['buckets'].items():
                marker = {
                    'semantic_core': '[fish-real-core]',
                    'context': '[fish-real-core]',
                    'boundary': '[fish-real-core]',
                    'arithmetic': '[fish-real-core]',
                    'result': '[fish-result-materialization]',
                    'native': '[fish-native-exit]',
                    'result_materialization': '[fish-result-materialization]',
                    'native_exit_materialization': '[fish-native-exit]',
                }.get(bucket)
                if marker is not None:
                    issue_mark_rows[marker].update(row_ids)
            frame = black_real_vi_filter['frame']
            black_real_vi_stats = {
                'selected': len(final_rows),
                'categories': {
                    bucket: len(row_ids)
                    for bucket, row_ids in sorted(black_real_vi_filter['buckets'].items())
                },
                'semantic_start': frame['semantic_start'],
                'semantic_end': frame['semantic_end'],
                'frame_base': frame['frame_base'],
                'local_addr': frame['local_addr'],
                'arg1_addr': frame['arg1_addr'],
                'arg2_addr': frame['arg2_addr'],
                'roles': {
                    key: frame.get(key)
                    for key in (
                        'vbp_label',
                        'vsp_label',
                        'arg1_label',
                        'arg2_label',
                        'ecx_label',
                        'result_label',
                        'addr_carrier_label',
                    )
                },
                'mode': black_real_vi_filter.get('mode'),
                'taint_top_scores': frame.get('taint_top_scores'),
                'reverse_candidate_count': frame.get('reverse_candidate_count'),
                'sink_categories': {
                    bucket: len(row_ids)
                    for bucket, row_ids in sorted((black_real_vi_filter.get('sinks') or {}).items())
                },
            }

        # Confirmed manually on the add/black trace: this row performs the
        # guest prologue save of the original EBP value to the guest stack.
        if (
            fallback_frame
            and 280399 < len(rows)
            and rows[280399].get('ip') == 0x51B1F1
            and (rows[280399].get('disasm') or '').lower() == 'push dword ptr [ebx]'
            and any(
                (addr & 0xFFFFFFFF) == (activation.base & 0xFFFFFFFF)
                and access in {'WRITE', 'READ_WRITE'}
                for _op, addr, access in non_vm_mem_accesses(rows[280399], model)
            )
        ):
            confirmed_real_vi_rows.add(280399)

        def in_semantic_frame_addr(addr: int) -> bool:
            addr &= 0xFFFFFFFF
            return ((activation.base - 4) & 0xFFFFFFFF) <= addr <= activation.frame_hi

        def mentions_frame_vmbblob(row: dict) -> bool:
            comment = (row.get('comment') or '').lower()
            return any(f'vmblob_0x{addr:x}' in comment for addr in semantic_frame_addrs)

        # These markers are intentionally emitted only for the stack-frame
        # fallback path.  Red/white already converges to a compact final set;
        # black needs extra visual breadcrumbs to separate carrier/staging
        # code from true guest-semantic rows.
        if fallback_frame:
            for row_id in final_rows:
                if not (0 <= row_id < len(rows)):
                    continue
                row = rows[row_id]
                comment = row.get('comment') or ''
                accesses = non_vm_mem_accesses(row, model)
                if 'STACK_' in comment:
                    issue_mark_rows['[fish-stack-carrier]'].add(row_id)
                if mentions_frame_vmbblob(row):
                    issue_mark_rows['[fish-frame-vmblob]'].add(row_id)
                if any(in_semantic_frame_addr(addr) and (addr & 3) != 0 for _op, addr, _access in accesses):
                    issue_mark_rows['[fish-unaligned-frame]'].add(row_id)

            for row_id in candidate_rows:
                if not (0 <= row_id < len(rows)):
                    continue
                row = rows[row_id]
                if mnemonic(rows, row_id) != 'PUSH':
                    continue
                accesses = non_vm_mem_accesses(row, model)
                reads_arg = any(access in {'READ', 'READ_WRITE'} and (addr & 0xFFFFFFFF) in arg_addrs
                                for _op, addr, access in accesses)
                writes_scratch_stack = any(access in {'WRITE', 'READ_WRITE'} and not in_semantic_frame_addr(addr)
                                           for _op, addr, access in accesses)
                if not reads_arg:
                    continue
                issue_mark_rows['[fish-arg-read]'].add(row_id)
                if row_id not in final_rows:
                    issue_mark_rows['[fish-missed-arg-read]'].add(row_id)
                if writes_scratch_stack:
                    issue_mark_rows['[fish-arg-to-stack]'].add(row_id)

            if black_real_vi_filter is not None:
                # In black fallback mode the broad semantic-refinement result
                # is too wide.  Use the endpoint/provenance filter instead for
                # both [vi] and [real-vi] so the GUI view is directly usable.
                real_vi_rows.update(black_real_vi_filter['rows'])
            else:
                # Fallback for traces where the black-add filter cannot be
                # inferred.  Keep the older conservative breadcrumbs.
                real_vi_rows.update(issue_mark_rows.get('[fish-arg-read]', set()))
                real_vi_rows.update(confirmed_real_vi_rows)
        else:
            # Red/white and other non-fallback traces converge to a compact
            # final set, but the final rows still include address-decode helper
            # rows.  Mark only direct semantic seeds as known real VIs.
            real_vi_rows.update(selection.semantic_seed_rows)

        self.last_vi_annotation_stats = {
            'candidates': len(candidate_rows),
            'final': len(final_rows),
            'real_vi': len(real_vi_rows),
            'semantic_seeds': len(selection.semantic_seed_rows),
            'address_decode': len(selection.address_decode_rows),
            'endpoint_addrs': sorted(selection.endpoint_addrs),
            'activation': selection.activation,
            'fallback_frame': fallback_frame,
            'issue_marks': {mark: len(row_ids) for mark, row_ids in sorted(issue_mark_rows.items())},
            'black_real_vi_filter': black_real_vi_stats,
            'black_stack_roles': black_stack_stats,
        }

        for row_id in sorted(candidate_rows):
            if 0 <= row_id < len(rows):
                self._append_unique_comment(rows[row_id], '[canditates]')
        for row_id in sorted(final_rows):
            if 0 <= row_id < len(rows):
                self._append_unique_comment(rows[row_id], '[vi]')
        for row_id in sorted(real_vi_rows):
            if 0 <= row_id < len(rows):
                self._append_unique_comment(rows[row_id], '[real-vi]')
        for mark, row_ids in sorted(issue_mark_rows.items()):
            for row_id in sorted(row_ids):
                if 0 <= row_id < len(rows):
                    self._append_unique_comment(rows[row_id], mark)

        if issue_mark_rows:
            marker_summary = ', '.join(f'{mark}={len(row_ids)}' for mark, row_ids in sorted(issue_mark_rows.items()))
            print(f'[LightFISH] arithmetic VI issue markers: {marker_summary}')
        if black_stack_stats is not None:
            self._print_black_stack_stats(black_stack_stats)
        print(
            f'[LightFISH] arithmetic VI annotation: '
            f'candidates={len(candidate_rows)} final={len(final_rows)} real={len(real_vi_rows)}'
        )
        return len(candidate_rows), len(final_rows)

    # =========================================================================
    # 메인 패스
    # =========================================================================

    def process_instruction(self, trace) -> bool:
        if self.vpc_slot is None or self.vbr is None:
            return True

        is_in_vm = self.is_trace_in_vm_tracking(trace)

        if is_in_vm and not self._was_in_vm:
            self._enter_vm()
        elif not is_in_vm and self._was_in_vm:
            self._reset_runtime_state()

        if not is_in_vm:
            self._was_in_vm = is_in_vm
            return True
        self._was_in_vm = is_in_vm

        vpc_slot_addr = self.vbr + self.vpc_slot

        handled_dsts: set[str] = set()
        close_fetch_window = False

        for m in (trace.get('mem') or []):
            addr   = m.get('addr', 0)
            access = m.get('access', '')
            value  = m.get('value', 0)
            op_accesses = self._mem_operand_accesses(trace, addr)
            if op_accesses:
                is_write = any(a in (OperandAccess.WRITE, OperandAccess.READ_WRITE)
                               for a in op_accesses)
                is_read = any(a in (OperandAccess.READ, OperandAccess.READ_WRITE)
                              for a in op_accesses)
            else:
                is_write = access != 'READ'
                is_read = access == 'READ'
            write_value = (
                value if access != 'READ'
                else self._estimate_mem_write_value(trace, addr, value)
            )

            # VPC 슬롯 쓰기 → VPC move 감지
            if is_write and addr == vpc_slot_addr:
                vpc_label = self.vb_addr_map.get(addr, f'VPC_0x{self.vpc_slot:x}')
                source_labels = self._collect_read_labels(trace, exclude_mem_addrs={vpc_slot_addr})
                self._handle_vpc_write(trace, write_value, source_labels)
                self._write_symbol(vpc_label, {vpc_label})
                self._write_elements(vpc_label, {vpc_label})
                continue

            if is_write:
                self._handle_vmop_access(trace, addr, 'WRITE', write_value)
            elif is_read:
                self._handle_vmop_access(trace, addr, 'READ', value)

            # VB 슬롯 쓰기 → provenance 갱신 + vb offset 어노테이션
            if is_write:
                if addr in self.vb_addr_map:
                    self._check_vb_offset(trace, addr)
                    vb_label = self.vb_addr_map[addr]
                    source_labels = self._collect_read_labels(trace)
                    if not vb_label.startswith(('VPC_', 'VHTP_', 'VMOP_')):
                        self._annotate_vb_relay(source_labels, vb_label, trace.get('id'))
                    self._write_symbol(vb_label, source_labels)
                    self._write_elements(vb_label, {vb_label})
                elif self.stack_temp_tracking_enabled:
                    source_labels = self._collect_read_labels(trace)
                    source_elements = self._collect_read_elements(trace)
                    if (source_labels or source_elements
                            or addr in self._stack_addr_labels
                            or addr in self._stack_addr_elements):
                        self._write_stack_temp(addr, source_labels, source_elements)
                continue

            # VPC 슬롯 읽기 → old value 보존
            if is_read and addr == vpc_slot_addr:
                self._pending_vpc = value

            # Host stack temporary 읽기 → push/pop 기반 VMBLOB staging 전파
            if is_read and self._propagate_stack_read(trace, addr, handled_dsts):
                continue

            # VB 슬롯 읽기 → adimehts 심볼 전파 + vb offset 어노테이션
            if is_read and addr in self.vb_addr_map:
                self._check_vb_offset(trace, addr)
                vb_label = self.vb_addr_map[addr]
                src_set  = self._adimehts.get(vb_label, {vb_label})
                if src_set is not None:
                    dst_info = self._get_dst_symbol_and_access(trace)
                    if dst_info is not None:
                        dst_sym, dst_access = dst_info
                        if dst_access == OperandAccess.READ_WRITE:
                            self._adimehts[dst_sym] = self._adimehts.get(dst_sym, set()) | set(src_set)
                        else:
                            self._adimehts[dst_sym] = set(src_set)
                        self._write_elements(dst_sym, {vb_label}, dst_access)
                        handled_dsts.add(dst_sym)
                continue

            # VMBLOB fetch: pending VPC 범위 내 역참조
            if is_read and self._is_vpc_fetch(trace, addr):
                label = f'VMBLOB_0x{addr:x}'

                if label not in self._fetch_traces:
                    self._fetch_traces[label] = trace
                    self._fetch_history.setdefault(label, []).append(trace)
                    self._append_comment(trace, self._build_fetch_comment(addr, trace))

                dst_info = self._get_dst_symbol_and_access(trace)
                if dst_info is None:
                    stack_addr = (
                        self._implicit_mem_addr(trace, (OperandAccess.WRITE, OperandAccess.READ_WRITE))
                        if self.stack_temp_tracking_enabled else None
                    )
                    if stack_addr is not None:
                        self._write_stack_temp(stack_addr, {label})
                        self._append_fetch_trace_annotation(
                            trace,
                            f'stacked to {self._stack_label(stack_addr)}',
                            trace.get('id'),
                        )
                        continue
                    row_id = trace.get('id', '?')
                    print(f'[LightFISH] row {row_id}: dst 심볼 식별 불가 — {label}')
                    print(f'  disasm   : {trace.get("disasm", "")}')
                    print(f'  operands : {trace.get("parsed_operands")}')
                    continue

                dst_sym, dst_access = dst_info
                if dst_access == OperandAccess.READ_WRITE:
                    self._adimehts[dst_sym] = self._adimehts.get(dst_sym, set()) | {label}
                else:
                    self._adimehts[dst_sym] = {label}
                self._write_elements(dst_sym, set(), dst_access)
                handled_dsts.add(dst_sym)

        # VHTP 파생 읽기 → VCH 심볼 dst에 등록
        if self.vhtp_value is not None:
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit or op.type != OperandType.MEM:
                    continue
                if op.access == OperandAccess.WRITE:
                    continue
                carrier = self._address_carrier_labels(op)
                if not carrier or not any(s.startswith('VHTP_') for s in carrier):
                    continue
                try:
                    addr = self._trace_mem_operand_addr(op, trace)
                    if addr is None:
                        continue
                    # VB 슬롯 주소이면 VHTP 값 로드일 뿐, VCH 인덱싱이 아님
                    if addr in self.vb_addr_map:
                        continue
                    index   = (addr - self.vhtp_value) // 4
                    vch_label    = 'VTABLE' if index == 0 else f'VCH_0x{index:x}'
                    self._vch_addr_map[addr] = vch_label
                    vmblob_srcs  = {lbl for lbl in carrier if lbl.startswith('VMBLOB_')}
                    # INDEX 레지스터가 VMBLOB을 carry → fetch 행에 vhtp index 직접 어노테이션
                    index_reg = (op.mem_info or {}).get('index', '')
                    if index_reg:
                        row_id = trace.get('id')
                        for lbl in self._adimehts.get(_root_reg(index_reg), set()):
                            if lbl.startswith('VMBLOB_'):
                                vmblob_srcs = vmblob_srcs | {lbl}
                                self._annotate_fetch(lbl, f'vhtp index : {hex(index)}', row_id)
                    if vmblob_srcs:
                        row_id = trace.get('id')
                        existing_srcs = self._vch_sources.setdefault(vch_label, set())
                        existing_srcs.update(vmblob_srcs)
                        for lbl in vmblob_srcs:
                            self._annotate_fetch(lbl, f'vhtp index : {hex(index)}', row_id)
                        self._remove_labels_from_symbols(vmblob_srcs)
                    dst_sym = self._get_dst_symbol(trace)
                    if dst_sym is not None:
                        self._adimehts[dst_sym] = {vch_label}
                        self._write_elements(dst_sym, {vch_label})
                        handled_dsts.add(dst_sym)
                    close_fetch_window = True
                except Exception:
                    pass

        # VTABLE 파생 읽기 → fetch 행에 vtable offset 역방향 어노테이션
        if self.vhtp_value is not None:
            read_idx = 0
            mem_reads = [m.get('addr', 0) & 0xFFFFFFFF
                         for m in (trace.get('mem') or []) if m.get('access') == 'READ']
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit or op.type != OperandType.MEM:
                    continue
                if op.access == OperandAccess.WRITE:
                    continue
                if read_idx >= len(mem_reads):
                    break
                read_addr = mem_reads[read_idx]
                read_idx += 1
                carrier  = self._address_carrier_labels(op)
                if 'VTABLE' not in carrier:
                    continue
                offset = (read_addr - self.vhtp_value) & 0xFFFFFFFF
                row_id = trace.get('id')
                source_labels = set(carrier) | self._vch_sources.get('VTABLE', set())
                for lbl in source_labels:
                    if lbl.startswith('VMBLOB_'):
                        self._annotate_fetch(lbl, f'vtable offset : {hex(offset)}', row_id)

        self._track_decode_decision(trace)

        # VHTP/VTABLE 처리 후 symbolic disasm 생성 → [VM] 바로 뒤에 삽입
        sym_disasm = self._build_symbolic_disasm(trace)
        if sym_disasm:
            self._insert_after_vm(trace, sym_disasm)

        # JMP/CALL + VCH 로드 탐지 → comment + fetch 역방향 어노테이션
        inst     = trace.get('instruction_obj')
        mnemonic = inst.mnemonic.upper() if inst else ''
        if mnemonic in ('JMP', 'CALL'):
            for op in (trace.get('parsed_operands') or []):
                if op.is_implicit:
                    continue
                labels = self._labels_for_operand_value(op, trace)
                for vch_lbl in labels:
                    if vch_lbl == 'VTABLE':
                        index = 0
                    elif vch_lbl.startswith('VCH_'):
                        try:
                            index = int(vch_lbl[6:], 16)  # 'VCH_0x' = 6 chars
                        except ValueError:
                            continue
                    else:
                        continue
                    self._append_comment(trace, f'=========[{vch_lbl} load]=========')
                    row_id = trace.get('id')
                    for vmblob_lbl in self._vch_sources.get(vch_lbl, set()):
                        self._annotate_fetch(vmblob_lbl, f'vhtp index : {hex(index)}', row_id)

        if self._write_result_ignores_sources(trace):
            self._clear_explicit_write_symbols(trace, handled_dsts)

        # 일반 레지스터 전파 (MOV/ALU reg←reg)
        src_sets: list[set[str]] = []
        element_src_sets: list[set[str]] = []
        dst_regs: list[tuple[str, OperandAccess]] = []

        for op in (trace.get('parsed_operands') or []):
            if op.is_implicit:
                continue
            if op.access in (OperandAccess.READ, OperandAccess.READ_WRITE):
                src_sets.append(self._labels_for_operand_value(op, trace))
                element_src_sets.append(self._elements_for_operand_value(op, trace))
            if op.type == OperandType.REG and op.access in (OperandAccess.WRITE, OperandAccess.READ_WRITE):
                reg = _root_reg(op.reg_name)
                dst_regs.append((reg, op.access))

        combined = set().union(*src_sets) if src_sets else set()
        combined_elements = set().union(*element_src_sets) if element_src_sets else set()

        for reg, access in dst_regs:
            if reg in handled_dsts:
                continue
            if access == OperandAccess.READ_WRITE:
                new_set = self._adimehts.get(reg, set()) | combined
            else:
                new_set = combined.copy()
                self._mark_dead_from_overwrite(self._adimehts.get(reg, set()), new_set)
            if new_set:
                self._adimehts[reg] = new_set
            else:
                self._adimehts.pop(reg, None)

            if access == OperandAccess.READ_WRITE:
                new_elements = self._element_sources.get(reg, set()) | combined_elements
            else:
                new_elements = combined_elements.copy()
            if new_elements:
                self._element_sources[reg] = new_elements
            else:
                self._element_sources.pop(reg, None)

        if close_fetch_window:
            self._start_new_dispatch_cycle()

        return True

    # =========================================================================
    # Snapshot
    # =========================================================================

    def get_snapshot(self) -> list:
        """adimehts 표: 심볼별 기여 레이블 집합."""
        return [{'name': sym, 'symbol': ', '.join(sorted(label_set))}
                for sym, label_set in self._adimehts.items()
                if label_set]

    def get_taint_esp_snapshot(self) -> list:
        """taint_esp 표: VBR/VPC/VHTP 식별 결과 + pre-pass VB 슬롯 목록."""
        header = []
        if self.vbr is not None:
            header.append({'name': 'VBR', 'symbol': hex(self.vbr)})
        if self.vpc_slot is not None:
            header.append({'name': f'VPC_0x{self.vpc_slot:x}',
                           'symbol': hex(self.vbr + self.vpc_slot)})
        if self.vhtp_slot is not None:
            header.append({'name': f'VHTP_0x{self.vhtp_slot:x}',
                           'symbol': hex(self.vbr + self.vhtp_slot)})
        if self.vmop_slot is not None:
            header.append({'name': f'VMOP_0x{self.vmop_slot:x}',
                           'symbol': hex(self.vbr + self.vmop_slot)})

        vb_slots = sorted(
            ({'name': label, 'symbol': hex(addr)}
             for addr, label in self.vb_addr_map.items()),
            key=lambda e: e['name']
        )
        return header + vb_slots
