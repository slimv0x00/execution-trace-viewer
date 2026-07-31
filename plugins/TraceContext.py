from z3 import *

# =============================================================================
# [핵심 해결책] Z3 Rewriter 설정
# -----------------------------------------------------------------------------
# 하위 바이트의 덧셈을 분리하지 못하도록 막습니다.
# 이를 설정하면 Extract(0, 7, A+B)가 Extract(0, 7, A) + Extract(0, 7, B)로
# 변형되지 않고 그대로 유지되므로, 나중에 Concat될 때 깔끔하게 합쳐집니다.
# =============================================================================
set_param('rewriter.bv_extract_prop', False)


def _z3_bv_to_str(expr) -> str:
    """Z3 BitVec expression → human-readable string.

    bvadd(x, C) where C >= 2^(bitwidth-1) is displayed as 'x - (2^bitwidth - C)'
    to show signed subtraction instead of a large unsigned addend.
    """
    if expr is None:
        return 'None'
    if is_bv_value(expr):
        return hex(expr.as_long())
    if not is_app(expr):
        return str(expr)
    op_map = {'bvadd': '+', 'bvsub': '-', 'bvxor': '^', 'bvor': '|', 'bvand': '&'}
    name = expr.decl().name()
    op = op_map.get(name)
    if op and expr.num_args() == 2:
        a, b = expr.arg(0), expr.arg(1)
        if name == 'bvadd':
            const, other = (a, b) if is_bv_value(a) else (b, a) if is_bv_value(b) else (None, None)
            if const is not None:
                bw = const.size()
                val = const.as_long()
                if val >= (1 << (bw - 1)):
                    neg = (1 << bw) - val
                    return f'{_z3_bv_to_str(other)} - {hex(neg)}'
        return f'{_z3_bv_to_str(a)} {op} {_z3_bv_to_str(b)}'
    return str(expr)


class TraceContext:

    # -------------------------------------------------------------------------
    # [설정] Trace 파일의 regs 리스트 순서 정의 (x64dbg/OllyDbg 표준 순서 가정)
    # -------------------------------------------------------------------------
    # Trace: 'regs': [EAX, ECX, EDX, EBX, ESP, EBP, ESI, EDI, EIP, EFLAGS]
    REG_ORDER_32 = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'eip', 'eflags']
    # 64비트 Trace일 경우 순서 (일반적인 x64dbg/ScyllaHide 순서 예시)
    REG_ORDER_64 = ['rax', 'rbx', 'rcx', 'rdx', 'rbp', 'rsp', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13',
                    'r14', 'r15', 'rip', 'rflags']

    # Expression complexity cap: when a symbolic expression exceeds this many
    # AST nodes, replace it with a fresh BitVec variable to prevent unbounded
    # growth and simplify() slowdown.
    MAX_EXPR_NODES = 150

    def __init__(self, arch_mode=64):
        self.arch_mode = arch_mode  # 32 or 64
        self.reg_layout = self._generate_reg_layout(arch_mode)
        self.root_reg_size = arch_mode // 8
        self._sym_cap_counter = 0
        self.cap_occurred = False  # set to True when _cap_expression triggers; reset externally
        self.cap_enabled = False   # True: replace with cap_N variable; False: apply z3.simplify()

        # 1. Concrete Value Storage (Register Name -> int)
        self.regs_concrete = {}

        # 2. Symbolic Expression Storage (Root Register Name -> z3.BitVecRef)
        # 부분 레지스터(al)에 써도 항상 rax에 통합되어 저장됨
        self.regs_symbolic = {}

        # 3. Memory Storage
        # 주소(int) -> 값(int/byte)
        self.mem_concrete = {}
        # 주소(int) -> z3.BitVecRef(8-bit)
        self.mem_symbolic = {}
        # (addr, size) -> z3.BitVecRef (full-width expression, avoids byte decomposition)
        self.mem_wide_symbolic = {}

        # Write Hook 함수 저장소 (None이면 작동 안 함)
        # 함수 시그니처: callback(target_name_or_addr, old_val, new_val)
        self.hook_memory_write = None
        self.hook_reg_write = None

    def _generate_reg_layout(self, mode):
        """아키텍처 모드에 따라 REG_LAYOUT을 동적으로 생성"""
        # -----------------------------------------------------------------------------
        # Register Layout Definitions (x64 Base)
        # 구조: (Root Register, Offset, Size)
        # -----------------------------------------------------------------------------
        layout = {}

        # 기본 레지스터 리스트 (64비트 기준 이름들)
        gp_regs = ['ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp']
        r_regs = [f'r{i}' for i in range(8, 16)]  # r8~r15

        if mode == 64:
            # --- 64-bit Mode: Root is 'rXX' ---
            for reg in gp_regs:
                root = f'r{reg}'
                layout[root] = (root, 0, 64)  # rax
                layout[f'e{reg}'] = (root, 0, 32)  # eax
                layout[reg] = (root, 0, 16)  # ax
                # 8-bit low (al, bl, cl, dl, sil, dil, bpl, spl)
                low_name = f'{reg[0]}l' if reg in ['ax', 'bx', 'cx', 'dx'] else f'{reg}l'
                layout[low_name] = (root, 0, 8)

            # r8~r15 처리
            for r in r_regs:
                layout[r] = (r, 0, 64)  # r8
                layout[f'{r}d'] = (r, 0, 32)  # r8d
                layout[f'{r}w'] = (r, 0, 16)  # r8w
                layout[f'{r}b'] = (r, 0, 8)  # r8b

            # High bytes (ah, bh, ch, dh) - 64비트에서도 rax가 부모
            for reg in ['a', 'b', 'c', 'd']:
                layout[f'{reg}h'] = (f'r{reg}x', 8, 8)

        else:
            # --- 32-bit Mode: Root is 'eXX' ---
            for reg in gp_regs:
                root = f'e{reg}'
                layout[root] = (root, 0, 32)  # eax
                layout[reg] = (root, 0, 16)  # ax
                low_name = f'{reg[0]}l' if reg in ['ax', 'bx', 'cx', 'dx'] else f'{reg}l'
                layout[low_name] = (root, 0, 8)

            # High bytes (ah, bh, ch, dh) - 32비트에서는 eax가 부모
            for reg in ['a', 'b', 'c', 'd']:
                layout[f'{reg}h'] = (f'e{reg}x', 8, 8)

        return layout

    # =========================================================================
    # [Helper] Expression Complexity Cap
    # =========================================================================
    @staticmethod
    def _ast_node_count(expr, limit):
        """Count AST nodes iteratively, with early termination at limit."""
        count = 0
        stack = [expr]
        while stack:
            node = stack.pop()
            count += 1
            if count > limit:
                return count
            for i in range(node.num_args()):
                stack.append(node.arg(i))
        return count

    def _cap_expression(self, sym_expr):
        """Simplify and canonicalize expressions that exceed the complexity threshold.

        Previously replaced with a fresh cap_N variable; now applies z3.simplify() so
        symbolic provenance (VMBLOB / VB labels) is preserved through the reduction.
        """
        if sym_expr is None or z3.is_bv_value(sym_expr):
            return sym_expr
        if self._ast_node_count(sym_expr, self.MAX_EXPR_NODES) > self.MAX_EXPR_NODES:
            self._sym_cap_counter += 1
            self.cap_occurred = True
            if self.cap_enabled:
                return BitVec(f"cap_{self._sym_cap_counter}", sym_expr.size())
            return z3.simplify(sym_expr)
        return sym_expr

    # =========================================================================
    # [Helper] Register Info Normalization
    # =========================================================================
    def _get_root_register_info(self, reg_name):
        """레지스터 이름을 정규화하고 (Root, Offset, Size) 정보를 반환"""
        reg_name = reg_name.lower()
        if reg_name in self.reg_layout:
            return self.reg_layout[reg_name]

        # 정의되지 않은 레지스터(rip, eflags 등)는 그 자체를 Root로 취급
        # 기본 크기는 아키텍처 모드에 따름
        default_size = self.arch_mode
        return reg_name, 0, default_size

    # =========================================================================
    # [Core] Register Access (Get)
    # =========================================================================
    def get_register(self, reg_name):
        """
        레지스터의 (Concrete 값, Symbolic 식, 비트 크기) 튜플을 반환
        """
        root_name, offset, size = self._get_root_register_info(reg_name)
        root_bits = 64 if self.arch_mode == 64 else 32  # Root 레지스터의 전체 크기

        # 1. Root 레지스터의 심볼릭 상태 확인/초기화
        if root_name not in self.regs_symbolic:
            # 심볼릭 상태가 없으면 Concrete 값을 기반으로 상수 BitVec 생성
            concrete_val = self.regs_concrete.get(root_name, 0)
            self.regs_symbolic[root_name] = BitVecVal(concrete_val, root_bits)

        root_expr = self.regs_symbolic[root_name]
        root_conc = self.regs_concrete.get(root_name, 0)

        # 2. 요청한 레지스터가 Root와 같다면 그대로 반환
        if root_name == reg_name:
            return root_conc, root_expr, size

        # 3. 부분 레지스터 처리 (Extract & Masking)

        # A. Symbolic Extract
        # z3.Extract(high, low, val)
        sym_val = Extract(offset + size - 1, offset, root_expr)

        # B. Concrete Masking (Python 비트 연산)
        mask = (1 << size) - 1
        conc_val = (root_conc >> offset) & mask

        return conc_val, sym_val, size

    # =========================================================================
    # [Core] Register Access (Set) - With Hook
    # =========================================================================
    def set_register(self, reg_name, new_conc_val, new_sym_expr):
        if isinstance(new_conc_val, str):
            new_conc_val = int(new_conc_val, 0)

        root_name, offset, size = self._get_root_register_info(reg_name)

        # [Hook 1] 쓰기 전 값 읽기 (Old Value) - Diff를 위해
        # 해당 레지스터(sub-register 포함)의 현재 심볼릭 상태를 읽어옴
        _, old_sym, _ = self.get_register(reg_name)

        if new_sym_expr is not None:
            new_sym_expr = simplify(new_sym_expr)
            new_sym_expr = self._cap_expression(new_sym_expr)

        # ------------------------------------------------
        # 1. Root 레지스터인 경우
        # ------------------------------------------------
        if root_name == reg_name:
            self.regs_concrete[root_name] = new_conc_val
            if new_sym_expr is not None:
                self.regs_symbolic[root_name] = new_sym_expr
            else:
                self.regs_symbolic[root_name] = BitVecVal(new_conc_val, self.arch_mode)

            # [Hook 2] 훅 호출 (Root Update)
            if self.hook_reg_write:
                final_new_sym = new_sym_expr if new_sym_expr is not None else BitVecVal(new_conc_val,
                                                                                        self.arch_mode)
                self.hook_reg_write(reg_name.upper(), old_sym, final_new_sym)
            return

        # ------------------------------------------------
        # 2. 부분 레지스터인 경우
        # ------------------------------------------------
        # A. Concrete Update
        old_root_conc = self.regs_concrete.get(root_name, 0)
        mask = ((1 << size) - 1) << offset
        new_root_conc = (old_root_conc & ~mask) | ((new_conc_val << offset) & mask)
        self.regs_concrete[root_name] = new_root_conc

        # B. Symbolic Update
        _, current_root_expr, _ = self.get_register(root_name)
        root_bits = current_root_expr.size()

        parts = []
        if offset + size < root_bits:
            parts.append(Extract(root_bits - 1, offset + size, current_root_expr))

        if new_sym_expr is None:
            new_sym_expr = BitVecVal(new_conc_val, size)
        parts.append(new_sym_expr)

        if offset > 0:
            parts.append(Extract(offset - 1, 0, current_root_expr))

        if len(parts) > 1:
            self.regs_symbolic[root_name] = Concat(*parts)
        else:
            self.regs_symbolic[root_name] = parts[0]

        # [Hook 2] 훅 호출 (Partial Update)
        # 중요: Sub-register에 썼을 때, Root 전체가 아닌 '변경된 Sub-register' 기준으로 알림
        if self.hook_reg_write:
            self.hook_reg_write(reg_name.upper(), old_sym, new_sym_expr)

    def set_memory(self, addr, size, conc_val, sym_expr):
        if isinstance(conc_val, str):
            conc_val = int(conc_val, 0)

        # 1. 입력된 큰 수식 자체는 한 번 정리해도 됨 (전체 수식 최적화)
        if sym_expr is not None:
            sym_expr = simplify(sym_expr)
            sym_expr = self._cap_expression(sym_expr)
        else:
            sym_expr = BitVecVal(conc_val, size * 8)

        # [Hook] 쓰기 전 값 읽기 (Old Value) - Diff를 위해
        old_sym_for_hook = None
        if self.hook_memory_write:
            _, old_sym_for_hook = self.get_memory(addr, size)

        # Wide symbolic store: invalidate overlapping entries, then store
        write_end = addr + size
        overlapping = [k for k in self.mem_wide_symbolic
                       if k[0] < write_end and addr < k[0] + k[1]]
        for k in overlapping:
            del self.mem_wide_symbolic[k]
        if not z3.is_bv_value(sym_expr) and sym_expr.size() == size * 8:
            self.mem_wide_symbolic[(addr, size)] = sym_expr

        is_constant_input = z3.is_bv_value(sym_expr)
        constant_val = sym_expr.as_long() if is_constant_input else 0

        for i in range(size):
            curr_addr = addr + i

            # Concrete 값 업데이트
            byte_conc = (conc_val >> (8 * i)) & 0xFF
            self.mem_concrete[curr_addr] = byte_conc

            # Symbolic 값 업데이트
            if is_constant_input:
                # 상수는 Python 비트 연산으로 쪼개서 바로 BitVecVal로 저장
                byte_val = (constant_val >> (8 * i)) & 0xFF
                self.mem_symbolic[curr_addr] = BitVecVal(byte_val, 8)
            else:
                # [핵심 수정] 여기서 simplify를 절대 하지 마세요!
                # 쪼개진 조각(Extract)을 변형하지 않고 그대로 저장해야
                # 나중에 Concat 했을 때 원본 형태(arg1 + arg2)로 깔끔하게 합쳐집니다.
                low_bit = i * 8
                high_bit = low_bit + 7

                # simplify() 제거됨
                byte_sym = Extract(high_bit, low_bit, sym_expr)

                self.mem_symbolic[curr_addr] = byte_sym

        # Hook 호출
        if self.hook_memory_write:
            self.hook_memory_write(addr, old_sym_for_hook, sym_expr)

    def get_memory(self, addr, size):
        # Fast path: return full-width expression from wide store (avoids byte decomposition)
        wide_key = (addr, size)
        if wide_key in self.mem_wide_symbolic:
            conc_val = 0
            for i in range(size):
                conc_val |= (self.mem_concrete.get(addr + i, 0) << (8 * i))
            return conc_val, self.mem_wide_symbolic[wide_key]

        # 1. Concrete 값 읽기
        conc_val = 0
        for i in range(size):
            byte_val = self.mem_concrete.get(addr + i, 0)
            conc_val |= (byte_val << (8 * i))

        # 2. Symbolic 값 읽기
        sym_bytes = []
        is_all_constant = True

        for i in range(size):
            curr_addr = addr + i
            if curr_addr in self.mem_symbolic:
                s_byte = self.mem_symbolic[curr_addr]
            else:
                c_byte = self.mem_concrete.get(curr_addr, 0)
                s_byte = BitVecVal(c_byte, 8)

            if not z3.is_bv_value(s_byte):
                is_all_constant = False
            sym_bytes.append(s_byte)

        # 3. 결과 반환
        if is_all_constant:
            return conc_val, BitVecVal(conc_val, size * 8)
        else:
            # 바이트 합치기 (Little Endian: 뒤집어서 Concat)
            if len(sym_bytes) == 1:
                sym_expr = sym_bytes[0]
            else:
                sym_expr = Concat(*reversed(sym_bytes))

            # [핵심 해결책] simplify 호출 시 직접 파라미터 전달
            # bv_extract_prop=False:
            # "Extract(0, 7, A+B)를 Extract(A)+Extract(B)로 쪼개지 마라"는 명령입니다.
            # 이 옵션이 켜져 있어야(False여야) Concat이 "어? 이거 합치면 A+B네" 하고 알아봅니다.
            return conc_val, simplify(sym_expr, bv_extract_prop=False)

    # =========================================================================
    # [Utility] x64dbg Trace Loading
    # trace_line 예
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
    # =========================================================================
    def load_register_state(self, trace_line):
        """
        x64dbg Trace 한 줄(Dictionary)을 받아서 레지스터 Concrete 상태를 동기화.
        기존에 Taint된(심볼릭 상태인) 레지스터는 심볼을 유지하고 값만 바꿈.
        1. 레지스터 값 동기화 (regs 리스트)
        2. 메모리 읽기 값 선제 주입 (mem 리스트의 READ)
        """
        # 1. Register Loading (List -> Context)
        if 'regs' in trace_line:
            reg_values = trace_line['regs']

            # 아키텍처 모드에 따라 레지스터 순서 선택
            current_order = self.REG_ORDER_64 if self.arch_mode == 64 else self.REG_ORDER_32

            for i, val in enumerate(reg_values):
                if i < len(current_order):
                    reg_name = current_order[i]
                    # EIP/RIP, Flags는 값만 저장하고 심볼릭 추적은 리셋(None)
                    if reg_name in ['eip', 'rip', 'eflags', 'rflags']:
                        self.set_register(reg_name, val, None)
                        continue

                    # 기존 심볼릭 상태 확인
                    # 현재 레지스터가 이미 오염되어 있는지(심볼릭 수식이 있는지) 확인
                    _, curr_sym, _ = self.get_register(reg_name)

                    next_sym = None
                    # 상수가 아니라면(즉, Taint된 상태라면) 그 수식을 유지
                    if curr_sym is not None and not z3.is_bv_value(curr_sym):
                        next_sym = curr_sym

                    # Concrete 값은 Trace의 최신 값으로 덮어쓰되,
                    # Symbolic 식은 기존 것(next_sym)을 유지함. (None이면 상수로 변환됨)
                    self.set_register(reg_name, val, next_sym)

        # 2. 메모리 READ 선제 주입 (Just-in-Time Loading)
        # 명령어가 실행되기 전에, 이 명령어가 읽을 메모리 값을 미리 Context에 넣어둠
        if 'mem' in trace_line:
            for mem_access in trace_line['mem']:
                # 'READ'는 명령어가 실행되기 직전에 값을 읽어오는 과정이므로
                # 기존 메모리 상태(Taint)를 덮어쓰면 안 됨.
                if mem_access['access'] == 'READ':
                    addr = mem_access['addr']
                    value = mem_access['value']

                    # Trace에는 메모리 크기 정보가 없으므로 아키텍처 기본 단위(4 or 8 bytes) 가정
                    # 크기 정보가 Trace에 없다면 보통 4바이트(32bit)로 가정하거나
                    # Trace 생성 시 size 필드를 추가하는 것이 좋습니다.
                    size = self.root_reg_size

                    # [Memory Taint 유지]
                    # 1. 현재 해당 주소의 심볼릭 상태를 읽어옴
                    _, curr_mem_sym = self.get_memory(addr, size)

                    next_mem_sym = None
                    # 2. 상수가 아니라면(Taint 상태) 유지
                    if curr_mem_sym is not None and not z3.is_bv_value(curr_mem_sym):
                        next_mem_sym = curr_mem_sym

                    # 3. Concrete 값은 Trace대로 업데이트하되, Symbolic 식은 유지
                    self.set_memory(addr, size, value, next_mem_sym)

    # =========================================================================
    # [Utility] Verification (검증)
    # 코드 예) Trace 파일을 한 줄씩 읽는 루프 안에서
    # for line in trace_data:
    #     # 1. [Pre-Execution] 상태 동기화 및 메모리 주입
    #     #    (regs 리스트로 현재 상태 맞추고, READ할 메모리 미리 세팅)
    #     ctx.load_trace_line(line)
    #
    #     # 2. [Execution] 명령어 에뮬레이션 (Symbolic Execution)
    #     #    Triton이나 핸들러를 통해 실제 연산 수행
    #     #    예: emulate_instruction(ctx, line['disasm'])
    #     print(f"Executing: {line['disasm']}")
    #
    #     # ... 여기서 ctx.set_register(...) 등이 내부적으로 일어남 ...
    #
    #     # 3. [Post-Execution] 결과 검증 (Verification)
    #     #    내가 계산한 결과가 Trace의 'regchanges'/'mem(WRITE)'와 같은지 확인
    #     is_valid, msg = ctx.verify_state(line)
    #
    #     if not is_valid:
    #         print(f"[!] Critical Error at EIP {line.get('ip')}:")
    #         print(msg)
    #         # 여기서 멈추거나 디버깅 모드로 진입
    #         break
    #     else:
    #         print(f"    -> Verified. (Taint flows correctly)")
    # =========================================================================
    def verify_state(self, trace_line):
        """
        에뮬레이션 수행 '후'에 호출하여, 결과가 Trace와 일치하는지 검증.
        반환값: (Boolean 성공여부, 에러 메시지)
        """
        errors = []

        # 1. 레지스터 변경 검증 (regchanges)
        # format: "ebp: 0x4ff8 "
        if 'regchanges' in trace_line and trace_line['regchanges'].strip():
            changes = trace_line['regchanges'].split()  # ['ebp:', '0x4ff8'] 가정

            # 파싱 로직 (문자열 구조에 따라 조정 필요)
            # 예시: "reg: val reg2: val2" 형태라면 짝을 맞춰야 함
            # 여기서는 단순하게 "reg: val" 하나만 있다고 가정하거나 split 처리를 정교하게 해야 함

            # 간단 파서 (reg: value 쌍으로 순회)
            raw_changes = trace_line['regchanges'].replace(':', '').split()
            # raw_changes -> ['ebp', '0x4ff8']

            for i in range(0, len(raw_changes), 2):
                reg_name = raw_changes[i].lower()
                target_val_str = raw_changes[i + 1]
                target_val = int(target_val_str, 16)

                # Context의 현재 값 확인
                curr_val, _, _ = self.get_register(reg_name)

                if curr_val != target_val:
                    errors.append(
                        f"Reg Mismatch [{reg_name}]: Context({hex(curr_val)}) != Trace({hex(target_val)})")

        # 2. 메모리 쓰기 검증 (mem WRITE)
        if 'mem' in trace_line:
            for mem_access in trace_line['mem']:
                if mem_access['access'] == 'WRITE':
                    addr = mem_access['addr']
                    target_val = mem_access['value']

                    # Context의 메모리 값 확인 (4바이트 가정)
                    curr_val, _ = self.get_memory(addr, self.root_reg_size)

                    if curr_val != target_val:
                        errors.append(
                            f"Mem Mismatch [0x{addr:X}]: Context({hex(curr_val)}) != Trace({hex(target_val)})")

        if errors:
            return False, "\n".join(errors)
        return True, "OK"

    # =========================================================================
    # [Utility] Snapshot (Taint 상태 추출)
    # =========================================================================
    def simplify_all_symbolic(self) -> None:
        """Force z3.simplify() on every symbolic expression in-place.

        Reduces accumulated expression-tree complexity without changing semantics.
        Intended to be called at semantically meaningful boundaries (e.g. relay points).
        """
        for reg_name in list(self.regs_symbolic.keys()):
            sym = self.regs_symbolic[reg_name]
            if sym is not None and not z3.is_bv_value(sym):
                self.regs_symbolic[reg_name] = z3.simplify(sym)

        for addr in list(self.mem_symbolic.keys()):
            sym = self.mem_symbolic[addr]
            if sym is not None and not z3.is_bv_value(sym):
                self.mem_symbolic[addr] = z3.simplify(sym)

        # Wide-symbolic cache: simplify in-place (do NOT clear).
        # Each entry was stored via set_memory() already simplified; after simplifying
        # individual bytes above, the wide-cache expression is still mathematically
        # correct and in its best simplified form — preserving it allows get_memory()
        # to return the clean wide expression (e.g. "3707358608 + host_ecx") instead
        # of reconstructing a worse form from the individually-simplified bytes.
        for key in list(self.mem_wide_symbolic.keys()):
            sym = self.mem_wide_symbolic[key]
            if sym is not None and not z3.is_bv_value(sym):
                self.mem_wide_symbolic[key] = z3.simplify(sym)

    def canonicalize_symbolic(self, known_symbols) -> None:
        """Replace symbolic expressions provably equal to a known symbol with that symbol.

        Uses z3 Solver unsat-check: if (expr != sym) is unsat, expr always equals sym.
        Call after simplify_all_symbolic() at relay boundaries.
        """
        if not known_symbols:
            return

        s = z3.Solver()

        def first_match(expr):
            if expr is None or z3.is_bv_value(expr):
                return None
            for sym in known_symbols:
                if expr.size() != sym.size():
                    continue
                s.reset()
                s.add(expr != sym)
                if s.check() == z3.unsat:
                    return sym
            return None

        # 1. Registers (root_reg_size bits)
        for reg_name in list(self.regs_symbolic.keys()):
            match = first_match(self.regs_symbolic[reg_name])
            if match is not None:
                self.regs_symbolic[reg_name] = match

        # 2. Memory: try chunk_size-byte groups first
        chunk_size = self.root_reg_size  # 4 for 32-bit arch
        sorted_addrs = sorted(self.mem_symbolic.keys())
        processed = set()

        for addr in sorted_addrs:
            if addr in processed:
                continue

            # Check if all chunk_size bytes exist and are tainted
            all_tainted = all(
                self.mem_symbolic.get(addr + i) is not None
                and not z3.is_bv_value(self.mem_symbolic[addr + i])
                for i in range(chunk_size)
            )

            if all_tainted:
                _, wide_expr = self.get_memory(addr, chunk_size)
                match = first_match(wide_expr)
                if match is not None:
                    for i in range(chunk_size):
                        self.mem_symbolic[addr + i] = z3.Extract(8 * i + 7, 8 * i, match)
                        processed.add(addr + i)
                    self.mem_wide_symbolic[(addr, chunk_size)] = match
                    continue

            # Fallback: individual byte (8-bit symbols only, rare)
            match = first_match(self.mem_symbolic.get(addr))
            if match is not None:
                self.mem_symbolic[addr] = match
            processed.add(addr)

    def get_symbolic_state_snapshot(self):
        """
        현재 Context에서 상수가 아닌(오염된) 레지스터와 메모리 목록을 추출하여 반환.
        메모리의 경우, 인접한 바이트를 묶어서(Word Size) 하나의 변수로 표현.
        :return: List of dict [{'name': '...', 'symbol': '...'}, ...]
        """
        current_taints = []

        # 1. 레지스터 상태 스캔
        for reg_name, sym_expr in self.regs_symbolic.items():
            # 상수가 아닐 때만 저장
            if sym_expr is not None and not z3.is_bv_value(sym_expr):
                taint_info = {
                    'name': reg_name.upper(),
                    'symbol': _z3_bv_to_str(sym_expr)
                }
                current_taints.append(taint_info)

        # 2. 메모리 상태 스캔
        # 키(주소)를 정렬하여 순회
        sorted_addrs = sorted(self.mem_symbolic.keys())
        processed_addrs = set()  # 이미 묶어서 출력한 주소는 건너뛰기 위함

        # 아키텍처 단위 (32bit=4, 64bit=8)
        chunk_size = self.root_reg_size

        for addr in sorted_addrs:
            if addr in processed_addrs:
                continue

            # 해당 주소의 값 확인
            sym_expr = self.mem_symbolic[addr]
            if sym_expr is None or z3.is_bv_value(sym_expr):
                continue

            # [Chunking 시도]
            # 현재 주소부터 chunk_size만큼 연속된 주소가 모두 Tainted인지 확인
            is_chunk_tainted = True
            chunk_bytes = []

            for i in range(chunk_size):
                curr = addr + i
                # 메모리에 존재하고, 심볼릭(Tainted) 상태여야 함
                if curr in self.mem_symbolic:
                    val = self.mem_symbolic[curr]
                    if val is not None and not z3.is_bv_value(val):
                        chunk_bytes.append(val)
                    else:
                        is_chunk_tainted = False
                        break
                else:
                    is_chunk_tainted = False
                    break

            # [Case A] Chunking 성공 (4/8바이트가 모두 오염됨 -> 합치기 시도)
            if is_chunk_tainted:
                _, merged_expr = self.get_memory(addr, chunk_size)

                taint_info = {
                    'name': f"Mem[{hex(addr)}] (Chunk {chunk_size}B)",
                    'symbol': _z3_bv_to_str(merged_expr)
                }
                current_taints.append(taint_info)

                # 처리된 주소들 마킹
                for i in range(chunk_size):
                    processed_addrs.add(addr + i)

            # [Case B] Chunking 실패 (낱개로 출력)
            else:
                taint_info = {
                    'name': f"Mem[{hex(addr)}]",
                    'symbol': _z3_bv_to_str(sym_expr)
                }
                current_taints.append(taint_info)
                processed_addrs.add(addr)

        return current_taints


# =============================================================================
# 사용 예시
# =============================================================================
if __name__ == "__main__":
    # -------------------------------------------------------------------------
    # Test Case 1: 32-bit Architecture (수정됨)
    # -------------------------------------------------------------------------
    print("\n" + "=" * 50)
    print("=== [Test 1] 32-bit Architecture Trace Check ===")
    print("=" * 50)

    ctx32 = TraceContext(arch_mode=32)

    # User's 32-bit sample
    # EAX = 3806 (Decimal) -> 0xEDE (Hex) **중요**
    trace_sample_32 = {
        'id': 0, 'ip': 4242012,
        'regs': [3806, 309, 326, 292, 0, 20476, 360, 377, 4242012, 0],  # regs[0]=EAX
    }

    ctx32.load_register_state(trace_sample_32)

    # 1. Verify EAX Load
    c, s, sz = ctx32.get_register('eax')
    print(f"EAX (Root): {hex(c)} (Expected: 0xede)")  # 3806 == 0xEDE

    # 2. Verify Sub-registers
    # EAX = 0x00000EDE
    # AL  = 0xDE (1101 1110)
    # AH  = 0x0E (0000 1110)
    c_al, _, _ = ctx32.get_register('al')
    c_ah, _, _ = ctx32.get_register('ah')
    print(f"AL Read   : {hex(c_al)} (Expected: 0xde)")
    print(f"AH Read   : {hex(c_ah)} (Expected: 0xe)")

    # 3. Symbolic Write Test
    print("[Action] Writing Symbolic 'sym_ah=0xFF' to AH...")
    sym_ah = BitVec('sym_ah', 8)
    ctx32.set_register('ah', 0xFF, sym_ah)

    c_new, s_new, _ = ctx32.get_register('eax')
    print(f"New EAX   : {hex(c_new)} (Expected: 0xffde)")
    # 원래 EAX(0xEDE)에서 AH(0x0E)를 0xFF로 교체 -> 0xFFDE

    # 4. Z3 Verification
    s = Solver()
    s.add(s_new == 0xffde)  # 0xffee가 아니라 0xffde가 정답
    print(f"Logic Check (s_new == 0xffde): {s.check()}")

    # -------------------------------------------------------------------------
    # Test Case 2: 64-bit Architecture
    # -------------------------------------------------------------------------
    print("\n" + "=" * 50)
    print("=== [Test 2] 64-bit Architecture Trace Check ===")
    print("=" * 50)

    ctx64 = TraceContext(arch_mode=64)

    # 64-bit Mock Trace
    # RAX = 0x1122334455667788
    # RBX = 0xFFFFFFFFFFFFFFFF
    trace_sample_64 = {
        'id': 1,
        'regs': [
            0x1122334455667788,  # RAX
            0xFFFFFFFFFFFFFFFF,  # RBX
            0, 0, 0, 0, 0, 0,  # RCX ~ RDI
            8, 9, 10, 11, 12, 13, 14, 15,  # R8 ~ R15
            0x400000, 0  # RIP, RFLAGS
        ]
    }

    ctx64.load_register_state(trace_sample_64)

    # 1. Verify RAX Load
    c_rax, s_rax, sz_rax = ctx64.get_register('rax')
    print(f"RAX (Root): {hex(c_rax)}")

    # 2. Verify Sub-registers (EAX, AX, AL)
    # EAX = 0x55667788 (Lower 32-bit)
    # AX  = 0x7788
    # AL  = 0x88
    c_eax, _, sz_eax = ctx64.get_register('eax')
    c_al, _, sz_al = ctx64.get_register('al')

    print(f"EAX Read  : {hex(c_eax)} (Size: {sz_eax})")
    print(f"AL Read   : {hex(c_al)} (Size: {sz_al})")

    # 3. 64-bit Memory Access Test
    print("[Action] Writing 0xAABBCCDDEEFF0011 to Mem[0x100]")
    ctx64.set_memory(0x100, 8, 0xAABBCCDDEEFF0011, None)

    mem_val, _ = ctx64.get_memory(0x100, 8)
    print(f"Mem Read  : {hex(mem_val)}")

    # 4. Symbolic Integration Test (Partial Register Write)
    # AL에 심볼을 쓰고 RAX 전체가 어떻게 변하는지 확인
    print("[Action] Writing Symbolic 'sym_al' to AL...")
    sym_al = BitVec('sym_al', 8)
    ctx64.set_register('al', 0x99, sym_al)

    c_final, s_final, _ = ctx64.get_register('rax')

    # 원래: 0x1122334455667788 -> AL(88)을 99로 변경 -> 0x1122334455667799
    print(f"New RAX   : {hex(c_final)} (Expected: 0x1122334455667799)")
    print(f"Symbolic Structure:\n{s_final}")

    # Z3 Check
    s64 = Solver()
    s64.add(s_final == 0x1122334455667799)
    print(f"Logic Check: {s64.check()}")
