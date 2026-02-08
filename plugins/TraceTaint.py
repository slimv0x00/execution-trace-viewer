from z3 import *
from .TraceOperand import OperandType


class TraceTaint:
    def __init__(self, ctx):
        """
        :param ctx: TraceContext 인스턴스 (상태 저장소)
        """
        self.ctx = ctx
        self.arch_bytes = ctx.arch_mode // 8  # 4 bytes (32bit) or 8 bytes (64bit)

        # 명령어 핸들러 매핑 (Dispatcher Pattern)
        self.handlers = {
            # 데이터 이동
            'MOV': self._handle_mov,
            'MOVZX': self._handle_mov,
            'MOVSX': self._handle_mov,
            'LEA': self._handle_lea,

            # 스택 조작 (기존)
            'PUSH': self._handle_push,
            'POP': self._handle_pop,

            # [New] 스택 조작 (Flags & All Regs)
            'PUSHFD': self._handle_pushfd,
            'POPFD': self._handle_popfd,
            'PUSHAD': self._handle_pushad,  # 32-bit only
            'POPAD': self._handle_popad,  # 32-bit only

            # [New] 제어 흐름
            'CALL': self._handle_call,
            'JMP': self._handle_jmp,

            # 산술 연산
            'ADD': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x + y),
            'SUB': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x - y),
            'IMUL': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x * y),

            # 논리 연산
            'XOR': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x ^ y),
            'OR': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x | y),
            'AND': lambda i, ip: self._handle_binary_op(i, ip, lambda x, y: x & y),

            # 단항 연산
            'NEG': lambda i, ip: self._handle_unary_op(i, ip, lambda x: -x, update_flags=True),
            'INC': lambda i, ip: self._handle_unary_op(i, ip, lambda x: x + 1, update_flags=True),
            'DEC': lambda i, ip: self._handle_unary_op(i, ip, lambda x: x - 1, update_flags=True),

            # Flags 업데이트 X (NOT은 False로 설정)
            'NOT': lambda i, ip: self._handle_unary_op(i, ip, lambda x: ~x, update_flags=False),

            'XCHG': self._handle_xchg,

            # [Shift]
            'SHL': lambda i, ip: self._handle_shift_op(i, ip, 'SHL'),
            'SHR': lambda i, ip: self._handle_shift_op(i, ip, 'SHR'),
            'SAR': lambda i, ip: self._handle_shift_op(i, ip, 'SAR'),

            # Atomic Operations
            'XADD': self._handle_xadd,
            'CMPXCHG': self._handle_cmpxchg,

            # Logical Compare
            'CMP': self._handle_cmp,
            'TEST': self._handle_test,

            # [Arithmetic - Flags Dependent]
            'ADC': lambda i, ip: self._handle_adc_sbb(i, ip, 'ADC'),
            'SBB': lambda i, ip: self._handle_adc_sbb(i, ip, 'SBB'),

            # [Multiply / Divide - Unsigned]
            'MUL': lambda i, ip: self._handle_mul_div(i, ip, 'MUL'),
            'DIV': lambda i, ip: self._handle_mul_div(i, ip, 'DIV'),
            # (참고) IDIV(Signed Div)도 DIV와 로직이 거의 같으므로 공유 가능
            'IDIV': lambda i, ip: self._handle_mul_div(i, ip, 'DIV'),

            # [Rotate]
            'ROL': lambda i, ip: self._handle_rotate(i, ip, 'ROL'),
            'ROR': lambda i, ip: self._handle_rotate(i, ip, 'ROR'),

            # [Return]
            'RET': self._handle_ret,
            'RETN': self._handle_ret,

            # [Flags Control]
            'STD': self._handle_std,
            'CLD': self._handle_cld,
        }

        # [Control Flow - Conditional (Jcc)]
        # 모든 조건부 점프를 _handle_jcc로 연결
        jcc_list = [
            'JE', 'JNE', 'JZ', 'JNZ',
            'JA', 'JAE', 'JB', 'JBE',
            'JC', 'JNC', 'JG', 'JGE', 'JL', 'JLE',
            'JS', 'JNS', 'JO', 'JNO', 'JP', 'JNP',
            'JPE', 'JPO'
        ]
        for jcc in jcc_list:
            self.handlers[jcc] = self._handle_jcc

    # =========================================================================
    # [Public] Taint Source 설정 (오염 시작점)
    # =========================================================================
    def add_taint_register(self, reg_name, var_name=None):
        """특정 레지스터를 심볼릭 변수로 만듦 (Taint Source)"""
        if var_name is None:
            var_name = f"sym_{reg_name}"

        # 레지스터 크기에 맞는 심볼 생성
        _, _, size = self.ctx.get_register(reg_name)
        sym_var = BitVec(var_name, size)  # size is already in bits

        # 현재 Concrete 값은 유지하고, Symbolic 식만 주입
        curr_conc, _, _ = self.ctx.get_register(reg_name)
        self.ctx.set_register(reg_name, curr_conc, sym_var)
        print(f"[+] Taint Source Added: {reg_name} = {sym_var}")

    def add_taint_memory(self, addr, size, var_name=None):
        """특정 메모리를 심볼릭 변수로 만듦"""
        if var_name is None:
            var_name = f"sym_mem_{hex(addr)}"

        sym_var = BitVec(var_name, size * 8)
        curr_conc, _ = self.ctx.get_memory(addr, size)
        self.ctx.set_memory(addr, size, curr_conc, sym_var)
        print(f"[+] Taint Source Added: Mem[{hex(addr)}] = {sym_var}")

    # =========================================================================
    # [Core] Instruction Processing
    # =========================================================================
    def process_instruction(self, inst_data):
        # 1. TraceInstruction 객체 활용
        inst_obj = inst_data.get('instruction_obj')

        if inst_obj:
            # [핵심] Capstone은 소문자를 주므로 반드시 .upper() 호출!
            mnemonic = inst_obj.mnemonic.upper()
        else:
            # 기존 문자열 파싱 방식 (Fallback)
            disasm = inst_data.get('disasm', '').upper()  # 여기서도 upper()
            parts = disasm.split()
            mnemonic = parts[0] if parts else ''

            # LOCK 처리
            if mnemonic == 'LOCK' and len(parts) > 1:
                mnemonic = parts[1]

        operands = inst_data.get('parsed_operands', [])
        current_ip = inst_data.get('ip')

        # 2. 핸들러 실행
        if mnemonic in self.handlers:
            try:
                self.handlers[mnemonic](operands, current_ip)
            except Exception as e:
                print(f"[!] Error processing {mnemonic} ({inst_data.get('disasm', '')}): {e}")
                return False  # 에러 발생 시 중단
        else:
            # 핸들러가 없으면 로그를 남기고 진행할지, 중단할지 결정
            # (대소문자 문제가 해결되면 이 로그는 진짜 모르는 명령어일 때만 뜸)
            print(f"[!] Unknown instruction {mnemonic}")
            return False  # Unknown시 중단

        return True

    # =========================================================================
    # [Helper] Stack Pointer Utils
    # =========================================================================
    def _get_sp(self):
        """현재 스택 포인터(ESP/RSP)의 (Concrete, Symbolic) 값을 반환"""
        sp_reg = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        return self.ctx.get_register(sp_reg)

    def _update_sp(self, offset_bytes):
        """스택 포인터를 offset만큼 변경 (Push: -offset, Pop: +offset)"""
        sp_reg = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        sp_c, sp_s, _ = self.ctx.get_register(sp_reg)

        # Symbolic Update
        new_sp_s = sp_s + offset_bytes
        # Concrete Update
        self.ctx.set_register(sp_reg, sp_c + offset_bytes, new_sp_s)
        return sp_c + offset_bytes, new_sp_s  # 변경된 SP 반환

    def _update_flags(self, dependency_expr):
        """
        [Helper] 연산 결과(dependency_expr)에 따라 EFLAGS를 Taint 시킴.
        구체적인 Flag 비트(ZF, SF...)를 계산하기보다,
        'Flags 전체가 이 연산 결과에 의존한다'고 설정하는 것이 Taint 분석에 효율적임.
        """
        if dependency_expr is None:
            return

        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'

        # 1. 현재 Flags의 Concrete 값 가져오기 (값은 유지)
        flags_c, _, _ = self.ctx.get_register(flags_reg)

        # 2. Flags에 Taint 전파
        # 연산 결과(dependency_expr)가 Taint라면 Flags도 Taint됨
        self.ctx.set_register(flags_reg, flags_c, dependency_expr)

    # =========================================================================
    # [Handlers] Control Flow (CALL, JMP, Jcc)
    # =========================================================================
    def _handle_call(self, operands, ip):
        """
        CALL target
        1. Return Address (Next IP) PUSH -> Stack
        2. Jump to target
        """
        if len(operands) < 1: return

        # 1. Return Address 계산
        # 원칙: ret_addr = ip + instruction_length
        # 핸들러 인자로 길이(length)를 받지 못하는 구조라면,
        # 임시로 '현재 ip'를 넣거나, 0을 넣어도 Taint 분석 흐름엔 큰 지장 없음 (Ret Addr가 오염원인 경우는 드물기에)
        # 만약 정확한 값을 원하면 process_instruction에서 길이를 넘겨주도록 구조 변경 필요.
        ret_addr_c = ip
        ret_addr_s = BitVecVal(ret_addr_c, self.ctx.arch_mode)

        # 2. SP(Stack Pointer) 감소
        sp_reg = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        sp_c, sp_s, _ = self.ctx.get_register(sp_reg)
        arch_bytes = self.ctx.arch_mode // 8

        new_sp_c = sp_c - arch_bytes
        new_sp_s = sp_s - arch_bytes  # SP 자체의 Taint 전파 (보통은 상수)

        # 3. 메모리에 Return Address 쓰기 (PUSH 동작)
        # 먼저 SP 레지스터 업데이트 (PUSH 전에 SP가 감소하므로)
        self.ctx.set_register(sp_reg, new_sp_c, new_sp_s)

        # 감소된 SP 위치에 Return Address 저장
        # (SP는 방금 업데이트했으므로 set_memory 호출 시 내부적으로 계산된 주소 사용 가능하지만,
        #  여기선 명시적으로 주소를 지정해서 호출)
        self.ctx.set_memory(new_sp_c, arch_bytes, ret_addr_c, ret_addr_s)

        # 4. Jump 수행 (EIP 변경)
        self._handle_jmp(operands, ip)

    def _handle_jmp(self, operands, ip):
        """
        JMP target (Unconditional)
        """
        if len(operands) < 1: return
        target = operands[0]

        # 타겟 주소 읽기 (Register or Memory or Imm)
        # JMP EAX -> EAX가 Taint면 EIP도 Taint (Computed Jump)
        # JMP 0x401000 -> 상수는 Clean
        val_c, val_s = target.read(self.ctx, ip)

        # EIP/RIP 업데이트
        ip_reg = 'rip' if self.ctx.arch_mode == 64 else 'eip'
        self.ctx.set_register(ip_reg, val_c, val_s)

        # [Analysis Point] 제어 흐름 오염 탐지
        # (목적지 주소 자체가 계산된 값인 경우)
        if val_s is not None and not z3.is_bv_value(val_s):
            # print(f"[!] Computed Jump detected at {hex(ip)} (Target Tainted)")
            pass

    def _handle_jcc(self, operands, ip):
        """
        Jcc target (Conditional Jump: JE, JNE, JBE, etc.)
        Logic:
          1. Check EFLAGS Taint (Implicit Control Flow Taint)
          2. Update EIP (Delegated to _handle_jmp)
        """
        # 1. Flags 의존성 확인
        # 조건부 점프는 Flags 상태에 따라 분기가 결정됨.
        # 따라서 Flags가 오염되었다면, '실행 흐름(Path)' 자체가 오염된 데이터에 의해 결정된 것임.
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'
        _, flags_s, _ = self.ctx.get_register(flags_reg)

        if flags_s is not None and not z3.is_bv_value(flags_s):
            # [Implicit Taint]
            # 분기 조건이 오염됨. 엄밀히 따지면 이후 실행되는 명령어들은
            # 이 분기에 의해 선택된 것이므로 '제어 종속성(Control Dependency)'을 가짐.
            # 하지만 모든 레지스터를 오염시키면 Taint Explosion이 발생하므로,
            # 여기서는 로그를 남기거나 코멘트에 표시하는 정도로 처리함.

            # (옵션) Trace 코멘트에 표시하고 싶다면 return 값을 활용하거나 ctx에 기록
            # print(f"[!] Tainted Branch Decision at {hex(ip)} (Flags Tainted)")
            pass

        # 2. 실제 점프 수행 (EIP 변경)
        # Trace Viewer는 이미 결정된 경로를 따라가므로, 조건 계산 없이
        # Trace에 기록된 오퍼랜드(Target Address)로 EIP를 갱신하면 됨.
        self._handle_jmp(operands, ip)

    # =========================================================================
    # [Handlers] Flags (PUSHFD, POPFD)
    # =========================================================================
    def _handle_pushfd(self, operands, ip):
        """EFLAGS/RFLAGS 레지스터를 스택에 PUSH"""
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'

        # Flags 읽기
        val_c, val_s, _ = self.ctx.get_register(flags_reg)

        # SP 감소
        self._update_sp(-self.arch_bytes)

        # 메모리에 쓰기
        sp_c, sp_s, _ = self._get_sp()
        self.ctx.set_memory(sp_c, self.arch_bytes, val_c, val_s)

    def _handle_popfd(self, operands, ip):
        """스택에서 값을 꺼내 EFLAGS/RFLAGS에 설정"""
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'

        # SP 위치에서 값 읽기
        sp_c, sp_s, _ = self._get_sp()
        val_c, val_s = self.ctx.get_memory(sp_c, self.arch_bytes)

        # Flags 업데이트
        self.ctx.set_register(flags_reg, val_c, val_s)

        # SP 증가
        self._update_sp(self.arch_bytes)

    # =========================================================================
    # [Handlers] Push/Pop All (PUSHAD, POPAD) - 32bit Only
    # =========================================================================
    def _handle_pushad(self, operands, ip):
        """
        Push EAX, ECX, EDX, EBX, Original ESP, EBP, ESI, EDI
        주의: ESP는 PUSHAD 실행 전의 값을 저장함.
        """
        if self.ctx.arch_mode == 64:
            return  # 64비트에는 없는 명령어 (Invalid Opcode)

        # 1. Original ESP 저장
        original_sp_c, original_sp_s, _ = self._get_sp()

        # PUSH 순서: EAX, ECX, EDX, EBX, ESP(Org), EBP, ESI, EDI
        regs_to_push = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']

        for reg in regs_to_push:
            # 값 준비
            if reg == 'esp':
                val_c, val_s = original_sp_c, original_sp_s
            else:
                val_c, val_s, _ = self.ctx.get_register(reg)

            # Push Logic (SP-4, Write)
            self._update_sp(-4)
            curr_sp_c, _, _ = self._get_sp()
            self.ctx.set_memory(curr_sp_c, 4, val_c, val_s)

    def _handle_popad(self, operands, ip):
        """
        Pop EDI, ESI, EBP, (skip ESP), EBX, EDX, ECX, EAX
        주의: 스택의 ESP 자리는 읽어서 버림 (ESP 레지스터를 덮어쓰지 않음)
        """
        if self.ctx.arch_mode == 64:
            return

        # POP 순서 (PUSH의 역순)
        regs_to_pop = ['edi', 'esi', 'ebp', 'esp', 'ebx', 'edx', 'ecx', 'eax']

        for reg in regs_to_pop:
            # 현재 SP에서 읽기
            curr_sp_c, _, _ = self._get_sp()
            val_c, val_s = self.ctx.get_memory(curr_sp_c, 4)

            # SP 증가 (+4)
            self._update_sp(4)

            # 레지스터 복구 (ESP는 제외하고 값만 버림)
            if reg != 'esp':
                self.ctx.set_register(reg, val_c, val_s)

    # =========================================================================
    # [Handlers] Semantic Logic
    # =========================================================================
    def _handle_mov(self, operands, ip):
        """MOV dest, src"""
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        # Source 읽기
        val_c, val_s = src.read(self.ctx, ip)

        # Destination 쓰기
        dst.write(self.ctx, val_c, val_s, ip)

    def _handle_lea(self, operands, ip):
        """LEA dest, [mem] -> 주소 자체를 값으로 저장"""
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        if src.type == OperandType.MEM:
            # LEA는 메모리 '값'을 읽는 게 아니라 '주소'를 계산해서 저장함
            # TraceOperand.resolve_addr 사용
            addr_c, addr_s = src.resolve_addr(self.ctx, ip)
            dst.write(self.ctx, addr_c, addr_s, ip)

    def _handle_binary_op(self, operands, ip, z3_op_func):
        """ADD, SUB, XOR, etc (dest = dest OP src)"""
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        # 1. 값 읽기
        dst_c, dst_s = dst.read(self.ctx, ip)
        src_c, src_s = src.read(self.ctx, ip)

        # 2. 연산 수행 (Concrete & Symbolic)
        # Concrete 연산은 Python 연산자 오버로딩 or 마스킹 필요하지만
        # 여기서는 Z3 식 생성에 집중 (Concrete 값은 TraceContext가 정답지(regchanges)로 보정하므로 생략 가능)
        # 하지만 시뮬레이션을 위해 단순 연산 수행 (Overflow 무시)
        # new_conc = z3_op_func(dst_c, src_c) # Python int끼리 연산

        # Z3 연산 (핵심)
        # dst_s와 src_s는 이미 BitVec이거나 BitVecVal(상수)임
        new_sym = z3_op_func(dst_s, src_s)

        # 단순화 (선택 사항: 식이 너무 커지는 것 방지)
        # new_sym = simplify(new_sym)

        # 3. 결과 쓰기
        # Concrete 값은 정확성을 위해 Trace의 regchanges를 믿거나, 여기서 계산해서 넣음
        # 일단은 0이나 dst_c로 넣어두고, Context의 load_trace_line이 보정하게 하는 패턴 추천
        dst.write(self.ctx, 0, new_sym, ip)

        # 3. [핵심] Flags 업데이트 추가
        self._update_flags(new_sym)

    def _handle_unary_op(self, operands, ip, z3_op_func, update_flags=True):
        """NOT, NEG, INC, DEC (dest = OP dest)"""
        if len(operands) < 1: return
        dst = operands[0]

        val_c, val_s = dst.read(self.ctx, ip)
        new_sym = z3_op_func(val_s)

        dst.write(self.ctx, 0, new_sym, ip)

        if update_flags:
            self._update_flags(new_sym)

    # =========================================================================
    # [Handlers] Stack Operations (PUSH, POP)
    # =========================================================================
    def _handle_push(self, operands, ip):
        """
        PUSH src
        TraceInstruction 변환 후: operands = [src, implicit_mem_dst]
        """
        if len(operands) < 2: return

        # 순서: Source(값) -> Dest(스택 메모리)
        src = operands[0]
        dst_mem = operands[1]  # [ESP-4] (Implicit)

        # 1. Source 값 읽기
        val_c, val_s = src.read(self.ctx, ip)

        # 2. Dest 메모리에 쓰기
        # 주의: 아직 ESP를 감소시키기 전이므로, dst_mem([ESP-4])이 가리키는 주소는
        # '현재 ESP - 4'가 됩니다. 이는 PUSH가 값을 넣을 올바른 위치입니다.
        dst_mem.write(self.ctx, val_c, val_s, ip)

        # 3. ESP 레지스터 업데이트 (Manual Update)
        # TraceInstruction은 메모리 쓰기 동작만 오퍼랜드로 줬지, ESP 감소는 안 줬으므로 수동 처리
        sp_reg = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        sp_c, sp_s, _ = self.ctx.get_register(sp_reg)

        new_sp_c = sp_c - (self.ctx.arch_mode // 8)
        new_sp_s = sp_s - (self.ctx.arch_mode // 8)

        self.ctx.set_register(sp_reg, new_sp_c, new_sp_s)

    def _handle_pop(self, operands, ip):
        """
        POP dst
        Logic:
          1. val = Read [ESP]
          2. ESP = ESP + 4  <-- 먼저 증가!
          3. Write val to dst
        TraceInstruction 변환 후: operands = [implicit_mem_src, dst]
        """
        if len(operands) < 2: return

        # 순서: Source(스택 메모리) -> Dest(레지스터)
        src_mem = operands[0]  # [ESP] (Implicit)
        dst = operands[1]  # Register (Target)

        # ---------------------------------------------------------------------
        # 1. 스택 메모리에서 값 읽기 (Read from Old ESP)
        # ---------------------------------------------------------------------
        # 아직 ESP를 증가시키기 전이므로, 현재 Top of Stack을 읽습니다.
        val_c, val_s = src_mem.read(self.ctx, ip)

        # ---------------------------------------------------------------------
        # 2. ESP 레지스터 먼저 업데이트 (Increment ESP)
        # ---------------------------------------------------------------------
        # x86 동작 원리상 Write보다 ESP 증가가 물리적으로 먼저 일어난다고 봐야
        # dst가 [ESP]일 때 올바른 주소(Old ESP + 4)에 쓸 수 있습니다.

        sp_reg_name = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        sp_c, sp_s, _ = self.ctx.get_register(sp_reg_name)

        arch_bytes = self.ctx.arch_mode // 8
        new_sp_c = sp_c + arch_bytes
        # ESP 심볼릭 추적은 보통 불필요하므로 상수로 처리하거나 심볼릭 더하기 수행
        if z3.is_bv_value(sp_s):
            new_sp_s = sp_s + arch_bytes
        else:
            new_sp_s = simplify(sp_s + arch_bytes)

        self.ctx.set_register(sp_reg_name, new_sp_c, new_sp_s)

        # ---------------------------------------------------------------------
        # 3. Destination에 쓰기 (Write to dst)
        # ---------------------------------------------------------------------
        # Case A: POP [ESP]
        #   - 위에서 ESP가 증가되었으므로, dst.write() 내부에서
        #   - resolve_addr이 증가된 ESP를 참조하여 0xd3f9dc에 값을 씁니다. (성공!)
        #
        # Case B: POP ESP
        #   - 위에서 ESP가 증가되었지만, 여기서 dst(ESP)에 val을 덮어씁니다.
        #   - 결과적으로 ESP = val 이 됩니다. (성공!)
        #
        # Case C: POP EAX
        #   - EAX에 val을 씁니다. (성공!)

        dst.write(self.ctx, val_c, val_s, ip)

    def _handle_xchg(self, operands, ip):
        """
        XCHG op1, op2
        두 오퍼랜드의 값을 교환함.
        """
        if len(operands) < 2: return
        op1, op2 = operands[0], operands[1]

        # 1. 두 값을 먼저 모두 읽어옴 (Context가 변하기 전)
        val1_c, val1_s = op1.read(self.ctx, ip)
        val2_c, val2_s = op2.read(self.ctx, ip)

        # 2. 쓰기 수행 (Pointer Aliasing 방지 로직)
        # 만약 "XCHG EAX, [EAX]" 같은 명령어가 있다면,
        # EAX를 먼저 업데이트해버리면 [EAX] 주소 계산 시 바뀐 EAX를 쓰게 되어 엉뚱한 메모리에 씀.
        # 따라서, 메모리 오퍼랜드가 있다면 그것부터 먼저 업데이트해야 함.

        if op1.type == OperandType.MEM:
            # Op1이 메모리: Op1 먼저 쓰고 -> Op2(레지스터) 씀
            op1.write(self.ctx, val2_c, val2_s, ip)
            op2.write(self.ctx, val1_c, val1_s, ip)
        elif op2.type == OperandType.MEM:
            # Op2가 메모리: Op2 먼저 쓰고 -> Op1(레지스터) 씀
            op2.write(self.ctx, val1_c, val1_s, ip)
            op1.write(self.ctx, val2_c, val2_s, ip)
        else:
            # 둘 다 레지스터인 경우: 순서 상관없음
            op1.write(self.ctx, val2_c, val2_s, ip)
            op2.write(self.ctx, val1_c, val1_s, ip)

    def _handle_shift_op(self, operands, ip, mode):
        """
        Shift Operation Handler
        :param mode: 'SHL' (<<), 'SHR' (LShR), 'SAR' (ASHR)
        """
        if len(operands) < 2: return
        dst, count = operands[0], operands[1]

        # 1. 값 읽기
        d_c, d_s = dst.read(self.ctx, ip)
        c_c, c_s = count.read(self.ctx, ip)

        # 2. Z3 비트 수 맞추기 (Shift Count Extension)
        # 예: SHL EAX, CL -> CL(8bit)을 EAX(32bit) 크기로 확장해야 연산 가능
        if d_s.size() > c_s.size():
            c_s = z3.ZeroExt(d_s.size() - c_s.size(), c_s)

        # 3. 연산 수행 (Symbolic & Concrete)
        new_sym = None
        new_conc = 0

        # Python의 쉬프트 연산은 음수 처리가 까다로울 수 있어 마스킹 적용
        mask = (1 << d_s.size()) - 1

        if mode == 'SHL':
            new_sym = z3.simplify(d_s << c_s)
            new_conc = (d_c << c_c) & mask
        elif mode == 'SHR':
            # Logical Shift Right (0 채움)
            new_sym = z3.simplify(z3.LShR(d_s, c_s))
            new_conc = (d_c >> c_c) & mask
        elif mode == 'SAR':
            # Arithmetic Shift Right (부호 유지)
            new_sym = z3.simplify(z3.ASHR(d_s, c_s))
            # Python >>는 기본적으로 Arithmetic Shift지만,
            # Unsigned로 읽어온 d_c를 Signed로 변환 후 처리하는 로직이 복잡하므로
            # 여기서는 Taint 전파에 집중하여 단순 처리하거나 별도 유틸 함수 필요.
            # (Taint 분석에서는 Concrete 값보다 Symbolic 연결이 중요함)
            new_conc = d_c >> c_c

            # 4. 결과 쓰기
        dst.write(self.ctx, new_conc, new_sym, ip)

        # 5. [핵심] Flags 업데이트
        self._update_flags(new_sym)

    # =========================================================================
    # [Handlers] Atomic Instructions (LOCK prefix common)
    # =========================================================================
    def _handle_xadd(self, operands, ip):
        """
        XADD dest, src
        Temp = dest + src
        src = dest (Original)
        dest = Temp (Sum)
        Flags affected by the addition (Temp)
        """
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        # 1. 값 읽기
        d_c, d_s = dst.read(self.ctx, ip)
        s_c, s_s = src.read(self.ctx, ip)

        # (필요 시 비트 확장 로직 추가)

        # 2. 덧셈 연산
        sum_sym = z3.simplify(d_s + s_s)
        sum_conc = d_c + s_c

        # 3. 값 교환 및 쓰기
        # src에는 원래 dest 값을 씀
        src.write(self.ctx, d_c, d_s, ip)

        # dest에는 합계(sum)를 씀
        dst.write(self.ctx, sum_conc, sum_sym, ip)

        # 4. [핵심] Flags 업데이트 (덧셈 결과에 의존)
        self._update_flags(sum_sym)

    def _handle_cmpxchg(self, operands, ip):
        """
        CMPXCHG dest, src
        1. Compare Accumulator with Dest (Updates Flags)
        2. If Equal (ZF=1): Dest = Src
        3. Else (ZF=0): Accumulator = Dest
        """
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        # 1. Accumulator 레지스터 결정
        size_bytes = dst.size
        if size_bytes == 1:
            acc_name = 'al'
        elif size_bytes == 2:
            acc_name = 'ax'
        elif size_bytes == 4:
            acc_name = 'eax'
        elif size_bytes == 8:
            acc_name = 'rax'
        else:
            return

        # 2. 값 읽기
        acc_c, acc_s, _ = self.ctx.get_register(acc_name)
        d_c, d_s = dst.read(self.ctx, ip)
        s_c, s_s = src.read(self.ctx, ip)

        # 3. [핵심] 비교 연산 및 Flags 업데이트
        # 값 교환 여부와 상관없이, 비교(뺄셈)는 항상 수행되어 Flags를 바꿈
        # Accumulator - Dest
        cmp_sym = z3.simplify(acc_s - d_s)
        self._update_flags(cmp_sym)

        # 4. 조건부 값 교환 (Concrete 값 기준 분기)
        # 마스킹 처리 (오버플로우 방지)
        mask = (1 << (size_bytes * 8)) - 1
        acc_c &= mask
        d_c &= mask

        if acc_c == d_c:
            # [Equal] ZF=1 Case
            # dest = src (Taint 전파: Src -> Dest)
            dst.write(self.ctx, s_c, s_s, ip)
        else:
            # [Not Equal] ZF=0 Case
            # Accumulator = dest (Taint 전파: Dest -> Accumulator)
            self.ctx.set_register(acc_name, d_c, d_s)

    def _handle_cmp(self, operands, ip):
        """
        CMP dest, src
        Logic: dest - src (Flags update only)
        """
        if len(operands) < 2: return
        op1, op2 = operands[0], operands[1]

        # 1. 값 읽기
        v1_c, v1_s = op1.read(self.ctx, ip)
        v2_c, v2_s = op2.read(self.ctx, ip)

        # 2. 비트 수 맞추기 (Sign Extension or Zero Extension)
        # 보통 CMP EAX, -1 처럼 부호 있는 비교가 많으므로 상황에 따라 다르지만
        # Taint 전파 관점에서는 ZeroExt로 비트만 맞춰줘도 충분함
        size_diff = v1_s.size() - v2_s.size()
        if size_diff > 0:
            v2_s = z3.ZeroExt(size_diff, v2_s)
        elif size_diff < 0:
            v1_s = z3.ZeroExt(-size_diff, v1_s)

        # 3. 뺄셈 연산 (결과는 버림)
        # 이 수식 자체가 Flags의 오염원이 됨
        res_sym = z3.simplify(v1_s - v2_s)

        # 4. [핵심] Flags 업데이트
        self._update_flags(res_sym)

    def _handle_test(self, operands, ip):
        """
        TEST dest, src
        Logic:
          Temp = dest & src
          SF, ZF, PF = Check(Temp)
          (Dest is NOT modified)
        """
        if len(operands) < 2: return
        op1, op2 = operands[0], operands[1]

        # 1. 값 읽기
        v1_c, v1_s = op1.read(self.ctx, ip)
        v2_c, v2_s = op2.read(self.ctx, ip)

        # 2. 비트 수 맞추기 (Zero Extension)
        # 예: TEST EAX, 0xFF (32bit vs 8bit) -> 0xFF를 32bit로 확장
        size_diff = v1_s.size() - v2_s.size()
        if size_diff > 0:
            v2_s = z3.ZeroExt(size_diff, v2_s)
        elif size_diff < 0:
            v1_s = z3.ZeroExt(-size_diff, v1_s)

        # 3. Symbolic AND 연산 (결과는 저장 안 함, Taint 전파용)
        # TEST는 결과가 0인지(ZF), 음수인지(SF) 등을 판단하므로
        # 결과 수식(AND) 자체가 Flags의 오염원이 됩니다.
        taint_expr = z3.simplify(v1_s & v2_s)

        # Flags 업데이트 (공통 메서드 사용)
        self._update_flags(taint_expr)

    def _handle_adc_sbb(self, operands, ip, mode):
        """
        ADC (Add with Carry): dest = dest + src + CF
        SBB (Sub with Borrow): dest = dest - src - CF
        """
        if len(operands) < 2: return
        dst, src = operands[0], operands[1]

        # 1. 오퍼랜드 읽기
        d_c, d_s = dst.read(self.ctx, ip)
        s_c, s_s = src.read(self.ctx, ip)

        # 2. [핵심] EFLAGS(CF) 읽기 (Taint Source)
        # CF가 포함된 EFLAGS 레지스터 전체의 Taint 여부를 가져옵니다.
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'
        _, flags_s, _ = self.ctx.get_register(flags_reg)

        # 3. 비트 수 맞추기
        if d_s.size() > s_s.size():
            s_s = z3.ZeroExt(d_s.size() - s_s.size(), s_s)

        # 4. 연산 수행 (Symbolic)
        # CF를 정확히 수식으로 표현하기보다, "Flags가 오염되었으면 결과도 오염된다"는
        # 의존성 관계(Dependency)를 형성하는 것이 Taint 분석의 목적입니다.

        # Flags가 Taint 상태라면 연산에 포함시킴
        taint_sources = [d_s, s_s]
        if flags_s is not None and not z3.is_bv_value(flags_s):
            # 수식적으로 정확히 1비트 CF를 더하는 건 복잡하므로,
            # Flags 전체를 ZeroExt 하여 더하는 식으로 '의존성'만 주입하거나
            # 단순히 식에 포함시킵니다. 여기서는 의존성 주입을 위해 더미로 추가합니다.
            # (실제 값은 Concrete가 처리하므로 Taint 전파만 신경 씀)
            flags_ext = z3.ZeroExt(d_s.size() - flags_s.size(), flags_s) if d_s.size() > flags_s.size() else flags_s
            taint_sources.append(flags_ext)

        # 연산 식 생성
        new_sym = None
        if mode == 'ADC':
            # sum(d, s, flags)
            new_sym = z3.simplify(sum(taint_sources))
            # Concrete: d + s + (CF? 1:0) -> Trace의 결과를 믿거나 직접 계산
            # 여기서는 편의상 단순 합으로 표현 (CF 미반영이어도 Taint는 전파됨)
            new_conc = d_c + s_c
        else:  # SBB
            new_sym = z3.simplify(d_s - s_s - (taint_sources[-1] if len(taint_sources) > 2 else 0))
            new_conc = d_c - s_c

        # 5. 결과 쓰기 & Flags 업데이트
        dst.write(self.ctx, new_conc, new_sym, ip)
        self._update_flags(new_sym)

    def _handle_mul_div(self, operands, ip, mode):
        """
        MUL src: AX = AL*src, DX:AX = AX*src, EDX:EAX = EAX*src
        DIV src: AX/src, DX:AX/src, EDX:EAX/src
        """
        if len(operands) < 1: return
        src = operands[0]

        # Src 읽기
        s_c, s_s = src.read(self.ctx, ip)

        # Accumulator 결정 (AL, AX, EAX, RAX)
        size = src.size
        if size == 1:
            acc = 'al';
            dst_hi = None;
            dst_lo = 'ax'  # 8bit -> 16bit result in AX
        elif size == 2:
            acc = 'ax';
            dst_hi = 'dx';
            dst_lo = 'ax'
        elif size == 4:
            acc = 'eax';
            dst_hi = 'edx';
            dst_lo = 'eax'
        elif size == 8:
            acc = 'rax';
            dst_hi = 'rdx';
            dst_lo = 'rax'
        else:
            return

        # Accumulator(피연산자 A) 읽기
        a_c, a_s, _ = self.ctx.get_register(acc)

        # 연산 및 Taint 전파
        if mode == 'MUL':
            # 결과는 a * s
            res_sym = z3.simplify(z3.ZeroExt(size * 8, a_s) * z3.ZeroExt(size * 8, s_s) if size < 8 else a_s * s_s)

            # 결과 쓰기
            if size == 1:
                # 8bit MUL은 결과를 AX에 통째로 씀
                self.ctx.set_register('ax', 0, res_sym)  # Concrete는 생략(Trace 의존)
            else:
                # 상위, 하위 레지스터에 쪼개서 들어감 (Taint는 양쪽 다 전파)
                self.ctx.set_register(dst_lo, 0, res_sym)  # Low Part Taint
                self.ctx.set_register(dst_hi, 0, res_sym)  # High Part Taint

            self._update_flags(res_sym)

        elif mode == 'DIV':
            # 나눗셈은 몫(LO)과 나머지(HI)로 나뉨. 둘 다 오염됨.
            # Taint 관점에서는 그냥 "결과는 입력들의 조합"이라고 퉁치는게 안전
            res_sym = z3.simplify(a_s + s_s)  # 의존성만 표현

            if size == 1:
                self.ctx.set_register('ax', 0, res_sym)
            else:
                self.ctx.set_register(dst_lo, 0, res_sym)  # Quotient
                self.ctx.set_register(dst_hi, 0, res_sym)  # Remainder

            # DIV는 Flags가 Undefined지만, 보통 변경되므로 업데이트 호출
            self._update_flags(res_sym)

    def _handle_rotate(self, operands, ip, mode):
        """
        ROL (Rotate Left), ROR (Rotate Right)
        """
        if len(operands) < 2: return
        dst, count = operands[0], operands[1]

        d_c, d_s = dst.read(self.ctx, ip)
        c_c, c_s = count.read(self.ctx, ip)

        # Z3 Rotate 함수 사용
        # Rotate count도 32/64비트로 확장 필요
        if d_s.size() > c_s.size():
            c_s = z3.ZeroExt(d_s.size() - c_s.size(), c_s)

        new_sym = None
        if mode == 'ROL':
            new_sym = z3.simplify(z3.RotateLeft(d_s, c_s))
        else:  # ROR
            new_sym = z3.simplify(z3.RotateRight(d_s, c_s))

        # Concrete 값 계산 (Python은 Rotate 연산자가 없어서 구현 복잡하므로 0 처리하거나 생략)
        # Trace 결과를 믿고 Concrete 값은 dst의 현재 값을 쓰거나 0으로 둠
        new_conc = d_c

        dst.write(self.ctx, new_conc, new_sym, ip)
        self._update_flags(new_sym)

    def _handle_ret(self, operands, ip):
        """
        RET / RETN [optional_imm]
        1. Pop Return Address from Stack -> Update EIP
        2. Increment ESP (Arch Size + Optional Immediate)
        """
        # TraceInstruction에서 이미 Implicit Operand(Mem[ESP])를 0번 인덱스에 넣어줬다고 가정합니다.
        if len(operands) < 1: return

        # ---------------------------------------------------------------------
        # 1. Return Address 읽기 (POP EIP와 유사)
        # ---------------------------------------------------------------------
        pop_op = operands[0]  # [Implicit] Mem[ESP]

        # 스택에서 복귀 주소 읽기
        ret_addr_c, ret_addr_s = pop_op.read(self.ctx, ip)

        # ---------------------------------------------------------------------
        # 2. EIP/RIP 업데이트 (Control Flow)
        # ---------------------------------------------------------------------
        ip_reg = 'rip' if self.ctx.arch_mode == 64 else 'eip'
        self.ctx.set_register(ip_reg, ret_addr_c, ret_addr_s)

        # [Analysis Point] 복귀 주소가 오염되었는지 확인 (ROP 탐지 핵심)
        if ret_addr_s is not None and not z3.is_bv_value(ret_addr_s):
            # print(f"[!] Tainted Return Address detected at {hex(ip)}! Flow Hijacking?")
            pass

        # ---------------------------------------------------------------------
        # 3. ESP 업데이트 (Stack Pointer Adjustment)
        # ---------------------------------------------------------------------
        # 기본적으로 POP 했으므로 아키텍처 크기만큼 증가
        sp_reg = 'rsp' if self.ctx.arch_mode == 64 else 'esp'
        sp_c, sp_s, _ = self.ctx.get_register(sp_reg)
        arch_bytes = self.ctx.arch_mode // 8

        total_increment = arch_bytes

        # [RET n 처리]
        # 만약 명시적인 오퍼랜드(Immediate)가 있다면, 그만큼 스택을 추가로 정리함 (stdcall)
        # operands 구조: [Implicit_Mem, Explicit_Imm(Optional)]
        if len(operands) > 1:
            imm_op = operands[1]
            if imm_op.type == OperandType.IMM:
                imm_val, _ = imm_op.read(self.ctx, ip)
                total_increment += imm_val

        # ESP 최종 업데이트
        new_sp_c = sp_c + total_increment
        # SP의 심볼릭 상태는 보통 유지되거나 상수로 계산됨
        new_sp_s = sp_s + total_increment if sp_s is not None else None

        self.ctx.set_register(sp_reg, new_sp_c, new_sp_s)

    def _handle_std(self, operands, ip):
        """
        STD (Set Direction Flag)
        EFLAGS의 DF(Bit 10)를 1로 설정합니다.
        """
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'
        flags_c, flags_s, _ = self.ctx.get_register(flags_reg)

        # DF는 10번째 비트 (0x400)
        DF_MASK = 0x400
        new_flags_c = flags_c | DF_MASK

        # Taint 상태(flags_s)는 기존 상태를 그대로 유지합니다.
        self.ctx.set_register(flags_reg, new_flags_c, flags_s)

    def _handle_cld(self, operands, ip):
        """
        CLD (Clear Direction Flag)
        EFLAGS의 DF(Bit 10)를 0으로 설정합니다.
        """
        flags_reg = 'rflags' if self.ctx.arch_mode == 64 else 'eflags'
        flags_c, flags_s, _ = self.ctx.get_register(flags_reg)

        # DF는 10번째 비트 (0x400)
        DF_MASK = 0x400
        new_flags_c = flags_c & ~DF_MASK

        # Taint 상태(flags_s)는 기존 상태를 그대로 유지합니다.
        self.ctx.set_register(flags_reg, new_flags_c, flags_s)
