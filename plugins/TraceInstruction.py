from .TraceOperand import *
from capstone import CS_MODE_64

class TraceInstruction:
    def __init__(self, trace_data, md):
        """
        :param trace_data: x64dbg trace 한 줄 (dict)
        :param md: 초기화된 Capstone 인스턴스
        """
        self.ip = trace_data['ip']
        self.opcode_bytes = bytes.fromhex(trace_data['opcodes'])
        self.mnemonic = ''
        self.op_str = ''
        self.operands = []  # List[TraceOperand]

        # 디스어셈블리 및 오퍼랜드 파싱 수행
        self._parse(md)

    def get_operands(self):
        return self.operands

    def __repr__(self):
        return f"<{hex(self.ip)}: {self.mnemonic} {self.op_str}>"

    def _parse(self, md):
        # Capstone으로 디스어셈블리
        try:
            cs_inst = next(md.disasm(self.opcode_bytes, self.ip), None)

            if cs_inst:
                # 1. Raw Mnemonic 가져오기 (예: "lock xadd", "mov")
                raw_mnemonic = cs_inst.mnemonic.upper()

                # 2. [핵심] LOCK 접두어 제거 및 정제
                # Capstone은 "lock xadd"처럼 문자열을 줄 수 있음. 이를 "XADD"로 통일.
                if raw_mnemonic.startswith("LOCK "):
                    self.mnemonic = raw_mnemonic.replace("LOCK ", "").strip()
                else:
                    self.mnemonic = raw_mnemonic

                self.op_str = cs_inst.op_str

                # 오퍼랜드 추출 및 변환
                for cs_op in cs_inst.operands:
                    op_obj = create_operand_from_capstone(cs_inst, cs_op)
                    if op_obj:
                        self.operands.append(op_obj)

            # 파싱이 끝난 후 암시적 오퍼랜드 추가
            if self.mnemonic:
                self._add_implicit_operands(md)

        except Exception as e:
            print(f"[!] Disassembly Error at {hex(self.ip)}: {e}")

    def _add_implicit_operands(self, md):
        """
        PUSH, POP, CALL, PUSHFD 등 암시적으로 스택/레지스터를 건드리는 명령어를 위해
        가상의 Memory Operand를 생성하여 추가함.
        """
        # 아키텍처에 따른 단위 크기 및 레지스터 이름 설정
        # (TraceInstruction이 ctx를 직접 모르므로 간단히 추론하거나,
        #  일반적으로 32비트 Trace면 4, 64비트면 8로 가정)
        #  정확히 하려면 md(Capstone)의 mode를 확인해야 함
        is_64bit = (md._mode == CS_MODE_64)
        arch_bytes = 8 if is_64bit else 4
        sp_reg = 'rsp' if is_64bit else 'esp'
        flags_reg = 'rflags' if is_64bit else 'eflags'

        mnemonic = self.mnemonic.upper()

        # ---------------------------------------------------------------------
        # 1. PUSH 계열 (PUSH, CALL) -> Stack Write [SP-size]
        # ---------------------------------------------------------------------
        if mnemonic in ['PUSH', 'CALL']:
            mem_info = {
                'base': sp_reg,
                'disp': -arch_bytes,
                'index': None, 'scale': 1
            }
            implicit_op = TraceOperand(OperandType.MEM, arch_bytes, mem_info=mem_info, access=OperandAccess.WRITE,
                                       is_implicit=True)
            self.operands.append(implicit_op)

        # ---------------------------------------------------------------------
        # 2. POP 계열 (POP, RET) -> Stack Read [SP]
        # ---------------------------------------------------------------------
        elif mnemonic in ['POP', 'RET', 'RETN']:
            mem_info = {
                'base': sp_reg,
                'disp': 0,
                'index': None, 'scale': 1
            }
            implicit_op = TraceOperand(OperandType.MEM, arch_bytes, mem_info=mem_info, access=OperandAccess.READ,
                                       is_implicit=True)
            self.operands.insert(0, implicit_op)

        # ---------------------------------------------------------------------
        # 3. PUSHFD / PUSHFQ (Flags -> Stack)
        # ---------------------------------------------------------------------
        elif mnemonic in ['PUSHFD', 'PUSHFQ']:
            # Source: EFLAGS/RFLAGS (Read)
            src_reg = TraceOperand(OperandType.REG, arch_bytes, reg_name=flags_reg, access=OperandAccess.READ,
                                   is_implicit=True)
            self.operands.append(src_reg)

            # Dest: Stack [SP-size] (Write)
            mem_info = {
                'base': sp_reg,
                'disp': -arch_bytes,
                'index': None, 'scale': 1
            }
            dst_mem = TraceOperand(OperandType.MEM, arch_bytes, mem_info=mem_info, access=OperandAccess.WRITE,
                                   is_implicit=True)
            self.operands.append(dst_mem)

        # ---------------------------------------------------------------------
        # 4. POPFD / POPFQ (Stack -> Flags)
        # ---------------------------------------------------------------------
        elif mnemonic in ['POPFD', 'POPFQ']:
            # Source: Stack [SP] (Read)
            mem_info = {
                'base': sp_reg,
                'disp': 0,
                'index': None, 'scale': 1
            }
            src_mem = TraceOperand(OperandType.MEM, arch_bytes, mem_info=mem_info, access=OperandAccess.READ,
                                   is_implicit=True)
            self.operands.append(src_mem)

            # Dest: EFLAGS/RFLAGS (Write)
            dst_reg = TraceOperand(OperandType.REG, arch_bytes, reg_name=flags_reg, access=OperandAccess.WRITE,
                                   is_implicit=True)
            self.operands.append(dst_reg)
